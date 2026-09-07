"""Streaming transport for the analysis pipeline.

This module deliberately contains no analysis logic. It runs the same
ThreatAnalyzer pipeline the REST endpoint runs and forwards phase events to an
async callback, so a streamed report and a requested report are byte-for-byte
the same object. An earlier version re-implemented the pipeline phase by phase
and silently drifted out of sync with it.
"""

import asyncio
import logging
import os
from datetime import datetime
from functools import partial
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .analyzer import ThreatAnalyzer
from .progress import ANALYSIS_PHASES, COMPLETE_PROGRESS
from ..models import AnalysisResult
from ..services.analysis_workers import analysis_workers

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[Dict[str, Any]], Optional[Awaitable[None]]]


class StreamingAnalyzer:
    """Runs an analysis on a worker thread and streams phase events.

    Usage:
        streaming = StreamingAnalyzer(progress_callback=send)
        result = await streaming.analyze_streaming(description, project_name)
    """

    def __init__(self, progress_callback: Optional[ProgressCallback] = None, analyzer: Optional[ThreatAnalyzer] = None):
        self._callback = progress_callback
        self._analyzer = analyzer

    async def analyze_streaming(
        self,
        description: str,
        project_name: str = "Untitled Project",
        use_local_slm: bool = True,
        analysis_mode: str = "standard",
        domain_profile: str = "general",
        source_documents: Optional[List[Dict[str, Any]]] = None,
    ) -> AnalysisResult:
        analyzer = self._analyzer or ThreatAnalyzer()
        loop = asyncio.get_running_loop()
        events: "asyncio.Queue[Optional[Dict[str, Any]]]" = asyncio.Queue()

        def sink(event: Dict[str, Any]) -> None:
            # Called from the analysis thread, so hand the event to the loop
            # rather than touching the queue directly.
            if not closed.is_set() and not loop.is_closed():
                loop.call_soon_threadsafe(events.put_nowait, event)

        import threading
        closed = threading.Event()
        forwarder = asyncio.create_task(self._forward(events))
        analyze = partial(
            analyzer.analyze_from_text,
            description,
            project_name,
            use_local_slm=use_local_slm,
            analysis_mode=analysis_mode,
            domain_profile=domain_profile,
            source_documents=source_documents,
            progress=sink,
        )
        try:
            result = await analysis_workers.run(analyze, timeout=int(os.getenv("AEGIS_THREAT_ANALYSIS_TIMEOUT_SECONDS", "300")))
        finally:
            closed.set()
            await events.put(None)
            await forwarder

        await self._emit({
            "type": "progress",
            "phase": "complete",
            "label": "Complete",
            "message": f"Analysis complete. {len(result.threats)} findings.",
            "progress": COMPLETE_PROGRESS,
            "timestamp": datetime.now().isoformat(),
        })
        return result

    async def _forward(self, events: "asyncio.Queue[Optional[Dict[str, Any]]]") -> None:
        while True:
            event = await events.get()
            if event is None:
                return
            await self._emit(event)

    async def _emit(self, event: Dict[str, Any]) -> None:
        if self._callback is None:
            return
        try:
            outcome = self._callback(event)
            if asyncio.iscoroutine(outcome):
                await outcome
        except Exception as exc:  # a disconnected client must not fail the analysis
            logger.debug("Progress callback failed: %s", exc)


# Exposed so a client can render the phase list before an analysis starts.
PHASES = [
    {"id": name, "label": label, "message": message}
    for name, label, message in ANALYSIS_PHASES
]

"""Phase reporting for the analysis pipeline.

Every transport runs the same pipeline. The only difference between the REST
endpoint and the WebSocket endpoint is whether phase transitions are forwarded
to a client, so the phase vocabulary lives here rather than in either transport.
"""

from datetime import datetime
from time import perf_counter
from typing import Any, Callable, Dict, List, Optional, Tuple

# Ordered phases of ThreatAnalyzer.analyze, each as (id, display label, message).
# A phase is announced when it starts, so the first reports 0 percent and
# completion is reported by the caller once the result exists.
ANALYSIS_PHASES: List[Tuple[str, str, str]] = [
    ("parsing", "Parsing", "Parsing the architecture description"),
    ("canonical_model", "Canonical Model", "Canonicalizing components, flows, and trust boundaries"),
    ("knowledge", "Knowledge Base", "Matching specialist threat packs and knowledge base rules"),
    ("declared_issues", "Declared Issues", "Reconciling declared and prose-stated weaknesses"),
    ("stride_coverage", "STRIDE Coverage", "Assessing every element against every STRIDE category"),
    ("local_intelligence", "Local Intelligence", "Running local retrieval and the challenger"),
    ("calibration", "Calibration", "Calibrating confidence and tiering findings"),
    ("attack_paths", "Attack Paths", "Building attack paths"),
    ("scoring", "Risk Scoring", "Scoring risk"),
    ("reporting", "Reporting", "Generating the diagram, quality gate, and report"),
]

PHASE_INDEX: Dict[str, int] = {name: index for index, (name, _, _) in enumerate(ANALYSIS_PHASES)}
PHASE_LABELS: Dict[str, str] = {name: label for name, label, _ in ANALYSIS_PHASES}
PHASE_MESSAGES: Dict[str, str] = {name: message for name, _, message in ANALYSIS_PHASES}

COMPLETE_PROGRESS = 100

ProgressSink = Callable[[Dict[str, Any]], None]


def phase_progress(name: str) -> int:
    """Percentage complete when the named phase begins."""
    return int(PHASE_INDEX[name] * 100 / len(ANALYSIS_PHASES))


class ProgressReporter:
    """Announces pipeline phases to an optional sink.

    The sink is called synchronously from the analysis thread and must not
    block; transports are expected to hand events to their own event loop.
    """

    def __init__(self, sink: Optional[ProgressSink] = None):
        self._sink = sink
        self._started = perf_counter()
        self._phase_started = self._started
        self._current = None
        self._durations = {}
        self._finished = None

    @property
    def active(self) -> bool:
        return self._sink is not None

    def phase(self, name: str, detail: Optional[Dict[str, Any]] = None) -> None:
        # Resolved even without a sink so a mistyped phase fails in any test,
        # not only in the streaming transport.
        message = PHASE_MESSAGES[name]
        progress = phase_progress(name)
        now = perf_counter()
        if self._current:
            self._durations[self._current] = self._durations.get(self._current, 0) + now - self._phase_started
        self._phase_started = now
        self._current = name
        if self._sink is None:
            return
        event = {
            "type": "progress",
            "phase": name,
            "label": PHASE_LABELS[name],
            "message": message,
            "progress": progress,
            "timestamp": datetime.now().isoformat(),
        }
        if detail:
            event["detail"] = detail
        self._sink(event)

    def finish(self) -> Dict[str, Any]:
        if self._finished is None:
            self._finished = perf_counter()
            if self._current:
                self._durations[self._current] = self._durations.get(self._current, 0) + self._finished - self._phase_started
            self._current = None
        return {
            "total_ms": round((self._finished - self._started) * 1000, 3),
            "phase_ms": {key: round(value * 1000, 3) for key, value in self._durations.items()},
        }

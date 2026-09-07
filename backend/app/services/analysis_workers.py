"""Process-wide admission control shared by REST and streaming analysis."""

import asyncio
import os
import threading


class AnalysisBusy(RuntimeError):
    pass


class AnalysisWorkers:
    def __init__(self, limit=2):
        self.limit = max(1, limit)
        self._slots = threading.BoundedSemaphore(self.limit)

    async def run(self, work, timeout=None):
        if not self._slots.acquire(blocking=False):
            raise AnalysisBusy("Analysis capacity is busy. Retry after the current analyses finish.")

        def execute():
            try:
                return work()
            finally:
                # A timed-out caller must not free a still-running worker's slot.
                self._slots.release()

        try:
            future = asyncio.get_running_loop().run_in_executor(None, execute)
        except BaseException:
            self._slots.release()
            raise
        future.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
        return await asyncio.wait_for(asyncio.shield(future), timeout=timeout)


analysis_workers = AnalysisWorkers(int(os.getenv("AEGIS_THREAT_ANALYSIS_CONCURRENCY", "2")))

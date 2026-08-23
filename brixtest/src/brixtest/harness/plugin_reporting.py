"""Session finalization and terminal reporting for the fleet harness."""

from __future__ import annotations

from brixtest import events
from brixtest.errors import ConservationError, QuiescenceError
from brixtest.evidence.legacy import publish as publish_evidence
from brixtest.results.report import write_index, write_report


class BrixTestReportingMixin:
    """Finalize harness resources and render concise terminal findings."""

    def _stop_resource_watch(self) -> None:
        if self.resources is not None:
            self.resources.stop()

    def _release_dynamic_servers(self) -> None:
        try:
            self.handle.dynamic.release_all()
        except QuiescenceError as exc:
            self._dynamic_leaks.append("session: %s" % exc)

    def _check_conservation(self) -> None:
        if self.start_report is None:
            return
        try:
            self.sentinel.conservation_check()
        except ConservationError as exc:
            self._conservation_delta = str(exc)
            report = self.lane.log_dir / "conservation-report.txt"
            report.write_text(self._conservation_delta + "\n")
            events.emit("conservation.delta", detail=self._conservation_delta)

    def _finish_result_store(self) -> None:
        if self.collector is None or self.store is None:
            return
        info = self.collector.finish_run()
        publish_evidence(self.store, info, self.collector.run_dir)
        self._report_path = write_report(
            self.store, info.run_id, self.collector.run_dir / "report.html",
        )
        write_index(self.store, self.lane.root / "results" / "index.html")
        self.store.close()

    def pytest_sessionfinish(self, session) -> None:
        self._stop_resource_watch()
        self._release_dynamic_servers()
        if not self.is_controller():
            return
        self.sentinel.stop()
        self._check_conservation()
        self._finish_result_store()
        self.lane.release()
        events.emit("session.finished", exitstatus=int(getattr(session, "exitstatus", 0)))

    def _report_resource_findings(self, terminalreporter) -> None:
        if self.resources is None:
            return
        for finding in self.resources.findings:
            terminalreporter.line(
                "brixtest FINDING [%s] %s: %s"
                % (finding.kind, finding.instance, finding.detail)
            )

    def _report_dynamic_leaks(self, terminalreporter) -> None:
        for leak in self._dynamic_leaks:
            terminalreporter.line("brixtest WARNING: dynamic server leak — %s" % leak)

    @staticmethod
    def _report_optional(terminalreporter, label: str, value: object) -> None:
        if value:
            terminalreporter.line("%s%s" % (label, value))

    def pytest_terminal_summary(self, terminalreporter) -> None:
        summary = self.start_report.summary() if self.start_report is not None else ""
        self._report_optional(terminalreporter, "brixtest fleet: ", summary)
        self._report_optional(terminalreporter, "brixtest: ", self._file_linear_note)
        self._report_optional(
            terminalreporter, "brixtest WARNING: ", self._conservation_delta,
        )
        self._report_resource_findings(terminalreporter)
        self._report_dynamic_leaks(terminalreporter)
        self._report_optional(terminalreporter, "brixtest report: ", self._report_path)

from __future__ import annotations

from threading import Lock

from sentinelops.models import IncidentReport


class IncidentStore:
    def __init__(self) -> None:
        self._reports: dict[str, IncidentReport] = {}
        self._lock = Lock()

    def put_if_absent(self, report: IncidentReport) -> IncidentReport:
        with self._lock:
            return self._reports.setdefault(report.incident_id, report)

    def get(self, incident_id: str) -> IncidentReport | None:
        return self._reports.get(incident_id)

"""Abstract base class for all compliance checks."""

from __future__ import annotations

import csv
import json
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from engine.models import CheckResult, CheckStatus, Finding
from engine.audit_trail import FileAccessTracker


class BaseCheck(ABC):
    """Abstract base for all compliance checks.

    Each check module extends this class and implements the execute()
    and get_evidence() methods for one or more controls.
    """

    def __init__(self, config: dict, demo: bool = False):
        self.config = config
        self.demo = demo
        self._evidence: dict = {}
        self._base_dir = config.get("_base_dir", ".")

    @abstractmethod
    def execute(self, control_id: str, method: str) -> CheckResult:
        pass

    @abstractmethod
    def get_evidence(self) -> dict:
        pass

    def _make_result(
        self,
        control_id: str,
        status: str,
        score: float,
        evidence: dict | None = None,
        findings: list[Finding] | None = None,
        remediation: list[str] | None = None,
        details: str = "",
        decay_days: int = 30,
    ) -> CheckResult:
        now = datetime.now()
        next_due = (now + timedelta(days=decay_days)).isoformat()
        return CheckResult(
            control_id=control_id,
            status=status,
            score=round(score, 3),
            timestamp=now.isoformat(),
            evidence=evidence or {},
            findings=findings or [],
            remediation=remediation or [],
            next_check_due=next_due,
            check_module=self.__class__.__name__,
            details=details,
        )

    def _load_demo_data(self, filename: str) -> dict | list | None:
        """Load demo sample data file."""
        path = Path(self._base_dir) / "demo" / "sample_data" / filename
        if not path.exists():
            return None
        FileAccessTracker.instance().record(
            str(path), "read", self.__class__.__name__,
            f"Demo sample data: {filename}",
        )
        with open(path, "r") as f:
            return json.load(f)

    def _load_evidence_file(self, config_key: str) -> dict | list | None:
        """Load evidence data from a user-configured file path.

        Supports JSON and CSV files. If the path is a directory, loads the
        most recently modified JSON or CSV file within it.

        Args:
            config_key: Key in config['evidence'] (e.g. 'vulnerability_scans').

        Returns:
            Parsed data, or None if not found/configured.
        """
        evidence_config = self.config.get("evidence", {})
        path_str = evidence_config.get(config_key)
        if not path_str:
            return None

        path = Path(path_str)
        if not path.exists():
            return None

        # Directory: find most recent JSON/CSV
        if path.is_dir():
            files = sorted(
                [f for f in path.iterdir()
                 if f.suffix.lower() in (".json", ".csv")
                 and not f.name.startswith(".")],
                key=lambda f: f.stat().st_mtime,
                reverse=True,
            )
            if not files:
                return None
            path = files[0]

        FileAccessTracker.instance().record(
            str(path), "read", self.__class__.__name__,
            f"Evidence file: {config_key}",
        )

        if path.suffix.lower() == ".csv":
            with open(path, "r", newline="") as f:
                return list(csv.DictReader(f))
        else:
            with open(path, "r") as f:
                return json.load(f)

    def _make_not_configured_result(
        self, control_id: str, config_key: str, decay_days: int = 30,
    ) -> CheckResult:
        """Return an ERROR result when evidence file is not configured."""
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details=f"Evidence file not configured. Set 'evidence.{config_key}' "
                    f"in config.yaml, or run with --demo flag. "
                    f"See templates/ directory for the expected file format.",
            decay_days=decay_days,
        )

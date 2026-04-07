"""Abstract base class for all compliance checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from engine.models import CheckResult, CheckStatus, Finding


class BaseCheck(ABC):
    """Abstract base for all compliance checks.

    Each check module extends this class and implements the execute()
    and get_evidence() methods for one or more controls.
    """

    def __init__(self, config: dict, demo: bool = False):
        """Initialize the check.

        Args:
            config: Engine configuration dictionary.
            demo: If True, use simulated demo data.
        """
        self.config = config
        self.demo = demo
        self._evidence: dict = {}
        self._base_dir = config.get("_base_dir", ".")

    @abstractmethod
    def execute(self, control_id: str, method: str) -> CheckResult:
        """Run the check and return a result.

        Args:
            control_id: The control ID being checked.
            method: The specific check method to run.

        Returns:
            CheckResult with status, score, evidence, and findings.
        """
        pass

    @abstractmethod
    def get_evidence(self) -> dict:
        """Collect evidence artifacts for audit trail.

        Returns:
            Dictionary of evidence collected during the check.
        """
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
        """Helper to create a CheckResult with common fields populated.

        Args:
            control_id: Control being checked.
            status: PASS, FAIL, PARTIAL, ERROR.
            score: Score from 0.0 to 1.0.
            evidence: Evidence dictionary.
            findings: List of findings.
            remediation: List of remediation steps.
            details: Human-readable details string.
            decay_days: Days until this check goes stale.

        Returns:
            Populated CheckResult.
        """
        now = datetime.now()
        from datetime import timedelta
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
        """Load demo sample data file.

        Args:
            filename: Name of file in demo/sample_data/.

        Returns:
            Parsed JSON data, or None if not found.
        """
        import json
        from pathlib import Path

        path = Path(self._base_dir) / "demo" / "sample_data" / filename
        if not path.exists():
            return None

        with open(path, "r") as f:
            return json.load(f)

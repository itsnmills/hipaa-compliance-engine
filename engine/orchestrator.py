"""Main execution orchestrator for the HIPAA Compliance Engine."""

from __future__ import annotations

import importlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from engine.config import load_config, get_data_dir
from engine.exceptions import CheckError, RegistryError
from engine.models import (
    CheckResult, CheckStatus, ControlStatus, ComplianceReport,
    ControlDefinition,
)
from controls.registry import ControlRegistry
from engine.audit_trail import FileAccessTracker
from scoring.freshness import (
    compute_control_status, build_compliance_report,
)


# Demo mode: age offsets to simulate checks run at different times in the past.
# This creates realistic freshness decay for the Midwest Family Dental demo,
# bringing the overall score to ~67% (Partially Compliant).
# Format: control_id -> days_since_last_check
DEMO_AGE_OFFSETS = {
    # Continuous controls (30-day decay) — some checked days ago
    "TECH-AUD-001": 6,        # Audit logging — 6 days ago
    "CC-EAR-001": 4,          # Encryption at rest — 4 days ago
    "CC-PM-001": 10,          # Patches — 10 days ago (67% fresh)
    "ADM-CP-001": 8,          # Backup — 8 days ago
    "CC-MFA-001": 5,          # Universal MFA — 5 days ago
    # Semi-annual controls (180-day decay) — moderate aging
    "CC-VS-001": 70,          # Vuln scanning — 70 days ago (61% fresh)
    "CC-NS-001": 85,          # Network segmentation — 85 days ago (53%)
    "ADM-WFS-001": 50,        # Workforce security — 50 days ago
    "TECH-AC-001": 40,        # Access controls — 40 days ago
    "TECH-INT-001": 75,       # Integrity — 75 days ago (58% fresh)
    "CC-1HR-001": 100,        # 1-hour termination — 100 days ago (44%)
    # Annual controls (365-day decay) — moderate to old
    "ADM-SMP-001": 150,       # Risk analysis — 150 days ago (59% fresh)
    "ADM-SAT-001": 120,       # Training — 120 days ago (67% fresh)
    "ADM-SIP-001": 110,       # IR plan — 110 days ago (70%)
    "ADM-BAC-001": 170,       # BA compliance — 170 days (53% fresh)
    "CC-PT-001": 140,         # Pen test — 140 days ago (62% fresh)
    "CC-TAI-001": 160,        # Asset inventory — 160 days ago (56%)
    "CC-NM-001": 180,         # Network map — 180 days ago (51%)
    "CC-ACA-001": 200,        # Annual audit — 200 days ago (45%)
    "CC-72H-001": 170,        # DR test — 170 days ago (53%)
    "CC-BAN-001": 190,        # BA notification — 190 days ago (48%)
    "CC-BAV-001": 195,        # BA verification — 195 days ago (47%)
    "CC-DOC-001": 130,        # Documentation — 130 days ago (64%)
    "PHY-FAC-001": 120,       # Facility — 120 days ago
    "PHY-WRK-001": 100,       # Workstation — 100 days ago
    "PHY-DMC-001": 150,       # Media controls — 150 days ago
}

# Map check module names to their Python module paths and class names
CHECK_MODULE_MAP = {
    "mfa": ("checks.mfa", "MFACheck"),
    "encryption": ("checks.encryption", "EncryptionCheck"),
    "vulnerability_scanning": ("checks.vulnerability_scanning", "VulnerabilityScanningCheck"),
    "penetration_testing": ("checks.penetration_testing", "PenetrationTestingCheck"),
    "network_segmentation": ("checks.network_segmentation", "NetworkSegmentationCheck"),
    "access_controls": ("checks.access_controls", "AccessControlsCheck"),
    "audit_logging": ("checks.audit_logging", "AuditLoggingCheck"),
    "incident_response": ("checks.incident_response", "IncidentResponseCheck"),
    "backup_recovery": ("checks.backup_recovery", "BackupRecoveryCheck"),
    "asset_inventory": ("checks.asset_inventory", "AssetInventoryCheck"),
    "ba_management": ("checks.ba_management", "BAManagementCheck"),
    "workforce_security": ("checks.workforce_security", "WorkforceSecurityCheck"),
    "policy_documentation": ("checks.policy_documentation", "PolicyDocumentationCheck"),
    "patch_management": ("checks.patch_management", "PatchManagementCheck"),
}


class ComplianceOrchestrator:
    """Orchestrates compliance checks across all controls."""

    def __init__(self, config: dict, demo: bool = False):
        """Initialize the orchestrator.

        Args:
            config: Loaded configuration dictionary.
            demo: If True, run checks in demo mode.
        """
        self.config = config
        self.demo = demo
        self.registry = ControlRegistry()
        self._check_instances: dict = {}
        self._history = CheckHistory()

    def _get_check_instance(self, module_name: str):
        """Get or create a check module instance."""
        if module_name not in self._check_instances:
            if module_name not in CHECK_MODULE_MAP:
                raise RegistryError(f"Unknown check module: {module_name}")

            module_path, class_name = CHECK_MODULE_MAP[module_name]
            module = importlib.import_module(module_path)
            check_class = getattr(module, class_name)
            self._check_instances[module_name] = check_class(self.config, self.demo)

        return self._check_instances[module_name]

    def run_all_checks(
        self,
        category: Optional[str] = None,
        callback=None,
    ) -> ComplianceReport:
        """Run all compliance checks and build report.

        Args:
            category: If specified, only run checks for this category.
            callback: Optional callback(control_id, status) for progress updates.

        Returns:
            Complete ComplianceReport.
        """
        controls = self.registry.all_controls
        if category:
            controls = [c for c in controls if c.category.lower() == category.lower()]

        results: dict[str, CheckResult] = {}

        for control in controls:
            try:
                result = self._run_single_check(control)
                results[control.id] = result
                if callback:
                    callback(control.id, result.status)
            except Exception as e:
                results[control.id] = CheckResult(
                    control_id=control.id,
                    status=CheckStatus.ERROR.value,
                    score=0.0,
                    timestamp=datetime.now().isoformat(),
                    details=f"Check error: {str(e)}",
                )
                if callback:
                    callback(control.id, CheckStatus.ERROR.value)

        # Compute control statuses with freshness
        all_controls = self.registry.all_controls
        control_statuses = []
        for control in all_controls:
            result = results.get(control.id)
            status = compute_control_status(control, result)
            control_statuses.append(status)

        # Save to history
        self._history.save_run(results)

        # Build report
        org_name = self.config.get("organization", {}).get("name", "Unknown")
        org_type = self.config.get("organization", {}).get("type", "covered_entity")
        history_data = self._history.get_history()

        return build_compliance_report(
            organization_name=org_name,
            organization_type=org_type,
            control_statuses=control_statuses,
            history=history_data,
        )

    def _run_single_check(self, control: ControlDefinition) -> CheckResult:
        """Run a single check for a control."""
        check = self._get_check_instance(control.check_module)
        result = check.execute(control.id, control.check_method)

        # In demo mode, backdate certain check results to simulate realistic
        # freshness decay. This creates a more realistic mixed-compliance
        # scenario where some checks are stale or approaching staleness.
        if self.demo and control.id in DEMO_AGE_OFFSETS:
            age_days = DEMO_AGE_OFFSETS[control.id]
            aged_time = datetime.now() - timedelta(days=age_days)
            result.timestamp = aged_time.isoformat()
            result.next_check_due = (
                aged_time + timedelta(days=control.freshness_decay_days)
            ).isoformat()

        return result

    def run_check(self, control_id: str) -> CheckResult:
        """Run a check for a specific control.

        Args:
            control_id: The control ID to check.

        Returns:
            CheckResult for the control.
        """
        control = self.registry.get(control_id)
        result = self._run_single_check(control)
        self._history.save_single(control_id, result)
        return result

    def get_control_status(self, control_id: str) -> ControlStatus:
        """Get the current status of a control including freshness."""
        control = self.registry.get(control_id)
        last_result = self._history.get_latest(control_id)
        return compute_control_status(control, last_result)

    def get_freshness_overview(self) -> list[ControlStatus]:
        """Get freshness status for all controls."""
        statuses = []
        for control in self.registry.all_controls:
            last_result = self._history.get_latest(control.id)
            status = compute_control_status(control, last_result)
            statuses.append(status)
        return statuses


class CheckHistory:
    """Manages persistent check history stored in data/check_history.json."""

    def __init__(self, data_dir: Optional[Path] = None):
        self._data_dir = data_dir or get_data_dir()
        self._history_file = self._data_dir / "check_history.json"
        self._data = self._load()

    def _load(self) -> dict:
        """Load history from disk."""
        if self._history_file.exists():
            FileAccessTracker.instance().record(
                str(self._history_file), "read", "CheckHistory",
                "Previous check results",
            )
            try:
                with open(self._history_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {"runs": [], "latest": {}}
        return {"runs": [], "latest": {}}

    def _save(self) -> None:
        """Persist history to disk."""
        self._data_dir.mkdir(exist_ok=True)
        FileAccessTracker.instance().record(
            str(self._history_file), "write", "CheckHistory",
            "Persist check results",
        )
        with open(self._history_file, "w") as f:
            json.dump(self._data, f, indent=2)

    def save_run(self, results: dict[str, CheckResult]) -> None:
        """Save a complete check run to history."""
        run = {
            "timestamp": datetime.now().isoformat(),
            "controls_checked": len(results),
            "results_summary": {},
        }

        for control_id, result in results.items():
            self._data["latest"][control_id] = result.to_dict()
            run["results_summary"][control_id] = {
                "status": result.status,
                "score": result.score,
            }

        self._data["runs"].append(run)
        # Keep last 50 runs
        self._data["runs"] = self._data["runs"][-50:]
        self._save()

    def save_single(self, control_id: str, result: CheckResult) -> None:
        """Save a single check result."""
        self._data["latest"][control_id] = result.to_dict()
        self._save()

    def get_latest(self, control_id: str) -> Optional[CheckResult]:
        """Get the latest check result for a control."""
        data = self._data.get("latest", {}).get(control_id)
        if data:
            return CheckResult.from_dict(data.copy())
        return None

    def get_history(self) -> list[dict]:
        """Get run history."""
        return self._data.get("runs", [])

    def clear(self) -> None:
        """Clear all history."""
        self._data = {"runs": [], "latest": {}}
        self._save()

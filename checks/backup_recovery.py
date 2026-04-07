"""Backup & 72-Hour DR verification check module."""

from __future__ import annotations

from datetime import datetime

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class BackupRecoveryCheck(BaseCheck):
    """Verify backup operations and 72-hour DR capability."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details="Live backup check requires backup system configuration",
        )

    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("backup_status.json") or {}
        dispatch = {
            "check_backup_status": self._check_backup_status,
            "check_dr_capability": self._check_dr_capability,
        }
        handler = dispatch.get(method, self._check_backup_status)
        return handler(control_id, data)

    def _check_backup_status(self, control_id: str, data: dict) -> CheckResult:
        """Check backup job status and schedule compliance."""
        jobs = data.get("backup_jobs", [])
        schedule = data.get("schedule", {})

        findings = []
        score = 1.0

        if not jobs:
            return self._make_result(
                control_id=control_id,
                status=CheckStatus.FAIL.value,
                score=0.0,
                findings=[Finding(
                    control_id=control_id,
                    title="No Backup Jobs Configured",
                    description="No backup jobs found for ePHI systems.",
                    severity="Critical",
                    cfr_reference="45 CFR § 164.308(a)(7)",
                    remediation="Configure automated backup jobs for all ePHI systems immediately.",
                    estimated_effort="Short-term",
                )],
                details="No backup jobs configured",
                decay_days=30,
            )

        # Check each backup job
        failed_jobs = [j for j in jobs if j.get("last_status") == "failed"]
        if failed_jobs:
            score -= 0.15 * len(failed_jobs)
            for job in failed_jobs:
                findings.append(Finding(
                    control_id=control_id,
                    title=f"Backup Job Failed: {job.get('name', 'unknown')}",
                    description=f"Backup job '{job.get('name')}' last failed on "
                              f"{job.get('last_run', 'unknown')}: {job.get('error', 'unknown error')}",
                    severity="High",
                    cfr_reference="45 CFR § 164.308(a)(7)",
                    remediation=f"Investigate and resolve backup failure for '{job.get('name')}'. "
                              f"Ensure backup is completing successfully before next scheduled run.",
                    evidence_summary=f"Job: {job.get('name')}, Error: {job.get('error')}",
                    estimated_effort="Quick Win",
                ))

        # Check backup testing
        last_test = data.get("last_restore_test", {})
        test_date = last_test.get("date", "")
        try:
            test_dt = datetime.fromisoformat(test_date)
            days_since_test = (datetime.now() - test_dt).days
        except (ValueError, TypeError):
            days_since_test = 999

        if days_since_test > 365:
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="Backup Restore Test Overdue",
                description=f"Last restore test was {days_since_test} days ago. "
                          f"Annual testing is recommended.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(7)",
                remediation="Conduct a backup restore test to verify data recovery capability.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        successful = len([j for j in jobs if j.get("last_status") == "success"])
        if not findings:
            status = CheckStatus.PASS.value
        elif failed_jobs:
            status = CheckStatus.PARTIAL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_jobs": len(jobs),
            "successful": successful,
            "failed": len(failed_jobs),
            "backup_type": data.get("backup_type", "Unknown"),
            "schedule": schedule.get("frequency", "Unknown"),
            "last_restore_test": test_date,
            "retention_days": data.get("retention_days", 0),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Backups: {successful}/{len(jobs)} successful, Last test: {days_since_test}d ago",
            decay_days=30,
        )

    def _check_dr_capability(self, control_id: str, data: dict) -> CheckResult:
        """Check 72-hour disaster recovery capability."""
        dr_plan = data.get("dr_plan", {})
        dr_tests = data.get("dr_tests", [])

        findings = []
        score = 1.0

        if not dr_plan.get("exists", False):
            score -= 0.5
            findings.append(Finding(
                control_id=control_id,
                title="No Disaster Recovery Plan",
                description="No documented DR plan found.",
                severity="Critical",
                cfr_reference="45 CFR § 164.308(a)(7)(ii)(B)",
                remediation="Develop a DR plan with documented 72-hour RTO for critical ePHI systems.",
                estimated_effort="Short-term",
            ))

        rto_hours = dr_plan.get("rto_hours", 999)
        if rto_hours > 72:
            score -= 0.3
            findings.append(Finding(
                control_id=control_id,
                title=f"RTO Exceeds 72 Hours ({rto_hours}h)",
                description=f"Current RTO is {rto_hours} hours, exceeding the 72-hour requirement.",
                severity="Critical",
                cfr_reference="45 CFR § 164.308(a)(7)(ii)(B)",
                remediation="Reduce RTO to 72 hours or less through improved DR procedures, "
                          "infrastructure, or cloud-based recovery options.",
                estimated_effort="Strategic",
            ))

        if not dr_tests:
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="DR Plan Not Tested",
                description="No disaster recovery test records found.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(7)(ii)(B)",
                remediation="Conduct a DR test to verify 72-hour restoration capability.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif any(f.severity == "Critical" for f in findings):
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "dr_plan_exists": dr_plan.get("exists", False),
            "rto_hours": rto_hours,
            "rpo_hours": dr_plan.get("rpo_hours", "Unknown"),
            "dr_tests_conducted": len(dr_tests),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"DR plan: {'yes' if dr_plan.get('exists') else 'no'}, RTO: {rto_hours}h, Tests: {len(dr_tests)}",
            decay_days=365,
        )

    def get_evidence(self) -> dict:
        return self._evidence

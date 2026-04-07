"""Audit Logging & Log Collection verification check module."""

from __future__ import annotations

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class AuditLoggingCheck(BaseCheck):
    """Verify centralized logging, retention, and review procedures."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._live_check(control_id, method)

    def _live_check(self, control_id: str, method: str) -> CheckResult:
        """Live mode: load evidence from user-configured file path."""
        data = self._load_evidence_file("audit_logs")
        if data is None:
            return self._make_not_configured_result(control_id, "audit_logs", 30)
        return self._check_audit_logging(control_id, data)


    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("audit_logs.json") or {}
        return self._check_audit_logging(control_id, data)

    def _check_audit_logging(self, control_id: str, data: dict) -> CheckResult:
        """Check audit logging configuration and compliance."""
        siem = data.get("siem", {})
        log_sources = data.get("log_sources", [])
        retention = data.get("retention", {})
        review_procedures = data.get("review_procedures", {})

        findings = []
        score = 1.0

        # Check SIEM status
        if not siem.get("active", False):
            score -= 0.4
            findings.append(Finding(
                control_id=control_id,
                title="SIEM/Central Logging Not Active",
                description="Centralized log collection system is not active or configured.",
                severity="High",
                cfr_reference="45 CFR § 164.312(b)",
                remediation="Deploy and configure centralized logging (SIEM) for all "
                          "ePHI-handling systems.",
                estimated_effort="Strategic",
            ))

        # Check log source coverage
        total_sources = len(log_sources)
        active_sources = sum(1 for s in log_sources if s.get("status") == "active")
        if total_sources > 0 and active_sources < total_sources:
            missing = total_sources - active_sources
            score -= 0.1 * missing
            inactive = [s.get("name", "?") for s in log_sources if s.get("status") != "active"]
            findings.append(Finding(
                control_id=control_id,
                title=f"{missing} Log Source(s) Not Collecting",
                description=f"The following log sources are not actively collecting: "
                          f"{', '.join(inactive)}",
                severity="Medium",
                cfr_reference="45 CFR § 164.312(b)",
                remediation="Restore log collection for all inactive sources. Investigate "
                          "and resolve connectivity or agent issues.",
                evidence_summary=f"Inactive sources: {inactive}",
                estimated_effort="Quick Win",
            ))

        # Check retention
        retention_days = retention.get("days", 0)
        required_days = 2190  # 6 years
        if retention_days < required_days:
            score -= 0.15
            findings.append(Finding(
                control_id=control_id,
                title="Log Retention Below 6-Year Requirement",
                description=f"Log retention is set to {retention_days} days. "
                          f"HIPAA requires 6-year retention ({required_days} days).",
                severity="Medium",
                cfr_reference="45 CFR § 164.312(b)",
                remediation=f"Increase log retention to at least {required_days} days (6 years).",
                estimated_effort="Short-term",
            ))

        # Check review procedures
        if not review_procedures.get("regular_reviews", False):
            score -= 0.1
            findings.append(Finding(
                control_id=control_id,
                title="No Regular Log Review Procedures",
                description="No evidence of regular audit log review procedures.",
                severity="Medium",
                cfr_reference="45 CFR § 164.312(b)",
                remediation="Establish procedures for regular log review and anomaly detection.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score <= 0.5:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "siem_active": siem.get("active", False),
            "siem_type": siem.get("type", "Unknown"),
            "total_log_sources": total_sources,
            "active_log_sources": active_sources,
            "retention_days": retention_days,
            "regular_reviews": review_procedures.get("regular_reviews", False),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"SIEM: {siem.get('type', '?')}, Sources: {active_sources}/{total_sources}, Retention: {retention_days}d",
            decay_days=30,
        )

    def get_evidence(self) -> dict:
        return self._evidence

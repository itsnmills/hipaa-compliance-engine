"""Patch Management & Remediation tracking check module."""

from __future__ import annotations

from datetime import datetime

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class PatchManagementCheck(BaseCheck):
    """Verify patch management procedures and SLA compliance."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._live_check(control_id, method)

    def _live_check(self, control_id: str, method: str) -> CheckResult:
        """Live mode: load evidence from user-configured file path."""
        data = self._load_evidence_file("patch_status")
        if data is None:
            return self._make_not_configured_result(control_id, "patch_status", 30)
        return self._check_patch_compliance(control_id, data)


    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("patch_status.json") or {}
        return self._check_patch_compliance(control_id, data)

    def _check_patch_compliance(self, control_id: str, data: dict) -> CheckResult:
        """Check patch management compliance."""
        systems = data.get("systems", [])
        sla_policy = data.get("sla_policy", {})

        findings = []
        score = 1.0

        if not systems:
            return self._make_result(
                control_id=control_id,
                status=CheckStatus.FAIL.value,
                score=0.0,
                findings=[Finding(
                    control_id=control_id,
                    title="No Patch Status Data",
                    description="No patch management data found for ePHI systems.",
                    severity="High",
                    cfr_reference="45 CFR § 164.308(a)(1)(ii)(B)",
                    remediation="Implement a patch management program for all ePHI systems.",
                    estimated_effort="Short-term",
                )],
                details="No patch data",
                decay_days=30,
            )

        # Analyze patch status
        critical_overdue = []
        high_overdue = []

        for system in systems:
            pending = system.get("pending_patches", [])
            for patch in pending:
                severity = patch.get("severity", "Medium")
                days_pending = patch.get("days_pending", 0)

                if severity == "Critical" and days_pending > sla_policy.get("critical_days", 14):
                    critical_overdue.append({
                        "system": system.get("hostname", "?"),
                        "patch": patch.get("name", "?"),
                        "days": days_pending,
                        "cve": patch.get("cve", "N/A"),
                    })
                elif severity == "High" and days_pending > sla_policy.get("high_days", 30):
                    high_overdue.append({
                        "system": system.get("hostname", "?"),
                        "patch": patch.get("name", "?"),
                        "days": days_pending,
                    })

        if critical_overdue:
            score -= 0.15 * min(len(critical_overdue), 3)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(critical_overdue)} Critical Patches Overdue",
                description=f"Critical patches exceeding 14-day SLA: "
                          f"{', '.join(p['cve'] for p in critical_overdue[:3] if p.get('cve') != 'N/A')}. "
                          f"Affected systems: {', '.join(set(p['system'] for p in critical_overdue[:3]))}",
                severity="Critical",
                cfr_reference="45 CFR § 164.308(a)(1)(ii)(B)",
                remediation="Apply overdue critical patches immediately. Prioritize by "
                          "CVSS score and ePHI exposure.",
                evidence_summary=f"Critical overdue: {critical_overdue[:3]}",
                estimated_effort="Quick Win",
            ))

        if high_overdue:
            score -= 0.1 * min(len(high_overdue), 3)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(high_overdue)} High-Priority Patches Overdue",
                description=f"High-priority patches exceeding 30-day SLA on "
                          f"{len(set(p['system'] for p in high_overdue))} system(s).",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(1)(ii)(B)",
                remediation="Apply overdue high-priority patches within the next maintenance window.",
                estimated_effort="Short-term",
            ))

        # Check if patch management process documented
        if not sla_policy.get("documented", False):
            score -= 0.1
            findings.append(Finding(
                control_id=control_id,
                title="Patch Management Process Not Documented",
                description="No formal patch management policy or SLA documentation.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(1)(ii)(B)",
                remediation="Document patch management procedures with defined SLAs.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        total_pending = sum(len(s.get("pending_patches", [])) for s in systems)
        total_applied = sum(s.get("patches_applied_30d", 0) for s in systems)

        if not findings:
            status = CheckStatus.PASS.value
        elif critical_overdue:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "systems_checked": len(systems),
            "total_pending": total_pending,
            "critical_overdue": len(critical_overdue),
            "high_overdue": len(high_overdue),
            "patches_applied_30d": total_applied,
            "sla_documented": sla_policy.get("documented", False),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Patches: {total_pending} pending, {len(critical_overdue)} critical overdue",
            decay_days=30,
        )

    def get_evidence(self) -> dict:
        return self._evidence

"""Business Associate Management verification check module."""

from __future__ import annotations

from datetime import datetime

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class BAManagementCheck(BaseCheck):
    """Verify BA agreements, annual verification, and notification procedures."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details="Live BA management check requires BAA directory configuration",
        )

    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("ba_agreements.json") or {}
        dispatch = {
            "check_baa_compliance": self._check_baa_compliance,
            "check_ba_notification": self._check_ba_notification,
            "check_ba_verification": self._check_ba_verification,
        }
        handler = dispatch.get(method, self._check_baa_compliance)
        return handler(control_id, data)

    def _check_baa_compliance(self, control_id: str, data: dict) -> CheckResult:
        """Check BAA compliance for all business associates."""
        bas = data.get("business_associates", [])

        findings = []
        score = 1.0

        if not bas:
            return self._make_result(
                control_id=control_id,
                status=CheckStatus.PASS.value,
                score=1.0,
                evidence={"business_associates": 0, "note": "No BAs identified"},
                details="No business associates identified",
                decay_days=365,
            )

        # Check each BA for current BAA
        expired_baas = [ba for ba in bas if ba.get("baa_status") == "expired"]
        missing_baas = [ba for ba in bas if ba.get("baa_status") == "missing"]

        if missing_baas:
            score -= 0.2 * len(missing_baas)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(missing_baas)} BA(s) Missing BAA",
                description=f"Business associates without signed BAA: "
                          f"{', '.join(ba.get('name', '?') for ba in missing_baas)}",
                severity="Critical",
                cfr_reference="45 CFR § 164.308(b)",
                remediation="Execute BAAs with all business associates immediately.",
                evidence_summary=f"Missing BAAs: {[ba.get('name') for ba in missing_baas]}",
                estimated_effort="Short-term",
            ))

        if expired_baas:
            score -= 0.1 * len(expired_baas)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(expired_baas)} Expired BAA(s)",
                description=f"BAAs requiring renewal: "
                          f"{', '.join(ba.get('name', '?') for ba in expired_baas)}",
                severity="High",
                cfr_reference="45 CFR § 164.308(b)",
                remediation="Renew expired BAAs. Update to include 2025 rule requirements.",
                evidence_summary=f"Expired BAAs: {[ba.get('name') for ba in expired_baas]}",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        compliant = len([ba for ba in bas if ba.get("baa_status") == "current"])
        if not findings:
            status = CheckStatus.PASS.value
        elif missing_baas:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_bas": len(bas),
            "current_baas": compliant,
            "expired_baas": len(expired_baas),
            "missing_baas": len(missing_baas),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"BAs: {len(bas)} total, {compliant} current, {len(expired_baas)} expired, {len(missing_baas)} missing",
            decay_days=365,
        )

    def _check_ba_notification(self, control_id: str, data: dict) -> CheckResult:
        """Check 24-hour BA contingency notification procedures."""
        bas = data.get("business_associates", [])

        findings = []
        score = 1.0

        bas_without_notification = [
            ba for ba in bas if not ba.get("notification_24hr_clause", False)
        ]

        if bas_without_notification:
            score -= 0.15 * len(bas_without_notification)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(bas_without_notification)} BAA(s) Missing 24-Hour Notification Clause",
                description=f"BAAs missing required 24-hour contingency notification: "
                          f"{', '.join(ba.get('name', '?') for ba in bas_without_notification)}",
                severity="High",
                cfr_reference="45 CFR § 164.308(b)(3)",
                remediation="Update BAAs to include 24-hour contingency notification requirement.",
                evidence_summary=f"Missing clause: {[ba.get('name') for ba in bas_without_notification]}",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_bas": len(bas),
            "with_notification_clause": len(bas) - len(bas_without_notification),
            "without_notification_clause": len(bas_without_notification),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"24hr notification: {len(bas) - len(bas_without_notification)}/{len(bas)} BAAs compliant",
            decay_days=365,
        )

    def _check_ba_verification(self, control_id: str, data: dict) -> CheckResult:
        """Check annual BA verification status."""
        bas = data.get("business_associates", [])

        findings = []
        score = 1.0

        unverified = [ba for ba in bas if not ba.get("annual_verification", False)]

        if unverified:
            score -= 0.15 * len(unverified)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(unverified)} BA(s) Missing Annual Verification",
                description=f"Annual safeguard verification not received from: "
                          f"{', '.join(ba.get('name', '?') for ba in unverified)}",
                severity="High",
                cfr_reference="45 CFR § 164.308(b)(4)",
                remediation="Request annual written verification of technical safeguards "
                          "from each BA, certified by a subject matter expert.",
                evidence_summary=f"Unverified BAs: {[ba.get('name') for ba in unverified]}",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif len(unverified) > len(bas) / 2:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_bas": len(bas),
            "verified": len(bas) - len(unverified),
            "unverified": len(unverified),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Annual verification: {len(bas) - len(unverified)}/{len(bas)} BAs verified",
            decay_days=365,
        )

    def get_evidence(self) -> dict:
        return self._evidence

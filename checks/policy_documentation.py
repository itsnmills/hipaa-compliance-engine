"""Policy Documentation verification check module."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path

from engine.models import CheckResult, CheckStatus, Finding
from engine.audit_trail import FileAccessTracker
from checks.base import BaseCheck

# Expected policy filenames for directory-scan mode.
# Maps a human-readable policy name to a list of filename patterns (without extension).
POLICY_FILE_PATTERNS: dict[str, list[str]] = {
    "Risk Analysis": ["risk_analysis", "risk_management"],
    "Access Control Policy": ["access_control"],
    "Security Awareness Training": ["security_awareness_training", "training"],
    "Incident Response Plan": ["incident_response", "ir_plan"],
    "Contingency Plan": ["contingency_plan", "disaster_recovery", "dr_plan"],
    "Business Associate Policy": ["business_associate", "baa_management"],
    "Encryption Policy": ["encryption"],
    "Audit Log Policy": ["audit_log", "audit_controls"],
    "Physical Security Policy": ["physical_security", "facility_access"],
    "Sanction Policy": ["sanction", "sanctions"],
    "Workforce Security Policy": ["workforce_security"],
    "Media Disposal Policy": ["media_disposal", "device_media"],
    "Patch Management Policy": ["patch_management"],
    "Network Security Policy": ["network_segmentation", "network_security"],
}

POLICY_EXTENSIONS = {".pdf", ".docx", ".doc", ".md", ".txt"}


class PolicyDocumentationCheck(BaseCheck):
    """Verify written policies, procedures, and documentation compliance."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._live_check(control_id, method)

    def _live_check(self, control_id: str, method: str) -> CheckResult:
        """Live mode: load evidence from user-configured file path.

        Supports two modes:
        1. JSON manifest mode — user provides a policy_documents.json
        2. Directory scan mode — user points policies_dir at a folder of
           actual .pdf/.docx/.md files. The engine checks filenames and
           modification dates.
        """
        evidence_config = self.config.get("evidence", {})
        path_str = evidence_config.get("policies_dir")
        if not path_str:
            return self._make_not_configured_result(control_id, "policies_dir", 365)

        path = Path(path_str)
        if not path.exists():
            return self._make_not_configured_result(control_id, "policies_dir", 365)

        # Decide mode: directory of real docs vs JSON manifest
        if path.is_dir() and not any(path.glob("*.json")):
            return self._directory_scan_check(control_id, method, path)

        # JSON manifest mode — use existing _load_evidence_file
        data = self._load_evidence_file("policies_dir")
        if data is None:
            return self._make_not_configured_result(control_id, "policies_dir", 365)

        dispatch = {
            "check_risk_analysis": self._check_risk_analysis,
            "check_risk_management": self._check_risk_management,
            "check_security_officer": self._check_security_officer,
            "check_annual_audit": self._check_annual_audit,
            "check_compliance_audit": self._check_compliance_audit,
            "check_documentation": self._check_documentation,
            "check_facility_security": self._check_facility_security,
            "check_workstation_policy": self._check_workstation_policy,
        }
        handler = dispatch.get(method, self._check_documentation)
        return handler(control_id, data)


    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("policy_documents.json") or {}
        dispatch = {
            "check_risk_analysis": self._check_risk_analysis,
            "check_risk_management": self._check_risk_management,
            "check_security_officer": self._check_security_officer,
            "check_annual_audit": self._check_annual_audit,
            "check_compliance_audit": self._check_compliance_audit,
            "check_documentation": self._check_documentation,
            "check_facility_security": self._check_facility_security,
            "check_workstation_policy": self._check_workstation_policy,
        }
        handler = dispatch.get(method, self._check_documentation)
        return handler(control_id, data)

    def _check_risk_analysis(self, control_id: str, data: dict) -> CheckResult:
        """Check for current risk analysis document."""
        risk_analysis = data.get("risk_analysis", {})

        findings = []
        score = 1.0

        if not risk_analysis.get("exists", False):
            return self._make_result(
                control_id=control_id,
                status=CheckStatus.FAIL.value,
                score=0.0,
                findings=[Finding(
                    control_id=control_id,
                    title="No Risk Analysis Document",
                    description="No written risk analysis found. This is a foundational HIPAA requirement.",
                    severity="Critical",
                    cfr_reference="45 CFR § 164.308(a)(1)(i)",
                    remediation="Conduct a comprehensive risk analysis covering all ePHI systems. "
                              "Document all identified risks with likelihood and impact ratings.",
                    estimated_effort="Short-term",
                )],
                details="No risk analysis",
                decay_days=365,
            )

        # Check if current
        last_update = risk_analysis.get("last_update", "")
        try:
            update_dt = datetime.fromisoformat(last_update)
            days_since = (datetime.now() - update_dt).days
        except (ValueError, TypeError):
            days_since = 999

        if days_since > 365:
            score -= 0.3
            findings.append(Finding(
                control_id=control_id,
                title="Risk Analysis Not Updated Annually",
                description=f"Risk analysis last updated {days_since} days ago. Annual updates required.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(1)(i)",
                remediation="Update risk analysis to reflect current environment and threats.",
                estimated_effort="Short-term",
            ))

        if not risk_analysis.get("comprehensive", True):
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="Risk Analysis Not Comprehensive",
                description="Risk analysis does not cover all ePHI systems and threats.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(1)(i)",
                remediation="Expand risk analysis to cover all systems that create, receive, "
                          "maintain, or transmit ePHI.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score < 0.5:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=risk_analysis, findings=findings,
            details=f"Risk analysis: {'exists' if risk_analysis.get('exists') else 'missing'}, "
                   f"Updated: {days_since}d ago",
            decay_days=365,
        )

    def _check_risk_management(self, control_id: str, data: dict) -> CheckResult:
        """Check risk management plan."""
        risk_mgmt = data.get("risk_management", {})
        findings = []
        score = 1.0

        if not risk_mgmt.get("plan_exists", False):
            score -= 0.4
            findings.append(Finding(
                control_id=control_id,
                title="No Risk Management Plan",
                description="No formal risk management plan documented.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(1)(ii)(B)",
                remediation="Develop a risk management plan addressing identified risks.",
                estimated_effort="Short-term",
            ))

        if not risk_mgmt.get("mitigation_tracking", False):
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="No Risk Mitigation Tracking",
                description="Risk remediation efforts are not being tracked.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(1)(ii)(B)",
                remediation="Implement risk mitigation tracking with assigned owners and timelines.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        status = CheckStatus.PASS.value if not findings else (
            CheckStatus.FAIL.value if score < 0.5 else CheckStatus.PARTIAL.value
        )

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=risk_mgmt, findings=findings,
            details=f"Risk management: plan={risk_mgmt.get('plan_exists', False)}",
            decay_days=365,
        )

    def _check_security_officer(self, control_id: str, data: dict) -> CheckResult:
        """Check security officer designation."""
        officer = data.get("security_officer", {})
        findings = []
        score = 1.0

        if not officer.get("designated", False):
            score = 0.0
            findings.append(Finding(
                control_id=control_id,
                title="No Designated Security Official",
                description="No security official has been formally designated.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(2)",
                remediation="Formally designate a Security Official in writing.",
                estimated_effort="Quick Win",
            ))
        elif not officer.get("documented", False):
            score = 0.7
            findings.append(Finding(
                control_id=control_id,
                title="Security Official Not Formally Documented",
                description=f"Security official ({officer.get('name', '?')}) is identified but "
                          f"designation is not formally documented.",
                severity="Medium",
                cfr_reference="45 CFR § 164.308(a)(2)",
                remediation="Create written documentation of security official designation.",
                estimated_effort="Quick Win",
            ))

        status = CheckStatus.PASS.value if not findings else (
            CheckStatus.FAIL.value if score == 0 else CheckStatus.PARTIAL.value
        )

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=officer, findings=findings,
            details=f"Security officer: {officer.get('name', 'not designated')}",
            decay_days=365,
        )

    def _check_annual_audit(self, control_id: str, data: dict) -> CheckResult:
        """Check annual evaluation/audit."""
        audit = data.get("annual_audit", {})
        return self._check_audit_common(control_id, audit)

    def _check_compliance_audit(self, control_id: str, data: dict) -> CheckResult:
        """Check annual compliance audit."""
        audit = data.get("compliance_audit", data.get("annual_audit", {}))
        return self._check_audit_common(control_id, audit)

    def _check_audit_common(self, control_id: str, audit: dict) -> CheckResult:
        """Common audit check logic."""
        findings = []
        score = 1.0

        if not audit.get("conducted", False):
            score -= 0.5
            findings.append(Finding(
                control_id=control_id,
                title="Annual Compliance Audit Not Conducted",
                description="No evidence of annual compliance audit within the past 12 months.",
                severity="High",
                cfr_reference="45 CFR § 164.308(a)(8)",
                remediation="Conduct an annual compliance audit covering all Security Rule requirements.",
                estimated_effort="Short-term",
            ))
        else:
            last_audit = audit.get("last_date", "")
            try:
                audit_dt = datetime.fromisoformat(last_audit)
                days_since = (datetime.now() - audit_dt).days
                if days_since > 365:
                    score -= 0.3
                    findings.append(Finding(
                        control_id=control_id,
                        title="Annual Audit Overdue",
                        description=f"Last audit was {days_since} days ago.",
                        severity="Medium",
                        cfr_reference="45 CFR § 164.308(a)(8)",
                        remediation="Schedule annual compliance audit.",
                        estimated_effort="Short-term",
                    ))
            except (ValueError, TypeError):
                pass

        score = max(0.0, score)
        status = CheckStatus.PASS.value if not findings else (
            CheckStatus.FAIL.value if score < 0.5 else CheckStatus.PARTIAL.value
        )

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=audit, findings=findings,
            details=f"Annual audit: {'conducted' if audit.get('conducted') else 'not conducted'}",
            decay_days=365,
        )

    def _check_documentation(self, control_id: str, data: dict) -> CheckResult:
        """Check written documentation and 6-year retention."""
        policies = data.get("policies", [])
        retention = data.get("retention", {})

        findings = []
        score = 1.0

        required_policies = data.get("required_policies", [])
        existing = {p.get("name") for p in policies if p.get("exists", False)}
        missing = [p for p in required_policies if p not in existing]

        if missing:
            score -= 0.1 * len(missing)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(missing)} Required Policy Document(s) Missing",
                description=f"Missing policies: {', '.join(missing[:5])}"
                          + (f" and {len(missing) - 5} more" if len(missing) > 5 else ""),
                severity="High",
                cfr_reference="45 CFR § 164.316",
                remediation="Create all required policy documents.",
                evidence_summary=f"Missing: {missing}",
                estimated_effort="Short-term",
            ))

        # Check reviews
        overdue_reviews = [
            p for p in policies
            if p.get("exists") and p.get("review_overdue", False)
        ]
        if overdue_reviews:
            score -= 0.05 * len(overdue_reviews)
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(overdue_reviews)} Policies Need Review",
                description="Some policies have not been reviewed within 12 months.",
                severity="Medium",
                cfr_reference="45 CFR § 164.316",
                remediation="Review and update all overdue policy documents.",
                estimated_effort="Short-term",
            ))

        # Check retention
        if not retention.get("6yr_compliant", True):
            score -= 0.15
            findings.append(Finding(
                control_id=control_id,
                title="Document Retention Below 6-Year Requirement",
                description="Document retention does not meet the 6-year HIPAA requirement.",
                severity="Medium",
                cfr_reference="45 CFR § 164.316",
                remediation="Configure retention policies to maintain documents for at least 6 years.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score < 0.5:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "total_policies": len(policies),
            "existing": len(existing),
            "missing": len(missing),
            "overdue_reviews": len(overdue_reviews),
            "retention_compliant": retention.get("6yr_compliant", False),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Policies: {len(existing)}/{len(required_policies)}, "
                   f"Reviews overdue: {len(overdue_reviews)}",
            decay_days=365,
        )

    def _check_facility_security(self, control_id: str, data: dict) -> CheckResult:
        """Check facility security plan."""
        facility = data.get("facility_security", {})
        findings = []
        score = 1.0

        if not facility.get("plan_exists", False):
            score -= 0.4
            findings.append(Finding(
                control_id=control_id,
                title="No Facility Security Plan",
                description="No documented facility security plan.",
                severity="Medium",
                cfr_reference="45 CFR § 164.310(a)",
                remediation="Develop a facility security plan covering physical access controls.",
                estimated_effort="Short-term",
            ))

        if not facility.get("visitor_logs", False):
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="No Visitor Log Procedures",
                description="No visitor logging procedures for secure areas.",
                severity="Low",
                cfr_reference="45 CFR § 164.310(a)",
                remediation="Implement visitor logging for areas with ePHI access.",
                estimated_effort="Quick Win",
            ))

        score = max(0.0, score)
        status = CheckStatus.PASS.value if not findings else (
            CheckStatus.FAIL.value if score < 0.5 else CheckStatus.PARTIAL.value
        )

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=facility, findings=findings,
            details=f"Facility security: plan={facility.get('plan_exists', False)}",
            decay_days=365,
        )

    def _check_workstation_policy(self, control_id: str, data: dict) -> CheckResult:
        """Check workstation use and security policies."""
        workstation = data.get("workstation_policy", {})
        findings = []
        score = 1.0

        if not workstation.get("use_policy", False):
            score -= 0.3
            findings.append(Finding(
                control_id=control_id,
                title="No Workstation Use Policy",
                description="No workstation use policy documented.",
                severity="Medium",
                cfr_reference="45 CFR § 164.310(b)-(c)",
                remediation="Develop workstation use and security policies.",
                estimated_effort="Short-term",
            ))

        if not workstation.get("auto_lock", False):
            score -= 0.2
            findings.append(Finding(
                control_id=control_id,
                title="Auto-Lock Not Configured",
                description="Workstations not configured to auto-lock after inactivity.",
                severity="Medium",
                cfr_reference="45 CFR § 164.310(b)-(c)",
                remediation="Configure automatic screen lock after 15 minutes of inactivity.",
                estimated_effort="Quick Win",
            ))

        score = max(0.0, score)
        status = CheckStatus.PASS.value if not findings else (
            CheckStatus.FAIL.value if score < 0.5 else CheckStatus.PARTIAL.value
        )

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=workstation, findings=findings,
            details=f"Workstation policy: {workstation.get('use_policy', False)}, "
                   f"auto-lock: {workstation.get('auto_lock', False)}",
            decay_days=365,
        )

    # ------------------------------------------------------------------
    # Directory-Scan Mode
    # ------------------------------------------------------------------

    def _directory_scan_check(
        self, control_id: str, method: str, policies_dir: Path,
    ) -> CheckResult:
        """Scan a directory of actual policy documents by filename pattern.

        Checks:
        - Which expected policy documents exist
        - Whether each file has been modified within the last 12 months
        """
        tracker = FileAccessTracker.instance()
        tracker.record(
            str(policies_dir), "read", self.__class__.__name__,
            "Policy documents directory (scan mode)",
        )

        # Collect all document files in the directory
        doc_files: dict[str, Path] = {}
        for f in policies_dir.iterdir():
            if f.is_file() and f.suffix.lower() in POLICY_EXTENSIONS:
                doc_files[f.stem.lower()] = f

        now = datetime.now()
        found_policies: list[dict] = []
        missing_policies: list[str] = []
        overdue_reviews: list[str] = []

        for policy_name, patterns in POLICY_FILE_PATTERNS.items():
            matched_file = None
            for pattern in patterns:
                # Try exact match first, then prefix match
                if pattern in doc_files:
                    matched_file = doc_files[pattern]
                    break
                # Prefix match: risk_analysis_v2.pdf
                for stem, fpath in doc_files.items():
                    if stem.startswith(pattern):
                        matched_file = fpath
                        break
                if matched_file:
                    break

            if matched_file:
                mtime = datetime.fromtimestamp(matched_file.stat().st_mtime)
                days_since = (now - mtime).days
                review_overdue = days_since > 365

                tracker.record(
                    str(matched_file), "read", self.__class__.__name__,
                    f"Policy document: {policy_name}",
                )

                found_policies.append({
                    "name": policy_name,
                    "exists": True,
                    "file": matched_file.name,
                    "last_modified": mtime.isoformat()[:10],
                    "days_since_modified": days_since,
                    "review_overdue": review_overdue,
                })
                if review_overdue:
                    overdue_reviews.append(policy_name)
            else:
                missing_policies.append(policy_name)
                found_policies.append({
                    "name": policy_name,
                    "exists": False,
                })

        # Build result
        total_expected = len(POLICY_FILE_PATTERNS)
        total_found = total_expected - len(missing_policies)
        findings = []
        score = 1.0

        if missing_policies:
            penalty = min(0.6, 0.05 * len(missing_policies))
            score -= penalty
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(missing_policies)} Expected Policy Document(s) Not Found",
                description=(
                    f"The following policies were not found in {policies_dir}: "
                    + ", ".join(missing_policies[:5])
                    + (f" and {len(missing_policies) - 5} more"
                       if len(missing_policies) > 5 else "")
                ),
                severity="High" if len(missing_policies) > 3 else "Medium",
                cfr_reference="45 CFR § 164.316",
                remediation=(
                    "Create the missing policy documents and save them in the "
                    "policies directory. See templates/README.md for expected filenames."
                ),
                estimated_effort="Short-term",
            ))

        if overdue_reviews:
            penalty = min(0.3, 0.03 * len(overdue_reviews))
            score -= penalty
            findings.append(Finding(
                control_id=control_id,
                title=f"{len(overdue_reviews)} Policies Not Updated Within 12 Months",
                description=(
                    "The following policies have not been modified in over 12 months: "
                    + ", ".join(overdue_reviews[:5])
                ),
                severity="Medium",
                cfr_reference="45 CFR § 164.316",
                remediation="Review and update all overdue policy documents.",
                estimated_effort="Short-term",
            ))

        score = max(0.0, score)
        if not findings:
            status = CheckStatus.PASS.value
        elif score < 0.5:
            status = CheckStatus.FAIL.value
        else:
            status = CheckStatus.PARTIAL.value

        evidence = {
            "mode": "directory_scan",
            "directory": str(policies_dir),
            "total_expected": total_expected,
            "total_found": total_found,
            "missing": missing_policies,
            "overdue_reviews": overdue_reviews,
            "policies": found_policies,
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Directory scan: {total_found}/{total_expected} policies found, "
                   f"{len(overdue_reviews)} overdue for review",
            decay_days=365,
        )

    def get_evidence(self) -> dict:
        return self._evidence

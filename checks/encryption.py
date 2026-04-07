"""Encryption at Rest & In Transit verification check module."""

from __future__ import annotations

from engine.models import CheckResult, CheckStatus, Finding
from checks.base import BaseCheck


class EncryptionCheck(BaseCheck):
    """Verify encryption at rest and in transit for ePHI systems."""

    def execute(self, control_id: str, method: str) -> CheckResult:
        if self.demo:
            return self._demo_check(control_id, method)
        return self._make_result(
            control_id=control_id,
            status=CheckStatus.ERROR.value,
            score=0.0,
            details="Live encryption check requires system access configuration",
        )

    def _demo_check(self, control_id: str, method: str) -> CheckResult:
        data = self._load_demo_data("encryption_status.json") or {}
        dispatch = {
            "check_encryption_rest": self._check_encryption_rest,
            "check_encryption_transit": self._check_encryption_transit,
            "check_integrity_controls": self._check_integrity_controls,
        }
        handler = dispatch.get(method, self._check_encryption_rest)
        return handler(control_id, data)

    def _check_encryption_rest(self, control_id: str, data: dict) -> CheckResult:
        """Check encryption at rest across all ePHI systems."""
        endpoints = data.get("endpoints", [])
        databases = data.get("databases", [])
        cloud_storage = data.get("cloud_storage", [])

        findings = []
        total_systems = len(endpoints) + len(databases) + len(cloud_storage)
        encrypted_count = 0

        # Check endpoints
        for ep in endpoints:
            if ep.get("encrypted", False):
                encrypted_count += 1
            else:
                findings.append(Finding(
                    control_id=control_id,
                    title=f"Unencrypted Endpoint: {ep.get('hostname', 'unknown')}",
                    description=f"Endpoint {ep.get('hostname')} ({ep.get('os', 'unknown')}) "
                              f"does not have full-disk encryption enabled.",
                    severity="Critical",
                    cfr_reference="45 CFR § 164.312(a)(2)(iv)",
                    remediation=f"Enable full-disk encryption ({ep.get('recommended_solution', 'BitLocker/FileVault/LUKS')}) "
                              f"on {ep.get('hostname')}. AES-256 is mandatory under the 2025 rule.",
                    evidence_summary=f"Host: {ep.get('hostname')}, OS: {ep.get('os')}, Encrypted: No",
                    estimated_effort="Short-term",
                ))

        # Check databases
        for db in databases:
            if db.get("tde_enabled", False):
                encrypted_count += 1
            else:
                findings.append(Finding(
                    control_id=control_id,
                    title=f"Database Without TDE: {db.get('name', 'unknown')}",
                    description=f"Database {db.get('name')} does not have Transparent "
                              f"Data Encryption enabled.",
                    severity="Critical",
                    cfr_reference="45 CFR § 164.312(a)(2)(iv)",
                    remediation=f"Enable TDE on {db.get('name')}. Configure AES-256 encryption keys.",
                    evidence_summary=f"Database: {db.get('name')}, TDE: Disabled",
                    estimated_effort="Short-term",
                ))

        # Check cloud storage
        for cs in cloud_storage:
            if cs.get("encrypted", False):
                encrypted_count += 1

        encryption_rate = encrypted_count / total_systems if total_systems > 0 else 0
        score = encryption_rate
        if not findings:
            status = CheckStatus.PASS.value
        elif encryption_rate >= 0.8:
            status = CheckStatus.PARTIAL.value
        else:
            status = CheckStatus.FAIL.value

        evidence = {
            "total_systems": total_systems,
            "encrypted_systems": encrypted_count,
            "encryption_rate": f"{encryption_rate:.0%}",
            "endpoints_checked": len(endpoints),
            "databases_checked": len(databases),
            "cloud_storage_checked": len(cloud_storage),
            "algorithm": data.get("algorithm", "AES-256"),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"Encryption at rest: {encrypted_count}/{total_systems} systems encrypted",
            decay_days=30,
        )

    def _check_encryption_transit(self, control_id: str, data: dict) -> CheckResult:
        """Check encryption in transit (TLS configuration)."""
        tls_configs = data.get("tls_configurations", [])
        certificates = data.get("certificates", [])

        findings = []
        total = len(tls_configs)
        compliant = 0

        for cfg in tls_configs:
            tls_version = cfg.get("tls_version", "")
            if tls_version in ("1.2", "1.3", "TLS 1.2", "TLS 1.3"):
                compliant += 1
            else:
                findings.append(Finding(
                    control_id=control_id,
                    title=f"Outdated TLS on {cfg.get('service', 'unknown')}",
                    description=f"Service {cfg.get('service')} is using TLS {tls_version}. "
                              f"TLS 1.2+ is mandatory.",
                    severity="Critical",
                    cfr_reference="45 CFR § 164.312(e)",
                    remediation=f"Upgrade {cfg.get('service')} to TLS 1.2 or higher. "
                              f"Disable TLS 1.0 and 1.1.",
                    evidence_summary=f"Service: {cfg.get('service')}, Current TLS: {tls_version}",
                    estimated_effort="Short-term",
                ))

        # Check certificate expiry
        for cert in certificates:
            if cert.get("expired", False):
                findings.append(Finding(
                    control_id=control_id,
                    title=f"Expired Certificate: {cert.get('domain', 'unknown')}",
                    description=f"TLS certificate for {cert.get('domain')} expired on "
                              f"{cert.get('expiry_date', 'unknown')}.",
                    severity="High",
                    cfr_reference="45 CFR § 164.312(e)",
                    remediation=f"Renew TLS certificate for {cert.get('domain')} immediately.",
                    evidence_summary=f"Domain: {cert.get('domain')}, Expired: {cert.get('expiry_date')}",
                    estimated_effort="Quick Win",
                ))

        tls_rate = compliant / total if total > 0 else 0
        score = tls_rate * (0.85 if any(c.get("expired") for c in certificates) else 1.0)

        if not findings:
            status = CheckStatus.PASS.value
        elif tls_rate >= 0.9:
            status = CheckStatus.PARTIAL.value
        else:
            status = CheckStatus.FAIL.value

        evidence = {
            "services_checked": total,
            "tls_compliant": compliant,
            "compliance_rate": f"{tls_rate:.0%}",
            "certificates_checked": len(certificates),
            "expired_certificates": sum(1 for c in certificates if c.get("expired")),
        }

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence=evidence, findings=findings,
            details=f"TLS compliance: {compliant}/{total} services on TLS 1.2+",
            decay_days=30,
        )

    def _check_integrity_controls(self, control_id: str, data: dict) -> CheckResult:
        """Check data integrity mechanisms."""
        integrity = data.get("integrity_controls", {})
        checksums = integrity.get("checksums_enabled", False)
        backup_verify = integrity.get("backup_verification", False)
        db_constraints = integrity.get("database_constraints", False)

        score = 0.0
        findings = []
        checks_passed = 0

        if checksums:
            score += 0.35
            checks_passed += 1
        if backup_verify:
            score += 0.35
            checks_passed += 1
        if db_constraints:
            score += 0.30
            checks_passed += 1

        if not checksums:
            findings.append(Finding(
                control_id=control_id,
                title="No Data Integrity Checksums",
                description="ePHI data integrity checksums are not enabled.",
                severity="Medium",
                cfr_reference="45 CFR § 164.312(c)",
                remediation="Implement checksums or hash verification for ePHI data integrity.",
                estimated_effort="Short-term",
            ))

        if checks_passed == 3:
            status = CheckStatus.PASS.value
        elif checks_passed >= 1:
            status = CheckStatus.PARTIAL.value
        else:
            status = CheckStatus.FAIL.value

        return self._make_result(
            control_id=control_id, status=status, score=score,
            evidence={"checksums": checksums, "backup_verify": backup_verify,
                      "db_constraints": db_constraints},
            findings=findings,
            details=f"Integrity controls: {checks_passed}/3 mechanisms in place",
            decay_days=180,
        )

    def get_evidence(self) -> dict:
        return self._evidence

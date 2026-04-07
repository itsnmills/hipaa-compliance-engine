"""Data models for the HIPAA Compliance Engine."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional


class CheckStatus(str, Enum):
    """Status of a compliance check."""
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"


class Severity(str, Enum):
    """Severity level for controls and findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Category(str, Enum):
    """Control safeguard categories."""
    TECHNICAL = "Technical"
    ADMINISTRATIVE = "Administrative"
    PHYSICAL = "Physical"
    CROSS_CUTTING = "Cross-Cutting"


class ScoreBand(str, Enum):
    """Compliance score bands."""
    FULLY_COMPLIANT = "Fully Compliant"
    SUBSTANTIALLY_COMPLIANT = "Substantially Compliant"
    PARTIALLY_COMPLIANT = "Partially Compliant"
    SIGNIFICANT_GAPS = "Significant Gaps"
    NON_COMPLIANT = "Non-Compliant"


def get_score_band(score: float) -> ScoreBand:
    """Determine the compliance score band for a given score."""
    if score >= 95:
        return ScoreBand.FULLY_COMPLIANT
    elif score >= 80:
        return ScoreBand.SUBSTANTIALLY_COMPLIANT
    elif score >= 60:
        return ScoreBand.PARTIALLY_COMPLIANT
    elif score >= 40:
        return ScoreBand.SIGNIFICANT_GAPS
    else:
        return ScoreBand.NON_COMPLIANT


def get_band_color(band: ScoreBand) -> str:
    """Get the display color name for a score band."""
    colors = {
        ScoreBand.FULLY_COMPLIANT: "green",
        ScoreBand.SUBSTANTIALLY_COMPLIANT: "light_green",
        ScoreBand.PARTIALLY_COMPLIANT: "yellow",
        ScoreBand.SIGNIFICANT_GAPS: "orange",
        ScoreBand.NON_COMPLIANT: "red",
    }
    return colors.get(band, "white")


@dataclass
class Finding:
    """A specific finding from a compliance check."""
    control_id: str
    title: str
    description: str
    severity: str
    cfr_reference: str
    remediation: str
    evidence_summary: str = ""
    estimated_effort: str = "Short-term"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class CheckResult:
    """Result of running a compliance check against a control."""
    control_id: str
    status: str
    score: float
    timestamp: str
    evidence: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    next_check_due: str = ""
    check_module: str = ""
    details: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> CheckResult:
        findings_data = data.pop("findings", [])
        findings = [Finding.from_dict(f) for f in findings_data]
        filtered = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        filtered["findings"] = findings
        return cls(**filtered)


@dataclass
class ControlDefinition:
    """Definition of a HIPAA control from the registry."""
    id: str
    cfr_reference: str
    category: str
    title: str
    description: str
    check_module: str
    check_method: str
    severity: str
    frequency: str
    freshness_decay_days: int
    evidence_required: str
    remediation_guidance: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ControlStatus:
    """Current compliance status of a control."""
    control: ControlDefinition
    last_check: Optional[CheckResult] = None
    freshness: float = 0.0
    effective_score: float = 0.0
    is_stale: bool = True
    days_since_check: Optional[int] = None
    next_due: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "control_id": self.control.id,
            "control_title": self.control.title,
            "category": self.control.category,
            "severity": self.control.severity,
            "last_check": self.last_check.to_dict() if self.last_check else None,
            "freshness": round(self.freshness, 3),
            "effective_score": round(self.effective_score, 3),
            "is_stale": self.is_stale,
            "days_since_check": self.days_since_check,
            "next_due": self.next_due,
        }


@dataclass
class CategoryScore:
    """Compliance score for a category."""
    category: str
    score: float
    weight: float
    weighted_score: float
    controls_total: int
    controls_passing: int
    controls_failing: int
    controls_partial: int
    band: str = ""

    def __post_init__(self):
        if not self.band:
            self.band = get_score_band(self.score).value


@dataclass
class ComplianceReport:
    """Complete compliance report data."""
    organization_name: str
    organization_type: str
    report_date: str
    overall_score: float
    overall_band: str
    category_scores: list[CategoryScore] = field(default_factory=list)
    control_statuses: list[ControlStatus] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    check_results: list[CheckResult] = field(default_factory=list)
    stale_controls: list[ControlStatus] = field(default_factory=list)
    approaching_stale: list[ControlStatus] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL.value]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH.value]

    @property
    def medium_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM.value]

    @property
    def low_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.LOW.value]

    @property
    def passing_controls(self) -> list[ControlStatus]:
        return [cs for cs in self.control_statuses
                if cs.last_check and cs.last_check.status == CheckStatus.PASS.value]

    @property
    def failing_controls(self) -> list[ControlStatus]:
        return [cs for cs in self.control_statuses
                if cs.last_check and cs.last_check.status == CheckStatus.FAIL.value]

    @property
    def partial_controls(self) -> list[ControlStatus]:
        return [cs for cs in self.control_statuses
                if cs.last_check and cs.last_check.status == CheckStatus.PARTIAL.value]

    def to_dict(self) -> dict:
        return {
            "organization_name": self.organization_name,
            "organization_type": self.organization_type,
            "report_date": self.report_date,
            "overall_score": round(self.overall_score, 1),
            "overall_band": self.overall_band,
            "category_scores": [asdict(cs) for cs in self.category_scores],
            "control_count": len(self.control_statuses),
            "findings_count": len(self.findings),
            "critical_count": len(self.critical_findings),
            "high_count": len(self.high_findings),
            "medium_count": len(self.medium_findings),
            "low_count": len(self.low_findings),
        }

"""Report styling, templates, and color definitions."""

from __future__ import annotations


# ============================================================
# BRAND COLORS (consistent with hipaa-risk-assessment)
# ============================================================

BRAND_BLUE = "#1E40AF"
BRAND_DARK = "#1E293B"
BRAND_LIGHT_BG = "#F8FAFC"
BRAND_BORDER = "#E2E8F0"

# Risk/severity colors
COLOR_CRITICAL = "#DC2626"
COLOR_HIGH = "#EA580C"
COLOR_MEDIUM = "#CA8A04"
COLOR_LOW = "#16A34A"
COLOR_NEUTRAL = "#64748B"
COLOR_PASS = "#16A34A"

# Background colors for risk badges
BG_CRITICAL = "#FEF2F2"
BG_HIGH = "#FFF7ED"
BG_MEDIUM = "#FEFCE8"
BG_LOW = "#F0FDF4"

# Score band colors
BAND_COLORS = {
    "Fully Compliant": "#16A34A",
    "Substantially Compliant": "#65A30D",
    "Partially Compliant": "#CA8A04",
    "Significant Gaps": "#EA580C",
    "Non-Compliant": "#DC2626",
}

BAND_BG_COLORS = {
    "Fully Compliant": "#F0FDF4",
    "Substantially Compliant": "#F7FEE7",
    "Partially Compliant": "#FEFCE8",
    "Significant Gaps": "#FFF7ED",
    "Non-Compliant": "#FEF2F2",
}

SEVERITY_COLORS = {
    "Critical": COLOR_CRITICAL,
    "High": COLOR_HIGH,
    "Medium": COLOR_MEDIUM,
    "Low": COLOR_LOW,
}

SEVERITY_BG_COLORS = {
    "Critical": BG_CRITICAL,
    "High": BG_HIGH,
    "Medium": BG_MEDIUM,
    "Low": BG_LOW,
}

STATUS_COLORS = {
    "PASS": COLOR_PASS,
    "FAIL": COLOR_CRITICAL,
    "PARTIAL": COLOR_MEDIUM,
    "ERROR": COLOR_NEUTRAL,
    "NOT_CHECKED": COLOR_NEUTRAL,
    "NOT_APPLICABLE": COLOR_NEUTRAL,
}


# ============================================================
# TEXT TEMPLATES
# ============================================================

EXECUTIVE_SUMMARY_TEMPLATES = {
    "Fully Compliant": (
        "{org_name} demonstrates excellent HIPAA Security Rule compliance with an overall "
        "score of {score}/100. The organization has implemented comprehensive administrative, "
        "physical, and technical safeguards meeting the 2025 NPRM mandatory requirements. "
        "Minor improvement opportunities have been identified in the detailed findings. "
        "Recommend maintaining current security practices and scheduling annual re-assessment "
        "to sustain this compliance posture."
    ),
    "Substantially Compliant": (
        "{org_name} has achieved strong HIPAA Security Rule compliance with an overall "
        "score of {score}/100. Most administrative, physical, and technical safeguards "
        "are properly implemented and maintained. A small number of gaps require attention "
        "to achieve full compliance with the 2025 mandatory requirements. A focused "
        "remediation plan addressing the identified findings should be completed within "
        "60 days to maintain this compliance level."
    ),
    "Partially Compliant": (
        "{org_name} has implemented foundational HIPAA security controls but significant "
        "gaps remain that require remediation. The overall compliance score of {score}/100 "
        "indicates that while core controls are in place, several mandatory 2025 requirements "
        "are not fully met. The findings identified in this report represent meaningful "
        "compliance risks that should be addressed through a structured remediation plan. "
        "Prioritize Critical and High severity findings within 90 days."
    ),
    "Significant Gaps": (
        "{org_name} has notable gaps across multiple HIPAA Security Rule safeguard categories. "
        "The overall compliance score of {score}/100 indicates significant areas where mandatory "
        "controls are not implemented or verified. The organization faces substantial exposure "
        "to regulatory enforcement and data breach risk. Immediate remediation of Critical "
        "findings is essential, with a comprehensive compliance improvement plan required "
        "within 60 days."
    ),
    "Non-Compliant": (
        "{org_name} has critical, immediate gaps in fundamental HIPAA Security Rule requirements. "
        "The overall compliance score of {score}/100 indicates that essential safeguards are "
        "missing or severely deficient. The organization is at high risk of regulatory "
        "enforcement action and data breach. Treat HIPAA compliance as a priority operational "
        "matter. Engage a compliance consultant and begin remediation of Critical findings "
        "immediately."
    ),
}

CATEGORY_DESCRIPTIONS = {
    "Technical": (
        "Technical Safeguards (45 CFR § 164.312) encompass the technology and policy "
        "procedures for protecting ePHI. This includes access controls, audit logging, "
        "integrity mechanisms, person/entity authentication (MFA), and transmission "
        "security (encryption in transit). Under the 2025 NPRM, MFA and TLS 1.2+ "
        "are mandatory for all ePHI systems."
    ),
    "Administrative": (
        "Administrative Safeguards (45 CFR § 164.308) establish the policies and procedures "
        "for compliance management. This includes risk analysis, workforce security, security "
        "awareness training, incident response, contingency planning, annual evaluation, "
        "and business associate oversight. These controls form the governance foundation "
        "of the security program."
    ),
    "Physical": (
        "Physical Safeguards (45 CFR § 164.310) address physical measures and policies "
        "for protecting electronic information systems. This includes facility access "
        "controls, workstation use and security policies, and device and media controls. "
        "These controls protect the physical infrastructure housing ePHI."
    ),
    "Cross-Cutting": (
        "Cross-Cutting Requirements represent the new mandatory controls introduced by "
        "the 2025 HIPAA Security Rule NPRM. These include universal MFA, encryption at "
        "rest (AES-256), network segmentation, semi-annual vulnerability scanning, annual "
        "penetration testing, technology asset inventory, 72-hour system restoration, "
        "annual BA verification, 1-hour access termination, and comprehensive documentation."
    ),
}

METHODOLOGY_TEXT = """\
This compliance assessment was conducted using the VerifAI Security HIPAA Compliance Engine, \
which performs automated verification of technical controls against the HIPAA Security Rule \
(45 CFR Part 164) and the 2025 NPRM mandatory requirements.

Assessment Framework:
The engine maps all 31 mandatory controls from the 2025 HIPAA Security Rule to automated \
checks that verify control implementation through direct system inspection, configuration \
analysis, evidence review, and policy verification.

Compliance Freshness Model:
Each control check result has a freshness score that decays over time based on the control's \
verification frequency requirement. The formula is:

    freshness = max(0, 1.0 - (days_since_check / decay_period))

Decay periods: Continuous controls = 30 days, Semi-annual = 180 days, Annual = 365 days.

Overall Score Calculation:
The overall compliance score is a weighted average of category scores:
  - Technical Safeguards: 35%
  - Administrative Safeguards: 30%
  - Cross-Cutting (2025 Mandatory): 25%
  - Physical Safeguards: 10%

Each control's effective score = check_result_score × freshness_multiplier.

Score Bands:
  95-100: Fully Compliant | 80-94: Substantially Compliant | 60-79: Partially Compliant
  40-59: Significant Gaps | 0-39: Non-Compliant
"""

DISCLAIMER_TEXT = """\
This compliance assessment report is provided as a technical evaluation tool and does not \
constitute legal advice. The findings represent a point-in-time evaluation based on available \
evidence and automated checks. Organizations should consult with legal counsel and qualified \
HIPAA compliance professionals for comprehensive compliance guidance. No warranties are made \
regarding the completeness or accuracy of these findings. Regulatory requirements may change; \
this assessment reflects requirements as of the report date.
"""

EFFORT_DESCRIPTIONS = {
    "Quick Win": "Minimal cost and effort. Can typically be completed in days to a few weeks. "
                 "Often involves configuration changes or policy documentation.",
    "Short-term": "Moderate investment required. Typically 30-90 days to implement. "
                  "May require vendor engagement, staff training, or process changes.",
    "Strategic": "Significant investment and planning required. Typically 6-12 months. "
                 "May involve technology deployment, infrastructure changes, or major process redesign.",
}

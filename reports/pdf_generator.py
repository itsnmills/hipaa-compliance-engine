"""Annual Compliance Audit PDF Report Generator.

Generates a professional, VerifAI Security branded compliance report
using ReportLab.
"""

from __future__ import annotations

import math
from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Flowable, KeepTogether,
)

from engine.models import (
    ComplianceReport, ControlStatus, Finding, CheckStatus,
    CategoryScore, get_score_band, ScoreBand,
)
from reports.templates import (
    BRAND_BLUE, BRAND_DARK, BRAND_LIGHT_BG, BRAND_BORDER,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_NEUTRAL,
    BG_CRITICAL, BG_HIGH, BG_MEDIUM, BG_LOW, COLOR_PASS,
    BAND_COLORS, SEVERITY_COLORS, STATUS_COLORS, SEVERITY_BG_COLORS,
    EXECUTIVE_SUMMARY_TEMPLATES, CATEGORY_DESCRIPTIONS,
    METHODOLOGY_TEXT, DISCLAIMER_TEXT,
)

PAGE_WIDTH, PAGE_HEIGHT = letter
MARGIN = 0.75 * inch
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN


def _hex(hex_color: str):
    """Convert hex color string to ReportLab color."""
    return colors.HexColor(hex_color)


# ============================================================
# CUSTOM FLOWABLES
# ============================================================

class ScoreGauge(Flowable):
    """Large circular compliance score gauge for the cover page."""

    def __init__(self, score: float, band: str, size: float = 1.8 * inch):
        super().__init__()
        self.score = score
        self.band = band
        self.size = size
        self.width = size
        self.height = size + 30

    def draw(self):
        c = self.canv
        cx = self.size / 2
        cy = self.size / 2 + 20

        band_color = BAND_COLORS.get(self.band, BRAND_BLUE)

        # Outer ring
        c.setStrokeColor(_hex(BRAND_BLUE))
        c.setLineWidth(4)
        c.setFillColor(_hex(BRAND_BLUE))
        c.circle(cx, cy, self.size / 2, fill=1)

        # Inner circle
        c.setFillColor(_hex(band_color))
        c.circle(cx, cy, self.size / 2 - 8, fill=1)

        # Score text
        c.setFillColor(colors.white)
        c.setFont("Helvetica-Bold", 36)
        c.drawCentredString(cx, cy + 2, f"{self.score:.0f}")

        c.setFont("Helvetica", 12)
        c.drawCentredString(cx, cy - 18, "/ 100")

        # Band label below
        c.setFillColor(_hex(band_color))
        c.setFont("Helvetica-Bold", 10)
        c.drawCentredString(cx, 5, self.band.upper())


class StatusBadge(Flowable):
    """Small status badge (PASS/FAIL/PARTIAL)."""

    def __init__(self, status: str, width: float = 55, height: float = 16):
        super().__init__()
        self.status = status
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        color = STATUS_COLORS.get(self.status, COLOR_NEUTRAL)
        bg = {
            "PASS": BG_LOW, "FAIL": BG_CRITICAL, "PARTIAL": BG_MEDIUM,
        }.get(self.status, BRAND_LIGHT_BG)

        c.setFillColor(_hex(bg))
        c.setStrokeColor(_hex(color))
        c.setLineWidth(0.5)
        c.roundRect(0, 0, self.width, self.height, 4, fill=1, stroke=1)

        c.setFillColor(_hex(color))
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(self.width / 2, 4.5, self.status)


class ScoreBar(Flowable):
    """Horizontal score bar for category breakdown."""

    def __init__(self, label: str, score: float, band: str,
                 bar_width: float = 3.5 * inch, height: float = 22):
        super().__init__()
        self.label = label
        self.score = score
        self.band = band
        self.bar_width = bar_width
        self.width = CONTENT_WIDTH
        self.height = height

    def draw(self):
        c = self.canv
        band_color = BAND_COLORS.get(self.band, BRAND_BLUE)
        label_width = 1.6 * inch
        bar_x = label_width + 10
        score_x = bar_x + self.bar_width + 10

        # Label
        c.setFillColor(_hex(BRAND_DARK))
        font_size = 9 if len(self.label) < 18 else 8
        c.setFont("Helvetica-Bold", font_size)
        c.drawString(0, 6, self.label)

        # Background track
        c.setFillColor(_hex(BRAND_BORDER))
        c.roundRect(bar_x, 2, self.bar_width, 14, 3, fill=1, stroke=0)

        # Filled bar
        fill_width = max(0, (self.score / 100) * self.bar_width)
        if fill_width > 0:
            c.setFillColor(_hex(band_color))
            c.roundRect(bar_x, 2, fill_width, 14, 3, fill=1, stroke=0)

        # Score text
        c.setFillColor(_hex(BRAND_DARK))
        c.setFont("Helvetica-Bold", 9)
        c.drawString(score_x, 6, f"{self.score:.0f}/100")

        c.setFillColor(_hex(band_color))
        c.setFont("Helvetica", 7)
        c.drawString(score_x + 45, 6, f"({self.band})")


# ============================================================
# PDF GENERATOR
# ============================================================

class ComplianceReportPDF:
    """Generate the annual compliance audit PDF report."""

    def __init__(self, report: ComplianceReport):
        self.report = report
        self._styles = self._build_styles()

    def _build_styles(self) -> dict:
        """Build paragraph styles for the report."""
        return {
            "cover_title": ParagraphStyle(
                "cover_title", fontName="Helvetica-Bold", fontSize=24,
                textColor=colors.white, alignment=TA_CENTER, leading=30,
            ),
            "cover_subtitle": ParagraphStyle(
                "cover_subtitle", fontName="Helvetica", fontSize=12,
                textColor=_hex("#CBD5E1"), alignment=TA_CENTER, leading=16,
            ),
            "section_title": ParagraphStyle(
                "section_title", fontName="Helvetica-Bold", fontSize=16,
                textColor=_hex(BRAND_DARK), leading=20, spaceBefore=6,
            ),
            "subsection_title": ParagraphStyle(
                "subsection_title", fontName="Helvetica-Bold", fontSize=11,
                textColor=_hex(BRAND_BLUE), leading=15, spaceBefore=8,
            ),
            "body": ParagraphStyle(
                "body", fontName="Helvetica", fontSize=9,
                textColor=_hex(BRAND_DARK), leading=14,
            ),
            "body_justify": ParagraphStyle(
                "body_justify", fontName="Helvetica", fontSize=9,
                textColor=_hex(BRAND_DARK), leading=14, alignment=TA_JUSTIFY,
            ),
            "caption": ParagraphStyle(
                "caption", fontName="Helvetica", fontSize=8,
                textColor=_hex(COLOR_NEUTRAL), leading=11,
            ),
            "table_header": ParagraphStyle(
                "table_header", fontName="Helvetica-Bold", fontSize=8,
                textColor=colors.white, leading=11,
            ),
            "table_cell": ParagraphStyle(
                "table_cell", fontName="Helvetica", fontSize=8,
                textColor=_hex(BRAND_DARK), leading=11,
            ),
            "table_cell_bold": ParagraphStyle(
                "table_cell_bold", fontName="Helvetica-Bold", fontSize=8,
                textColor=_hex(BRAND_DARK), leading=11,
            ),
            "finding_title": ParagraphStyle(
                "finding_title", fontName="Helvetica-Bold", fontSize=9,
                textColor=_hex(BRAND_DARK), leading=12,
            ),
            "finding_desc": ParagraphStyle(
                "finding_desc", fontName="Helvetica", fontSize=8,
                textColor=_hex(BRAND_DARK), leading=11,
            ),
            "finding_rec": ParagraphStyle(
                "finding_rec", fontName="Helvetica", fontSize=8,
                textColor=_hex(COLOR_NEUTRAL), leading=11,
            ),
            "disclaimer": ParagraphStyle(
                "disclaimer", fontName="Helvetica", fontSize=7.5,
                textColor=_hex(COLOR_NEUTRAL), leading=10, alignment=TA_JUSTIFY,
            ),
        }

    def generate(self, output_path: str) -> str:
        """Generate the PDF report.

        Args:
            output_path: Path to write the PDF file.

        Returns:
            The output file path.
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=MARGIN,
            bottomMargin=0.85 * inch,
        )

        story = []
        story.extend(self._build_cover_page())
        story.append(PageBreak())
        story.extend(self._build_executive_summary())
        story.append(PageBreak())
        story.extend(self._build_score_dashboard())
        story.append(PageBreak())
        story.extend(self._build_detailed_findings())
        story.append(PageBreak())
        story.extend(self._build_control_matrix())
        story.append(PageBreak())
        story.extend(self._build_ba_section())
        story.append(PageBreak())
        story.extend(self._build_risk_register())
        story.append(PageBreak())
        story.extend(self._build_methodology())

        doc.build(story, canvasmaker=_PageNumberCanvas)

        return output_path

    # ----------------------------------------------------------
    # COVER PAGE
    # ----------------------------------------------------------

    def _build_cover_page(self) -> list:
        """Build the cover page."""
        elements = []

        # Header band
        header_data = [[
            Paragraph("HIPAA SECURITY RULE<br/>ANNUAL COMPLIANCE AUDIT REPORT",
                      self._styles["cover_title"])
        ]]
        header_table = Table(header_data, colWidths=[CONTENT_WIDTH])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _hex(BRAND_BLUE)),
            ("TOPPADDING", (0, 0), (-1, -1), 30),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 30),
            ("LEFTPADDING", (0, 0), (-1, -1), 20),
            ("RIGHTPADDING", (0, 0), (-1, -1), 20),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(header_table)
        elements.append(Spacer(1, 25))

        # Compliance Score Gauge (centered)
        gauge = ScoreGauge(self.report.overall_score, self.report.overall_band)
        gauge_table = Table([[gauge]], colWidths=[CONTENT_WIDTH])
        gauge_table.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(gauge_table)
        elements.append(Spacer(1, 20))

        # Info box
        r = self.report
        info_items = [
            ("Organization", r.organization_name),
            ("Practice Type", r.organization_type.replace("_", " ").title()),
            ("Report Date", r.report_date),
            ("Controls Assessed", str(len(r.control_statuses))),
            ("Findings", str(len(r.findings))),
        ]

        info_data = []
        for label, value in info_items:
            info_data.append([
                Paragraph(f"<b>{label}:</b>", self._styles["body"]),
                Paragraph(value, self._styles["body"]),
            ])

        info_table = Table(info_data, colWidths=[1.8 * inch, 4.2 * inch])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _hex(BRAND_LIGHT_BG)),
            ("BOX", (0, 0), (-1, -1), 0.5, _hex(BRAND_BORDER)),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 20))

        # Finding counts by severity
        counts = [
            ("Critical", len(r.critical_findings), COLOR_CRITICAL, BG_CRITICAL),
            ("High", len(r.high_findings), COLOR_HIGH, BG_HIGH),
            ("Medium", len(r.medium_findings), COLOR_MEDIUM, BG_MEDIUM),
            ("Low", len(r.low_findings), COLOR_LOW, BG_LOW),
        ]

        count_cells = []
        for label, count, color, bg in counts:
            count_cells.append(
                Paragraph(
                    f'<font color="{color}" size="16"><b>{count}</b></font><br/>'
                    f'<font color="{color}" size="8">{label}</font>',
                    ParagraphStyle("cnt", alignment=TA_CENTER, leading=18),
                )
            )

        count_table = Table([count_cells], colWidths=[CONTENT_WIDTH / 4] * 4)
        count_table.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (0, 0), _hex(BG_CRITICAL)),
            ("BACKGROUND", (1, 0), (1, 0), _hex(BG_HIGH)),
            ("BACKGROUND", (2, 0), (2, 0), _hex(BG_MEDIUM)),
            ("BACKGROUND", (3, 0), (3, 0), _hex(BG_LOW)),
            ("BOX", (0, 0), (-1, -1), 0.5, _hex(BRAND_BORDER)),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, _hex(BRAND_BORDER)),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(count_table)
        elements.append(Spacer(1, 40))

        # Footer
        elements.append(Paragraph(
            '<font color="#64748B" size="9">Prepared by </font>'
            f'<font color="{BRAND_BLUE}" size="9"><b>VerifAI Security</b></font>'
            '<font color="#64748B" size="9"> — HIPAA Compliance Engine v1.0</font>',
            ParagraphStyle("footer", alignment=TA_CENTER),
        ))

        return elements

    # ----------------------------------------------------------
    # EXECUTIVE SUMMARY
    # ----------------------------------------------------------

    def _build_executive_summary(self) -> list:
        elements = []

        elements.append(Paragraph("Executive Summary", self._styles["section_title"]))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=_hex(BRAND_BLUE),
            spaceBefore=2, spaceAfter=10,
        ))

        # Summary text
        template = EXECUTIVE_SUMMARY_TEMPLATES.get(
            self.report.overall_band,
            EXECUTIVE_SUMMARY_TEMPLATES["Partially Compliant"],
        )
        summary_text = template.format(
            org_name=self.report.organization_name,
            score=f"{self.report.overall_score:.0f}",
        )
        elements.append(Paragraph(summary_text, self._styles["body_justify"]))
        elements.append(Spacer(1, 15))

        # Category scores
        elements.append(Paragraph("Category Compliance Scores", self._styles["subsection_title"]))
        elements.append(Spacer(1, 8))

        for cs in self.report.category_scores:
            elements.append(ScoreBar(
                label=f"{cs.category} ({cs.weight:.0%})",
                score=cs.score,
                band=cs.band,
            ))
            elements.append(Spacer(1, 6))

        elements.append(Spacer(1, 10))

        # Key findings summary
        critical_high = self.report.critical_findings + self.report.high_findings
        if critical_high:
            elements.append(Paragraph("Top Priority Findings", self._styles["subsection_title"]))
            elements.append(Spacer(1, 6))

            for finding in critical_high[:5]:
                severity_color = SEVERITY_COLORS.get(finding.severity, COLOR_NEUTRAL)
                severity_bg = SEVERITY_BG_COLORS.get(finding.severity, BRAND_LIGHT_BG)

                card_data = [[
                    Paragraph(
                        f'<font color="{severity_color}"><b>[{finding.severity.upper()}]</b></font> '
                        f'<b>{finding.title}</b><br/>'
                        f'<font color="{COLOR_NEUTRAL}" size="7">{finding.cfr_reference} — '
                        f'{finding.control_id}</font>',
                        self._styles["finding_desc"],
                    ),
                ]]
                card = Table(card_data, colWidths=[CONTENT_WIDTH - 10])
                card.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), _hex(severity_bg)),
                    ("BOX", (0, 0), (-1, -1), 0.5, _hex(severity_color)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]))
                elements.append(card)
                elements.append(Spacer(1, 4))

        # Strengths
        passing = self.report.passing_controls
        if passing:
            elements.append(Spacer(1, 8))
            elements.append(Paragraph("Areas of Strength", self._styles["subsection_title"]))
            elements.append(Spacer(1, 4))
            for cs in passing[:5]:
                elements.append(Paragraph(
                    f'<font color="{COLOR_PASS}">&#10003;</font> '
                    f'{cs.control.title} ({cs.control.cfr_reference})',
                    self._styles["body"],
                ))
            if len(passing) > 5:
                elements.append(Paragraph(
                    f'<font color="{COLOR_NEUTRAL}">...and {len(passing) - 5} more controls passing</font>',
                    self._styles["caption"],
                ))

        return elements

    # ----------------------------------------------------------
    # SCORE DASHBOARD
    # ----------------------------------------------------------

    def _build_score_dashboard(self) -> list:
        elements = []

        elements.append(Paragraph("Compliance Score Dashboard", self._styles["section_title"]))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=_hex(BRAND_BLUE),
            spaceBefore=2, spaceAfter=10,
        ))

        # Overall score summary
        band_color = BAND_COLORS.get(self.report.overall_band, BRAND_BLUE)
        elements.append(Paragraph(
            f'Overall Compliance Score: <font color="{band_color}"><b>'
            f'{self.report.overall_score:.1f}/100</b></font> — '
            f'<font color="{band_color}"><b>{self.report.overall_band}</b></font>',
            self._styles["body"],
        ))
        elements.append(Spacer(1, 12))

        # Per-category detail
        for cs in self.report.category_scores:
            desc = CATEGORY_DESCRIPTIONS.get(cs.category, "")
            band_color = BAND_COLORS.get(cs.band, BRAND_BLUE)

            elements.append(Paragraph(
                f'{cs.category} Safeguards '
                f'<font color="{band_color}">({cs.score:.0f}/100)</font>',
                self._styles["subsection_title"],
            ))
            elements.append(ScoreBar(
                label=f"Weight: {cs.weight:.0%}",
                score=cs.score,
                band=cs.band,
            ))
            elements.append(Spacer(1, 4))
            elements.append(Paragraph(desc, self._styles["caption"]))
            elements.append(Paragraph(
                f'Controls: {cs.controls_total} total | '
                f'<font color="{COLOR_PASS}">{cs.controls_passing} passing</font> | '
                f'<font color="{COLOR_CRITICAL}">{cs.controls_failing} failing</font> | '
                f'<font color="{COLOR_MEDIUM}">{cs.controls_partial} partial</font>',
                self._styles["caption"],
            ))
            elements.append(Spacer(1, 10))

        # Freshness overview
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("Freshness Status", self._styles["subsection_title"]))
        elements.append(Spacer(1, 4))

        stale = self.report.stale_controls
        approaching = self.report.approaching_stale
        fresh_count = len(self.report.control_statuses) - len(stale) - len(approaching)

        elements.append(Paragraph(
            f'<font color="{COLOR_PASS}">&#9679;</font> '
            f'{fresh_count} controls with fresh results &nbsp;&nbsp;'
            f'<font color="{COLOR_MEDIUM}">&#9679;</font> '
            f'{len(approaching)} approaching staleness &nbsp;&nbsp;'
            f'<font color="{COLOR_CRITICAL}">&#9679;</font> '
            f'{len(stale)} stale',
            self._styles["body"],
        ))

        return elements

    # ----------------------------------------------------------
    # DETAILED FINDINGS
    # ----------------------------------------------------------

    def _build_detailed_findings(self) -> list:
        elements = []

        elements.append(Paragraph("Detailed Findings", self._styles["section_title"]))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=_hex(BRAND_BLUE),
            spaceBefore=2, spaceAfter=10,
        ))

        categories = sorted(set(cs.control.category for cs in self.report.control_statuses))

        for category in categories:
            cat_statuses = [
                cs for cs in self.report.control_statuses
                if cs.control.category == category
            ]
            cat_score = next(
                (s for s in self.report.category_scores if s.category == category),
                None,
            )

            band_color = BAND_COLORS.get(cat_score.band, BRAND_BLUE) if cat_score else BRAND_BLUE

            elements.append(Paragraph(
                f'{category} Safeguards',
                self._styles["subsection_title"],
            ))
            elements.append(HRFlowable(
                width="100%", thickness=1, color=_hex(band_color),
                spaceBefore=2, spaceAfter=8,
            ))

            for cs in cat_statuses:
                elements.extend(self._build_control_card(cs))
                elements.append(Spacer(1, 6))

            elements.append(Spacer(1, 10))

        return elements

    def _build_control_card(self, cs: ControlStatus) -> list:
        """Build a card for a single control with its findings."""
        elements = []

        status = cs.last_check.status if cs.last_check else "NOT_CHECKED"
        status_color = STATUS_COLORS.get(status, COLOR_NEUTRAL)
        score = cs.last_check.score if cs.last_check else 0.0
        severity_color = SEVERITY_COLORS.get(cs.control.severity, COLOR_NEUTRAL)

        # Header row: ID, Title, Status, Score
        header = Paragraph(
            f'<font color="{severity_color}"><b>{cs.control.id}</b></font> — '
            f'<b>{cs.control.title}</b> &nbsp;'
            f'<font color="{status_color}" size="8"><b>[{status}]</b></font> &nbsp;'
            f'<font color="{COLOR_NEUTRAL}" size="7">Score: {score:.0%} | '
            f'Freshness: {cs.freshness:.0%} | '
            f'{cs.control.cfr_reference}</font>',
            self._styles["finding_desc"],
        )
        elements.append(header)

        # Findings for this control
        if cs.last_check and cs.last_check.findings:
            for finding in cs.last_check.findings:
                f_color = SEVERITY_COLORS.get(finding.severity, COLOR_NEUTRAL)
                f_bg = SEVERITY_BG_COLORS.get(finding.severity, BRAND_LIGHT_BG)

                card_data = [[
                    Paragraph(
                        f'<font color="{f_color}"><b>{finding.severity}:</b></font> '
                        f'{finding.title}<br/>'
                        f'<font color="{COLOR_NEUTRAL}" size="7">{finding.description}</font><br/>'
                        f'<font color="{BRAND_BLUE}" size="7"><b>Remediation:</b> '
                        f'{finding.remediation}</font>',
                        self._styles["finding_desc"],
                    ),
                ]]
                card = Table(card_data, colWidths=[CONTENT_WIDTH - 20])
                card.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), _hex(f_bg)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                elements.append(Spacer(1, 2))
                elements.append(card)

        return elements

    # ----------------------------------------------------------
    # CONTROL COVERAGE MATRIX
    # ----------------------------------------------------------

    def _build_control_matrix(self) -> list:
        elements = []

        elements.append(Paragraph("Control Coverage Matrix", self._styles["section_title"]))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=_hex(BRAND_BLUE),
            spaceBefore=2, spaceAfter=10,
        ))

        elements.append(Paragraph(
            "Complete matrix of all 31 mandatory HIPAA Security Rule controls with "
            "verification status.",
            self._styles["body"],
        ))
        elements.append(Spacer(1, 8))

        # Table header
        header = [
            Paragraph("ID", self._styles["table_header"]),
            Paragraph("Control Title", self._styles["table_header"]),
            Paragraph("Category", self._styles["table_header"]),
            Paragraph("Severity", self._styles["table_header"]),
            Paragraph("Status", self._styles["table_header"]),
            Paragraph("Score", self._styles["table_header"]),
        ]

        data = [header]
        for cs in self.report.control_statuses:
            status = cs.last_check.status if cs.last_check else "NOT_CHECKED"
            score = cs.last_check.score if cs.last_check else 0.0
            status_color = STATUS_COLORS.get(status, COLOR_NEUTRAL)
            severity_color = SEVERITY_COLORS.get(cs.control.severity, COLOR_NEUTRAL)

            data.append([
                Paragraph(cs.control.id, self._styles["table_cell_bold"]),
                Paragraph(cs.control.title, self._styles["table_cell"]),
                Paragraph(cs.control.category, self._styles["table_cell"]),
                Paragraph(
                    f'<font color="{severity_color}">{cs.control.severity}</font>',
                    self._styles["table_cell"],
                ),
                Paragraph(
                    f'<font color="{status_color}"><b>{status}</b></font>',
                    self._styles["table_cell"],
                ),
                Paragraph(f"{score:.0%}", self._styles["table_cell"]),
            ])

        col_widths = [0.8 * inch, 2.2 * inch, 0.9 * inch, 0.7 * inch, 0.7 * inch, 0.6 * inch]
        table = Table(data, colWidths=col_widths, repeatRows=1)

        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), _hex(BRAND_BLUE)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, _hex(BRAND_BORDER)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        # Alternating row colors
        for i in range(1, len(data)):
            if i % 2 == 0:
                style_commands.append(
                    ("BACKGROUND", (0, i), (-1, i), _hex(BRAND_LIGHT_BG))
                )

        table.setStyle(TableStyle(style_commands))
        elements.append(table)

        return elements

    # ----------------------------------------------------------
    # BUSINESS ASSOCIATE SECTION
    # ----------------------------------------------------------

    def _build_ba_section(self) -> list:
        elements = []

        elements.append(Paragraph("Business Associate Compliance", self._styles["section_title"]))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=_hex(BRAND_BLUE),
            spaceBefore=2, spaceAfter=10,
        ))

        # Find BA-related control statuses
        ba_controls = [
            cs for cs in self.report.control_statuses
            if cs.control.check_module == "ba_management"
        ]

        if not ba_controls:
            elements.append(Paragraph(
                "No business associate controls found in this assessment.",
                self._styles["body"],
            ))
            return elements

        elements.append(Paragraph(
            "The 2025 HIPAA Security Rule introduces stricter requirements for business "
            "associate oversight, including 24-hour contingency notification and annual "
            "written verification of technical safeguards.",
            self._styles["body_justify"],
        ))
        elements.append(Spacer(1, 8))

        for cs in ba_controls:
            status = cs.last_check.status if cs.last_check else "NOT_CHECKED"
            status_color = STATUS_COLORS.get(status, COLOR_NEUTRAL)

            elements.append(Paragraph(
                f'<font color="{status_color}"><b>[{status}]</b></font> '
                f'<b>{cs.control.title}</b> ({cs.control.id})',
                self._styles["body"],
            ))

            if cs.last_check and cs.last_check.evidence:
                evidence = cs.last_check.evidence
                for key, value in evidence.items():
                    elements.append(Paragraph(
                        f'&nbsp;&nbsp;&nbsp;&nbsp;<font color="{COLOR_NEUTRAL}">'
                        f'{key.replace("_", " ").title()}: {value}</font>',
                        self._styles["caption"],
                    ))

            if cs.last_check and cs.last_check.findings:
                for finding in cs.last_check.findings:
                    f_color = SEVERITY_COLORS.get(finding.severity, COLOR_NEUTRAL)
                    elements.append(Paragraph(
                        f'&nbsp;&nbsp;&nbsp;&nbsp;<font color="{f_color}">&#9679; '
                        f'{finding.title}</font>',
                        self._styles["finding_desc"],
                    ))

            elements.append(Spacer(1, 6))

        return elements

    # ----------------------------------------------------------
    # RISK REGISTER
    # ----------------------------------------------------------

    def _build_risk_register(self) -> list:
        elements = []

        elements.append(Paragraph("Risk Register", self._styles["section_title"]))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=_hex(BRAND_BLUE),
            spaceBefore=2, spaceAfter=10,
        ))

        elements.append(Paragraph(
            "All open findings sorted by severity. Each finding includes the associated "
            "control, CFR reference, and recommended remediation effort level.",
            self._styles["body"],
        ))
        elements.append(Spacer(1, 8))

        if not self.report.findings:
            elements.append(Paragraph(
                '<font color="' + COLOR_PASS + '">No open findings — all controls passing.</font>',
                self._styles["body"],
            ))
            return elements

        header = [
            Paragraph("Control", self._styles["table_header"]),
            Paragraph("CFR Ref", self._styles["table_header"]),
            Paragraph("Finding", self._styles["table_header"]),
            Paragraph("Severity", self._styles["table_header"]),
            Paragraph("Effort", self._styles["table_header"]),
        ]

        data = [header]
        for finding in self.report.findings:
            severity_color = SEVERITY_COLORS.get(finding.severity, COLOR_NEUTRAL)
            data.append([
                Paragraph(finding.control_id, self._styles["table_cell_bold"]),
                Paragraph(finding.cfr_reference, self._styles["table_cell"]),
                Paragraph(finding.title, self._styles["table_cell"]),
                Paragraph(
                    f'<font color="{severity_color}"><b>{finding.severity}</b></font>',
                    self._styles["table_cell"],
                ),
                Paragraph(finding.estimated_effort, self._styles["table_cell"]),
            ])

        col_widths = [0.9 * inch, 1.1 * inch, 2.5 * inch, 0.7 * inch, 0.7 * inch]
        table = Table(data, colWidths=col_widths, repeatRows=1)

        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), _hex(BRAND_BLUE)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, _hex(BRAND_BORDER)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i in range(1, len(data)):
            if i % 2 == 0:
                style_commands.append(
                    ("BACKGROUND", (0, i), (-1, i), _hex(BRAND_LIGHT_BG))
                )
        table.setStyle(TableStyle(style_commands))
        elements.append(table)

        return elements

    # ----------------------------------------------------------
    # METHODOLOGY & DISCLAIMER
    # ----------------------------------------------------------

    def _build_methodology(self) -> list:
        elements = []

        elements.append(Paragraph("Methodology & Disclaimer", self._styles["section_title"]))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=_hex(BRAND_BLUE),
            spaceBefore=2, spaceAfter=10,
        ))

        elements.append(Paragraph("Assessment Methodology", self._styles["subsection_title"]))
        elements.append(Spacer(1, 4))

        for para in METHODOLOGY_TEXT.strip().split("\n\n"):
            elements.append(Paragraph(para.strip(), self._styles["body_justify"]))
            elements.append(Spacer(1, 6))

        elements.append(Spacer(1, 10))
        elements.append(Paragraph("Disclaimer", self._styles["subsection_title"]))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph(DISCLAIMER_TEXT.strip(), self._styles["disclaimer"]))

        return elements


# ============================================================
# PAGE NUMBER CANVAS
# ============================================================

class _PageNumberCanvas:
    """Custom canvas that adds page numbers and footer to every page."""

    def __init__(self, *args, **kwargs):
        from reportlab.pdfgen.canvas import Canvas
        self._canvas_class = Canvas
        self._canvas = Canvas(*args, **kwargs)
        self._pages = []

    def __getattr__(self, name):
        return getattr(self._canvas, name)

    def showPage(self):
        self._pages.append(dict(self._canvas.__dict__))
        self._canvas.showPage()

    def save(self):
        num_pages = len(self._pages)
        for i, page in enumerate(self._pages):
            self._canvas.__dict__.update(page)
            self._draw_footer(i + 1, num_pages)
            self._canvas_class.showPage(self._canvas)
        self._canvas_class.save(self._canvas)

    def _draw_footer(self, page_num: int, total_pages: int):
        c = self._canvas
        y = 0.5 * inch

        # Line above footer
        c.setStrokeColor(_hex(BRAND_BORDER))
        c.setLineWidth(0.5)
        c.line(MARGIN, y + 10, PAGE_WIDTH - MARGIN, y + 10)

        c.setFont("Helvetica", 7)
        c.setFillColor(_hex(COLOR_NEUTRAL))

        # Left: branding
        c.drawString(MARGIN, y, "VerifAI Security — HIPAA Compliance Engine")

        # Center: page number
        c.drawCentredString(PAGE_WIDTH / 2, y, f"Page {page_num} of {total_pages}")

        # Right: confidential
        c.drawRightString(PAGE_WIDTH - MARGIN, y, "CONFIDENTIAL")


def generate_pdf(report: ComplianceReport, output_path: str) -> str:
    """Convenience function to generate a PDF report.

    Args:
        report: ComplianceReport data.
        output_path: Output file path.

    Returns:
        The output file path.
    """
    generator = ComplianceReportPDF(report)
    return generator.generate(output_path)

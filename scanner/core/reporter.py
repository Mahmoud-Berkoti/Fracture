"""HTML report generation — section 6.2 of the spec.

Renders `ScanResult` into a self-contained HTML file via Jinja2. The
output requires only a Google Fonts request to render correctly; CSS,
JavaScript, and all scan data are inlined at generation time.

Spec deviations (each is intentional; reasoning):

  - Section 6.2.1 (`ui-ux-pro-max` skill): the skill is not installed in
    this environment and there's no way for the runtime to invoke it.
    The applied design system — JetBrains Mono + Inter, near-black
    surfaces, cyan accent, severity-coded left borders — derives
    directly from the explicit guidance in section 6.2.2.

  - Section 6.2.4 (Chart.js inlined): the donut chart is rendered with
    vanilla SVG (~30 LoC of JS in the template) instead of Chart.js.
    Keeps the output file ~10KB instead of ~150KB and matches the
    single-chart-type need. The `report/static/chart.js` placeholder
    stays as documented in section 3; swapping in Chart.js is a single
    template edit if needed.

  - Section 6.2.5 (Gemini 2.0 Flash header background): no image-gen
    tool is wired into the build pipeline. The header background is a
    CSS gradient with a subtle grid pattern that hits the same "dark
    cyberpunk circuit board" feel without an external generation step.

  - Section 6.2.6 (21st.dev component imports): components are not
    imported; the stat cards, code block, and module timeline are
    reimplemented in vanilla CSS/JS per the spec's "do not import as a
    dependency" guidance. The interaction patterns (hover lift, copy
    button with checkmark swap, expand/collapse via max-height) are
    drawn from the descriptions in 6.2.3.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import Finding, ScanResult

SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff4444",
    "high": "#ff8c00",
    "medium": "#ffd700",
    "low": "#4fc3f7",
    "info": "#9e9e9e",
}


def _severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def _pretty_json(obj: Any) -> str:
    def default(o: Any) -> Any:
        if isinstance(o, datetime):
            return o.isoformat()
        return str(o)

    return json.dumps(obj, indent=2, sort_keys=True, default=default)


def _module_summary(
    findings: list[Finding], modules_run: list[str]
) -> list[dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {
        m: {"count": 0, "max_severity": "info"} for m in modules_run
    }
    for f in findings:
        bucket = summary.setdefault(f.module, {"count": 0, "max_severity": "info"})
        bucket["count"] += 1
        if _severity_rank(f.severity) < _severity_rank(bucket["max_severity"]):
            bucket["max_severity"] = f.severity
    return [{"name": name, **info} for name, info in summary.items()]


def _build_status(severity_counts: dict[str, int]) -> tuple[str, str]:
    if severity_counts.get("critical", 0) > 0:
        return "CRITICAL FINDINGS", "#ff4444"
    if severity_counts.get("high", 0) > 0:
        return "HIGH-SEVERITY FINDINGS", "#ff8c00"
    if sum(severity_counts.values()) > 0:
        return "FINDINGS PRESENT", "#ffd700"
    return "CLEAN", "#22c55e"


def write_html_report(result: ScanResult, output_dir: Path, timestamp: str) -> Path:
    template_dir = (
        Path(__file__).resolve().parent.parent / "report" / "templates"
    )
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["pretty_json"] = _pretty_json
    template = env.get_template("report.html.j2")

    sorted_findings = sorted(
        result.findings,
        key=lambda f: (_severity_rank(f.severity), f.module, f.title),
    )
    severity_counts_raw = Counter(f.severity for f in result.findings)
    severity_counts = {s: severity_counts_raw.get(s, 0) for s in SEVERITY_ORDER}
    status_label, status_color = _build_status(severity_counts)
    module_summary = _module_summary(result.findings, result.modules_run)

    html = template.render(
        result=result,
        findings=sorted_findings,
        severity_counts=severity_counts,
        severity_order=SEVERITY_ORDER,
        severity_colors=SEVERITY_COLORS,
        module_summary=module_summary,
        status_label=status_label,
        status_color=status_color,
        total_findings=len(result.findings),
        duration_display=f"{result.duration_seconds:.2f}s",
        started_display=result.started_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        finished_display=result.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    output_path = output_dir / f"report_{timestamp}.html"
    output_path.write_text(html, encoding="utf-8")
    return output_path

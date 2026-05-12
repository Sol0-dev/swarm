"""
ReportWriter - Generates professional bug bounty reports.
Formats: HackerOne, Bugcrowd, Intigriti, Immunefi, generic HTML.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from rich.console import Console

console = Console()

REPORTS_DIR = Path.home() / ".swarmbounty" / "reports"


class ReportWriter:
    def __init__(self, swarm):
        self.swarm = swarm
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def generate(self, session: Dict, platform: str = "hackerone") -> str:
        """Generate a full report for all report-worthy findings."""
        target = session["target"]
        findings = [f for f in session.get("findings", []) if f.get("report_worthy", False)]

        if not findings:
            # Generate for all validated findings
            findings = [f for f in session.get("findings", []) if f.get("validated")]
        if not findings:
            findings = session.get("findings", [])

        if not findings:
            console.print("[yellow]No findings to report.[/yellow]")
            return ""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = REPORTS_DIR / f"{session['id']}_{timestamp}"
        report_dir.mkdir(exist_ok=True)

        generated_paths = []

        for finding in findings:
            console.print(f"  [dim]Writing report for {finding.get('id', '?')}...[/dim]")
            report_text = self.swarm.write_report(finding, target, platform)
            finding_id = finding.get("id", "FIND-001").replace(" ", "_")
            vuln = finding.get("vuln_class", "vuln").replace(" ", "_").lower()
            report_path = report_dir / f"{finding_id}_{vuln}.md"
            with open(report_path, "w") as f:
                f.write(f"# Bug Report - {finding.get('vuln_class', 'Unknown')}\n")
                f.write(f"**Target:** {target}\n")
                f.write(f"**Session:** {session['id']}\n")
                f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
                f.write("---\n\n")
                f.write(report_text)
            generated_paths.append(str(report_path))

        # Generate summary report
        summary_path = report_dir / "SUMMARY.md"
        summary = self._generate_summary(session, findings, generated_paths)
        with open(summary_path, "w") as f:
            f.write(summary)

        # Generate HTML report (Burp-style)
        html_path = report_dir / "report.html"
        html = self._generate_html(session, findings)
        with open(html_path, "w") as f:
            f.write(html)

        console.print(f"[green]✓ Reports saved to: {report_dir}[/green]")
        console.print(f"  Summary: {summary_path}")
        console.print(f"  HTML:    {html_path}")
        for p in generated_paths:
            console.print(f"  Finding: {p}")

        return str(report_dir)

    def _generate_summary(self, session: Dict, findings: List[Dict],
                          report_paths: List[str]) -> str:
        """Generate a summary markdown file."""
        chains = session.get("chains", [])
        total_cvss = sum(f.get("cvss", 0) or 0 for f in findings)
        avg_cvss = total_cvss / len(findings) if findings else 0

        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "Unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        lines = [
            f"# Bug Bounty Hunt Summary",
            f"",
            f"**Target:** {session['target']}",
            f"**Session:** {session['id']}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
            f"**Total Findings:** {len(findings)}",
            f"**Average CVSS:** {avg_cvss:.1f}",
            f"",
            f"## Severity Breakdown",
            f"",
        ]
        for sev, count in sev_counts.items():
            lines.append(f"- **{sev}:** {count}")

        lines += [
            f"",
            f"## Findings",
            f"",
        ]
        for f in findings:
            lines.append(
                f"### {f.get('id', '?')} - {f.get('vuln_class', 'Unknown')}"
            )
            lines.append(f"- **Severity:** {f.get('severity', 'Unknown')}")
            lines.append(f"- **CVSS:** {f.get('cvss', 'N/A')}")
            lines.append(f"- **Endpoint:** {f.get('endpoint', 'N/A')}")
            lines.append(f"- **Description:** {f.get('description', 'N/A')}")
            lines.append(f"")

        if chains:
            lines += [f"## Exploit Chains", f""]
            for chain in chains:
                lines.append(f"### {chain.get('chain_name', 'Chain')}")
                lines.append(f"- **Combined Severity:** {chain.get('combined_severity', 'N/A')}")
                lines.append(f"- **Payout Multiplier:** {chain.get('payout_multiplier', 'N/A')}")
                lines.append(f"- **Narrative:** {chain.get('narrative', '')}")
                lines.append(f"")

        return "\n".join(lines)

    def _generate_html(self, session: Dict, findings: List[Dict]) -> str:
        """Generate a Burp-style HTML report."""
        sev_colors = {
            "Critical": "#8B0000",
            "High": "#CC0000",
            "Medium": "#FF6600",
            "Low": "#CC9900",
            "Informational": "#336699"
        }

        findings_html = ""
        for f in findings:
            sev = f.get("severity", "Unknown")
            color = sev_colors.get(sev, "#666")
            vuln_details = json.dumps(f.get("validation", {}), indent=2)

            findings_html += f"""
<div class="finding">
  <div class="finding-header" style="border-left: 4px solid {color}">
    <span class="finding-id">{f.get('id','?')}</span>
    <span class="finding-title">{f.get('vuln_class','Unknown').upper()}</span>
    <span class="severity-badge" style="background:{color}">{sev}</span>
    <span class="cvss">CVSS: {f.get('cvss','N/A')}</span>
  </div>
  <div class="finding-body">
    <p><strong>Endpoint:</strong> <code>{f.get('endpoint','N/A')}</code></p>
    <p><strong>Description:</strong> {f.get('description','N/A')}</p>
    <pre class="json-details">{vuln_details}</pre>
  </div>
</div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SwarmBounty Report - {session['target']}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Courier New', monospace; background: #0d0d0d; color: #e0e0e0; margin: 0; padding: 20px; }}
  .header {{ background: #1a1a2e; padding: 20px; border: 1px solid #16213e; margin-bottom: 20px; }}
  .header h1 {{ color: #00d4ff; margin: 0 0 10px 0; font-size: 24px; }}
  .header .meta {{ color: #888; font-size: 12px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }}
  .stat {{ background: #1a1a2e; padding: 15px; text-align: center; border: 1px solid #16213e; }}
  .stat .num {{ font-size: 28px; font-weight: bold; color: #00d4ff; }}
  .stat .label {{ font-size: 11px; color: #888; }}
  .finding {{ background: #111; border: 1px solid #222; margin-bottom: 15px; }}
  .finding-header {{ padding: 12px 15px; display: flex; align-items: center; gap: 15px; background: #161616; }}
  .finding-id {{ color: #888; font-size: 12px; min-width: 80px; }}
  .finding-title {{ font-weight: bold; color: #fff; flex: 1; }}
  .severity-badge {{ padding: 3px 10px; border-radius: 3px; font-size: 11px; color: #fff; font-weight: bold; }}
  .cvss {{ color: #888; font-size: 12px; }}
  .finding-body {{ padding: 15px; }}
  .finding-body p {{ margin: 5px 0; }}
  code {{ background: #222; padding: 2px 6px; border-radius: 3px; color: #00ff88; }}
  pre.json-details {{ background: #0a0a0a; padding: 10px; overflow-x: auto; font-size: 11px; color: #888; border: 1px solid #222; }}
  .section-title {{ color: #00d4ff; font-size: 18px; margin: 25px 0 10px; border-bottom: 1px solid #16213e; padding-bottom: 5px; }}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ SwarmBounty Security Report</h1>
  <div class="meta">
    Target: {session['target']} | Session: {session['id']} | Generated: {datetime.now().isoformat()}
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="num">{len(findings)}</div><div class="label">FINDINGS</div></div>
  <div class="stat"><div class="num">{len([f for f in findings if f.get('severity') in ('Critical','High')])}</div><div class="label">CRITICAL/HIGH</div></div>
  <div class="stat"><div class="num">{len(session.get('chains',[]))}</div><div class="label">CHAINS</div></div>
  <div class="stat"><div class="num">{len([f for f in findings if f.get('report_worthy')])}</div><div class="label">REPORT-READY</div></div>
</div>

<div class="section-title">FINDINGS</div>
{findings_html}

<div style="color:#333; font-size:11px; margin-top:30px; text-align:center;">
  Generated by SwarmBounty | Based on shuvonsec/claude-bug-bounty methodology
  <br>⚠ For authorized security testing only
</div>
</body>
</html>"""

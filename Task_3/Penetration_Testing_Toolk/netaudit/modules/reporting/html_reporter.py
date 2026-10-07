import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from ..base import BaseModule
from ...core.graph import AssetGraph
from ...core.models import RiskLevel


class HTMLReportGenerator(BaseModule):
    """
    Generates a high-grade executive HTML security dashboard report
    with metrics, visual vulnerability cards, evidence logs, and actionable remediations.
    """

    name = "html_report_generator"
    description = "Generates a styled, interactive HTML dashboard presenting asset inventory and vulnerability metrics."
    category = "reporting"

    def __init__(self, output_path: str = "audit_report.html", options: Dict[str, Any] = None):
        super().__init__(options)
        self.output_path = output_path

    def run(self, graph: AssetGraph) -> None:
        data = graph.to_dict()
        risk_score = data["risk_score"]
        findings = graph.get_all_findings()

        # Count findings by severity
        sev_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        for f in findings:
            sev = f.get("severity", "INFO")
            if sev in sev_counts:
                sev_counts[sev] += 1

        total_open_ports = sum(len(h.services) for h in graph.hosts.values())
        targets_str = ", ".join(f"`{net}`" for net in graph.scope_guard.networks)

        # Risk badge color determination
        if risk_score >= 70:
            risk_badge_cls = "risk-critical"
            risk_label = "HIGH RISK"
        elif risk_score >= 40:
            risk_badge_cls = "risk-high"
            risk_label = "MEDIUM RISK"
        elif risk_score >= 15:
            risk_badge_cls = "risk-medium"
            risk_label = "ELEVATED RISK"
        elif risk_score > 0:
            risk_badge_cls = "risk-low"
            risk_label = "LOW RISK"
        else:
            risk_badge_cls = "risk-safe"
            risk_label = "HARDENED / SECURE"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetAudit Enterprise Security Audit Report</title>
    <style>
        :root {{
            --bg-dark: #0b0f19;
            --card-bg: #151c2c;
            --card-border: #232d42;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --primary: #38bdf8;
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-medium: #eab308;
            --sev-low: #3b82f6;
            --sev-info: #64748b;
            --sev-safe: #22c55e;
        }}

        * {{ box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; }}
        body {{ background-color: var(--bg-dark); color: var(--text-main); margin: 0; padding: 2rem 1.5rem; line-height: 1.5; }}
        .container {{ max-width: 1280px; margin: 0 auto; }}

        /* Top Header Navigation */
        .top-header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.75rem 2rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5);
        }}
        .brand-title {{ font-size: 1.75rem; font-weight: 800; color: #fff; margin: 0; letter-spacing: -0.025em; display: flex; align-items: center; gap: 0.75rem; }}
        .brand-title span {{ color: var(--primary); }}
        .subtitle {{ color: var(--text-muted); margin: 0.35rem 0 0 0; font-size: 0.9rem; }}

        /* Risk Gauge Badge */
        .risk-gauge {{
            text-align: right;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--card-border);
            padding: 0.75rem 1.25rem;
            border-radius: 12px;
        }}
        .risk-score-num {{ font-size: 2.2rem; font-weight: 900; line-height: 1; }}
        .risk-critical {{ color: var(--sev-critical); }}
        .risk-high {{ color: var(--sev-high); }}
        .risk-medium {{ color: var(--sev-medium); }}
        .risk-low {{ color: var(--sev-low); }}
        .risk-safe {{ color: var(--sev-safe); }}
        .risk-label {{ font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-top: 0.2rem; }}

        /* Metrics Cards Grid */
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }}
        .metric-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.25rem; box-shadow: 0 4px 12px rgba(0,0,0,0.2); }}
        .metric-title {{ font-size: 0.8rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
        .metric-value {{ font-size: 1.8rem; font-weight: 800; margin-top: 0.5rem; }}

        /* Severity Pill Counter Badges */
        .sev-pill {{ display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.25rem 0.65rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
        .pill-CRITICAL {{ background: rgba(239, 68, 68, 0.15); color: var(--sev-critical); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .pill-HIGH {{ background: rgba(249, 115, 22, 0.15); color: var(--sev-high); border: 1px solid rgba(249, 115, 22, 0.3); }}
        .pill-MEDIUM {{ background: rgba(234, 179, 8, 0.15); color: var(--sev-medium); border: 1px solid rgba(234, 179, 8, 0.3); }}
        .pill-LOW {{ background: rgba(59, 130, 246, 0.15); color: var(--sev-low); border: 1px solid rgba(59, 130, 246, 0.3); }}
        .pill-INFO {{ background: rgba(100, 116, 139, 0.15); color: var(--sev-info); border: 1px solid rgba(100, 116, 139, 0.3); }}

        /* Table Styling */
        .section-header {{ display: flex; justify-content: space-between; align-items: center; margin: 2rem 0 1rem 0; }}
        .section-title {{ font-size: 1.25rem; font-weight: 700; color: #fff; margin: 0; }}
        
        .table-container {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; overflow: hidden; margin-bottom: 2rem; box-shadow: 0 4px 12px rgba(0,0,0,0.2); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
        th {{ background: #0f172a; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 1rem 1.25rem; border-bottom: 1px solid var(--card-border); }}
        td {{ padding: 1rem 1.25rem; border-bottom: 1px solid var(--card-border); color: var(--text-main); }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: rgba(255,255,255,0.02); }}

        code {{ background: #090d16; padding: 0.2rem 0.45rem; border-radius: 6px; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 0.85em; color: var(--primary); border: 1px solid #1e293b; }}

        /* Finding Card Component */
        .finding-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.25rem; box-shadow: 0 4px 12px rgba(0,0,0,0.2); transition: transform 0.15s ease; }}
        .finding-card:hover {{ border-color: #334155; }}
        .finding-card.border-CRITICAL {{ border-left: 5px solid var(--sev-critical); }}
        .finding-card.border-HIGH {{ border-left: 5px solid var(--sev-high); }}
        .finding-card.border-MEDIUM {{ border-left: 5px solid var(--sev-medium); }}
        .finding-card.border-LOW {{ border-left: 5px solid var(--sev-low); }}
        .finding-card.border-INFO {{ border-left: 5px solid var(--sev-info); }}

        .finding-head {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; margin-bottom: 0.75rem; }}
        .finding-title {{ font-size: 1.1rem; font-weight: 700; color: #fff; margin: 0; }}
        .target-tag {{ font-size: 0.8rem; background: #090d16; padding: 0.3rem 0.6rem; border-radius: 6px; border: 1px solid var(--card-border); color: #cbd5e1; white-space: nowrap; }}

        .finding-body {{ color: #cbd5e1; font-size: 0.92rem; margin-bottom: 1rem; }}
        
        .box-remediation {{ background: rgba(34, 197, 94, 0.06); border: 1px solid rgba(34, 197, 94, 0.2); border-radius: 8px; padding: 1rem; margin-top: 1rem; }}
        .box-remediation-title {{ font-size: 0.8rem; font-weight: 700; color: var(--sev-safe); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.4rem; display: flex; align-items: center; gap: 0.4rem; }}
        
        .box-evidence {{ background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 0.85rem 1rem; margin-top: 0.85rem; font-family: monospace; font-size: 0.82rem; color: #94a3b8; overflow-x: auto; white-space: pre-wrap; }}

        .ref-links {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.85rem; }}
        .ref-link {{ font-size: 0.75rem; color: var(--primary); text-decoration: none; background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.2); padding: 0.2rem 0.5rem; border-radius: 4px; }}
        .ref-link:hover {{ text-decoration: underline; background: rgba(56, 189, 248, 0.15); }}

        /* Filter Controls */
        .filter-bar {{ display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; margin-bottom: 1.5rem; }}
        .btn-filter {{ background: var(--card-bg); border: 1px solid var(--card-border); color: var(--text-muted); padding: 0.4rem 0.85rem; border-radius: 8px; font-size: 0.8rem; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
        .btn-filter.active, .btn-filter:hover {{ background: #1e293b; color: #fff; border-color: var(--primary); }}
    </style>
    <script>
        function filterFindings(sev) {{
            const cards = document.querySelectorAll('.finding-card');
            const btns = document.querySelectorAll('.btn-filter');
            btns.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            cards.forEach(card => {{
                if (sev === 'ALL' || card.getAttribute('data-severity') === sev) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</head>
<body>
    <div class="container">
        <!-- Top Executive Header -->
        <div class="top-header">
            <div>
                <h1 class="brand-title">Net<span>Audit</span> Security Report</h1>
                <p class="subtitle">Automated Security Posture & Asset Vulnerability Assessment</p>
                <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;">
                    <strong>Authorized Scope:</strong> {targets_str} &nbsp;|&nbsp; 
                    <strong>Timestamp:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
                </div>
            </div>
            <div class="risk-gauge">
                <div class="risk-score-num {risk_badge_cls}">{risk_score} <span style="font-size: 1rem; color: var(--text-muted);">/ 100</span></div>
                <div class="risk-label">{risk_label}</div>
            </div>
        </div>

        <!-- Metric Counter Cards -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Discovered Hosts</div>
                <div class="metric-value">{len(graph.hosts)}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Open Services</div>
                <div class="metric-value">{total_open_ports}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Critical Vulnerabilities</div>
                <div class="metric-value" style="color: var(--sev-critical);">{sev_counts['CRITICAL']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">High / Medium Risks</div>
                <div class="metric-value" style="color: var(--sev-high);">{sev_counts['HIGH'] + sev_counts['MEDIUM']}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Total Findings</div>
                <div class="metric-value">{len(findings)}</div>
            </div>
        </div>

        <!-- Section 1: Infrastructure Asset Inventory -->
        <div class="section-header">
            <h2 class="section-title">1. Discovered Asset Inventory</h2>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Target IP</th>
                        <th>Hostname / PTR</th>
                        <th>Host Status</th>
                        <th>Discovered Open Services & Banners</th>
                        <th>Security Issues</th>
                    </tr>
                </thead>
                <tbody>
"""
        for ip, host in graph.hosts.items():
            srv_list = []
            for p, s in sorted(host.services.items()):
                details = f"<code>TCP/{p} ({s.service_name})</code>"
                if s.banner:
                    details += f" &mdash; <em>{s.banner[:60]}...</em>" if len(s.banner) > 60 else f" &mdash; <em>{s.banner}</em>"
                srv_list.append(details)
            
            srv_html = "<br>".join(srv_list) if srv_list else "<span style='color:var(--text-muted)'>No open ports discovered</span>"
            
            host_findings_count = len(host.findings) + sum(len(s.findings) for s in host.services.values())
            
            html_content += f"""
                    <tr>
                        <td><code>{ip}</code></td>
                        <td>{host.hostname or 'N/A'}</td>
                        <td><span style="color: var(--sev-safe); font-weight:700;">● UP</span></td>
                        <td>{srv_html}</td>
                        <td><span class="sev-pill pill-{'HIGH' if host_findings_count > 0 else 'INFO'}">{host_findings_count} Issue(s)</span></td>
                    </tr>
"""
        html_content += """
                </tbody>
            </table>
        </div>

        <!-- Section 2: Detailed Vulnerabilities & Remediation -->
        <div class="section-header">
            <h2 class="section-title">2. Correlated Security Findings & Actionable Hardening Plans</h2>
        </div>

        <!-- Filter Controls -->
        <div class="filter-bar">
            <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: 700; margin-right: 0.5rem;">FILTER SEVERITY:</span>
            <button class="btn-filter active" onclick="filterFindings('ALL')">ALL ({len(findings)})</button>
            <button class="btn-filter" onclick="filterFindings('CRITICAL')">CRITICAL ({sev_counts['CRITICAL']})</button>
            <button class="btn-filter" onclick="filterFindings('HIGH')">HIGH ({sev_counts['HIGH']})</button>
            <button class="btn-filter" onclick="filterFindings('MEDIUM')">MEDIUM ({sev_counts['MEDIUM']})</button>
            <button class="btn-filter" onclick="filterFindings('LOW')">LOW ({sev_counts['LOW']})</button>
            <button class="btn-filter" onclick="filterFindings('INFO')">INFO ({sev_counts['INFO']})</button>
        </div>
"""

        if not findings:
            html_content += """
        <div class="finding-card border-INFO" data-severity="INFO">
            <div class="finding-title" style="color: var(--sev-safe);">✔ No Security Vulnerabilities or Policy Violations Detected</div>
            <p style="color: var(--text-muted); margin-top: 0.5rem;">All inspected services align with standard baseline requirements.</p>
        </div>
"""
        else:
            for f in findings:
                target_label = f"{f['target_ip']}:{f['port']}" if f.get('port') else f['target_ip']
                sev = f.get("severity", "INFO")
                
                # Format references
                refs_html = ""
                if f.get("references"):
                    refs = [f'<a class="ref-link" href="{r}" target="_blank">{r}</a>' for r in f["references"]]
                    refs_html = f'<div class="ref-links"><strong>References:</strong> {" ".join(refs)}</div>'

                # Format raw evidence if present
                evidence_html = ""
                if f.get("raw_evidence"):
                    evidence_html = f'<div class="box-evidence"><strong>RAW EVIDENCE LOG:</strong>\n{f["raw_evidence"]}</div>'

                # Format remediation block
                remediation_text = f['remediation'].replace("\n", "<br>")

                html_content += f"""
        <div class="finding-card border-{sev}" data-severity="{sev}">
            <div class="finding-head">
                <div>
                    <span class="sev-pill pill-{sev}">{sev}</span>
                    <h3 class="finding-title" style="display:inline; margin-left: 0.5rem;">{f['title']}</h3>
                </div>
                <div class="target-tag">Target: <code>{target_label}</code></div>
            </div>
            
            <div class="finding-body">
                <p><strong>Description:</strong> {f['description']}</p>
                {evidence_html}
                <div class="box-remediation">
                    <div class="box-remediation-title">🛡️ Recommended Hardening & Remediation Action</div>
                    <div>{remediation_text}</div>
                </div>
                {refs_html}
            </div>
        </div>
"""

        html_content += """
    </div>
</body>
</html>
"""
        with open(self.output_path, "w", encoding="utf-8") as out:
            out.write(html_content)

"""
HTML Incident Report Generator
"""
import os
import time
from typing import List, Dict, Any

def generate_html_report(
    target_dir: str,
    scan_results: Dict[str, Any],
    verdict_list: List[Dict[str, Any]],
    output_filename: str = "fim_incident_report.html"
) -> str:
    """Generate professional HTML incident report."""
    target_dir = os.path.abspath(target_dir)
    out_path = os.path.join(target_dir, output_filename)
    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    malicious_count = sum(1 for v in verdict_list if v.get("verdict") == "MALICIOUS")
    suspicious_count = sum(1 for v in verdict_list if v.get("verdict") == "SUSPICIOUS")
    benign_count = sum(1 for v in verdict_list if v.get("verdict") == "BENIGN")

    findings_rows = []
    for v in verdict_list:
        verdict = v.get("verdict", "BENIGN")
        badge_class = "badge-danger" if verdict == "MALICIOUS" else ("badge-warning" if verdict == "SUSPICIOUS" else "badge-success")
        
        findings_rows.append(f"""
        <tr>
            <td><code>{v.get('target_file')}</code></td>
            <td><span class="badge {badge_class}">{verdict}</span></td>
            <td><code>{v.get('mitre_tactic', 'None')}</code></td>
            <td>{v.get('reasoning')}</td>
            <td><code>{v.get('recommended_action')}</code></td>
        </tr>
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FIM AI SOC Incident Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 1100px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        h1 {{ color: #38bdf8; margin-top: 0; display: flex; align-items: center; gap: 12px; }}
        .meta {{ color: #94a3b8; font-size: 0.9em; margin-bottom: 24px; border-bottom: 1px solid #334155; padding-bottom: 12px; }}
        .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
        .card {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; }}
        .card .number {{ font-size: 2em; font-weight: bold; margin-top: 8px; }}
        .card-danger .number {{ color: #f87171; }}
        .card-warning .number {{ color: #fbbf24; }}
        .card-success .number {{ color: #4ade80; }}
        .card-info .number {{ color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; font-weight: 600; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }}
        .badge-danger {{ background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }}
        .badge-warning {{ background: #78350f; color: #fde68a; border: 1px solid #f59e0b; }}
        .badge-success {{ background: #14532d; color: #86efac; border: 1px solid #22c55e; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #e2e8f0; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AI SOC Analyst Incident Report</h1>
        <div class="meta">
            Target Directory: <code>{target_dir}</code> | Generated: {now_str}
        </div>

        <div class="cards">
            <div class="card card-danger">
                <div>Malicious Threat</div>
                <div class="number">{malicious_count}</div>
            </div>
            <div class="card card-warning">
                <div>Suspicious Events</div>
                <div class="number">{suspicious_count}</div>
            </div>
            <div class="card card-success">
                <div>Benign Events</div>
                <div class="number">{benign_count}</div>
            </div>
            <div class="card card-info">
                <div>Total Analysed</div>
                <div class="number">{len(verdict_list)}</div>
            </div>
        </div>

        <h2>🔍 Detailed Investigation Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>File Path</th>
                    <th>Verdict</th>
                    <th>MITRE ATT&CK</th>
                    <th>Reasoning & Analysis</th>
                    <th>Recommended Action</th>
                </tr>
            </thead>
            <tbody>
                {''.join(findings_rows) if findings_rows else '<tr><td colspan="5">No file modifications detected. System clean.</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return out_path

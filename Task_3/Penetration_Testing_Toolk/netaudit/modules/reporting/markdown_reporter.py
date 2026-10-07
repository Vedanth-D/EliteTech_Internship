import os
from datetime import datetime, timezone
from typing import Dict, Any
from ..base import BaseModule
from ...core.graph import AssetGraph


class MarkdownReportGenerator(BaseModule):
    """
    Generates a structured Markdown executive and technical security audit report.
    """

    name = "markdown_report_generator"
    description = "Compiles audit findings and asset inventory into a Markdown document."
    category = "reporting"

    def __init__(self, output_path: str = "audit_report.md", options: Dict[str, Any] = None):
        super().__init__(options)
        self.output_path = output_path

    def run(self, graph: AssetGraph) -> None:
        risk_score = graph.calculate_risk_score()
        all_findings = graph.get_all_findings()

        lines = [
            "# Executive Security Audit & Asset Inventory Report",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Aggregate Risk Score:** `{risk_score}/100.0`  \n",
            "---",
            "## 1. Executive Summary",
            f"An automated security audit was conducted across authorized target infrastructure. A total of **{len(graph.hosts)}** host(s) were inspected, resulting in **{len(all_findings)}** security findings and configuration observations.",
            "",
            "## 2. Infrastructure & Asset Inventory",
            "| Host IP | Hostname | Status | Open Ports & Services | Security Issues |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]

        for ip, host in graph.hosts.items():
            srv_list = []
            for p, s in sorted(host.services.items()):
                item = f"`TCP/{p}` ({s.service_name})"
                if s.banner:
                    item += f" - *{s.banner[:40]}*"
                srv_list.append(item)
            
            ports_str = "<br>".join(srv_list) if srv_list else "None detected"
            issue_count = len(host.findings) + sum(len(s.findings) for s in host.services.values())
            lines.append(f"| `{ip}` | {host.hostname or 'N/A'} | `UP` | {ports_str} | `{issue_count}` |")

        lines.extend([
            "",
            "## 3. Correlated Security Findings & Actionable Hardening Plans",
        ])

        if not all_findings:
            lines.append("> [!NOTE]\n> No security vulnerabilities or policy violations were detected across target infrastructure.")
        else:
            for idx, finding in enumerate(all_findings, 1):
                target_str = f"{finding['target_ip']}"
                if finding['port']:
                    target_str += f":{finding['port']}"

                sev = finding['severity']
                alert_type = "CAUTION" if sev == "CRITICAL" else ("WARNING" if sev in ("HIGH", "MEDIUM") else "NOTE")

                lines.extend([
                    f"### 3.{idx} [{sev}] {finding['title']}",
                    f"- **Target:** `{target_str}`",
                    f"- **Finding ID:** `{finding['id']}`",
                    f"- **Description:** {finding['description']}",
                ])

                if finding.get("raw_evidence"):
                    lines.extend([
                        "- **Raw Evidence Log:**",
                        "```text",
                        str(finding["raw_evidence"]).strip(),
                        "```"
                    ])

                lines.extend([
                    f"> [!{alert_type}]",
                    f"> **Remediation & Hardening Plan:**",
                    f"> {finding['remediation'].replace('\n', '\n> ')}"
                ])

                if finding.get('references'):
                    refs = ", ".join(f"[{r}]({r})" for r in finding['references'])
                    lines.append(f"- **References:** {refs}")
                lines.append("")

        lines.extend([
            "---",
            "*Report produced by NetAudit Security Audit & Asset Inventory Framework.*"
        ])

        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

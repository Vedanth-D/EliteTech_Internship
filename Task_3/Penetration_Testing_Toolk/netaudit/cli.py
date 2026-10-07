import sys
import logging
import argparse
from typing import List

from .core.scope import ScopeGuard, ScopeViolationError
from .core.graph import AssetGraph
from .core.engine import AuditEngine
from .modules.discovery.host_sweep import HostSweepCollector
from .modules.auditors.banner_grabber import ServiceBannerAuditor
from .modules.auditors.tls_auditor import TLSCipherAuditor
from .modules.auditors.ssh_policy import SSHPolicyAuditor
from .modules.auditors.smb_policy import SMBPolicyAuditor
from .modules.auditors.http_headers import HTTPHeaderAuditor
from .modules.reporting.markdown_reporter import MarkdownReportGenerator
from .modules.reporting.html_reporter import HTMLReportGenerator


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NetAudit: Modular Security Audit & Asset Inventory Framework"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        nargs="+",
        help="Target IP address(es) or CIDR block(s) authorized for auditing (e.g. 127.0.0.1 192.168.1.0/24)"
    )
    parser.add_argument(
        "-p", "--ports",
        nargs="+",
        type=int,
        help="Optional list of custom ports to inspect"
    )
    parser.add_argument(
        "--md-report",
        default="audit_report.md",
        help="Output path for Markdown report (default: audit_report.md)"
    )
    parser.add_argument(
        "--html-report",
        default="audit_report.html",
        help="Output path for HTML report (default: audit_report.html)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    print("==================================================================")
    print("      NetAudit: Security Audit & Asset Inventory Framework        ")
    print("==================================================================")

    try:
        # Step 1: Initialize Authorization Scope Guard
        print(f"[*] Initializing scope guard for authorized targets: {args.target}")
        scope_guard = ScopeGuard(allowed_targets=args.target)

        # Step 2: Initialize Graph Data Engine & Orchestrator Engine
        graph = AssetGraph(scope_guard=scope_guard)
        engine = AuditEngine(graph=graph)

        # Step 3: Register Pipeline Modules
        target_ips = args.target
        ports = args.ports

        print("[*] Registering discovery & auditor modules...")
        engine.register_module(HostSweepCollector(target_ips=target_ips, ports=ports))
        engine.register_module(ServiceBannerAuditor())
        engine.register_module(TLSCipherAuditor())
        engine.register_module(SSHPolicyAuditor())
        engine.register_module(SMBPolicyAuditor())
        engine.register_module(HTTPHeaderAuditor())
        engine.register_module(MarkdownReportGenerator(output_path=args.md_report))
        engine.register_module(HTMLReportGenerator(output_path=args.html_report))

        # Step 4: Execute Pipeline
        print("[*] Executing security audit pipeline...")
        engine.run_all()

        # Step 5: Summary
        risk = graph.calculate_risk_score()
        print("\n------------------------------------------------------------------")
        print(f"[+] Audit execution finished successfully.")
        print(f"[+] Discovered Active Hosts : {len(graph.hosts)}")
        print(f"[+] Total Security Findings  : {len(graph.get_all_findings())}")
        print(f"[+] Aggregate Risk Score    : {risk} / 100.0")
        print(f"[+] Markdown Report Written : {args.md_report}")
        print(f"[+] HTML Dashboard Written  : {args.html_report}")
        print("------------------------------------------------------------------")

    except ScopeViolationError as e:
        print(f"\n[!] Scope Violation Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during audit execution: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

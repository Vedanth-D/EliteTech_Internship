"""
File Integrity Checker (FIM) - AI SOC Analyst CLI Entrypoint
Zero-Manual-Input Automated Security & Threat Response Engine
"""
import argparse
import os
import sys
import time
import platform

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import get_auto_target_paths, AUTO_LEARNING_PERIOD_HOURS, DESKTOP_NOTIFICATIONS_ENABLED
from core.scanner import scan_directory
from core.baseline import save_baseline, load_baseline, verify_baseline_integrity, compare_scans
from core.vault import backup_all_baseline_files, restore_file_from_vault
from core.monitor import start_live_monitor
from analytics.ml_anomaly import FIMAnomalyDetector
from agent.llm_analyst import AnalystAgent
from agent.response_engine import execute_response_action
from agent.alert_manager import trigger_security_alert
from reporting.html_report import generate_html_report
from reporting.pdf_report import generate_pdf_report

console = Console()

def cmd_start():
    """
    Zero-Input Automated Entrypoint:
    Auto-detects critical system/app paths, auto-hashes HMAC baselines if missing,
    enables auto-learning window, dispatches desktop notifications & exports PDF reports.
    """
    console.print(Panel(
        f"[bold cyan]🛡️ FIM Agentic AI SOC Analyst - Autonomous Security Engine[/]\n"
        f"[bold white]Operating System:[/] {platform.system()} {platform.release()} ({platform.architecture()[0]})\n"
        f"[bold white]Auto-Learning Window:[/] Active ({AUTO_LEARNING_PERIOD_HOURS}h Observation Period)\n"
        f"[bold white]Desktop Notifications:[/] {'ENABLED' if DESKTOP_NOTIFICATIONS_ENABLED else 'DISABLED'}\n"
        f"[bold white]PDF Report Export:[/] AUTOMATIC",
        title="⚡ ZERO-INPUT STARTUP MODE",
        border_style="cyan"
    ))

    target_paths = get_auto_target_paths()
    console.print(f"[bold yellow]📍 Auto-Selected Target Paths ({len(target_paths)}):[/]")
    for p in target_paths:
        console.print(f"  • {p}")

    for target_dir in target_paths:
        console.print(f"\n[bold cyan]Checking HMAC baseline for:[/] {target_dir}")
        baseline_map, msg = load_baseline(target_dir)

        # Auto-Baseline on first run if missing
        if not baseline_map:
            console.print(f"[yellow]⚠️  No baseline found. Executing automatic HMAC-SHA256 baseline creation...[/]")
            scan_map = scan_directory(target_dir)
            b_path, h_path = save_baseline(target_dir, scan_map)
            vault_count = backup_all_baseline_files(target_dir, scan_map)
            baseline_map = scan_map

            console.print(Panel(
                f"[bold green]Auto-Baseline Created Successfully![/]\n"
                f"• Tracked Files: {len(scan_map)}\n"
                f"• Baseline DB: {b_path}\n"
                f"• HMAC Signature: {h_path}\n"
                f"• Vault Backups: {vault_count} pristine files stored in backup vault",
                title=f"✓ Baseline Ready: {os.path.basename(target_dir)}",
                border_style="green"
            ))
        else:
            console.print(f"[bold green]✓ {msg}[/]")

    primary_target = target_paths[0]
    baseline_map, _ = load_baseline(primary_target)
    start_live_monitor(primary_target, baseline_map, auto_approve=True)

def cmd_init(target_dir: str):
    """Initialize HMAC-signed baseline and backup vault."""
    console.print(f"[bold cyan]Initializing FIM baseline for:[/] {os.path.abspath(target_dir)}")
    scan_map = scan_directory(target_dir)

    b_path, h_path = save_baseline(target_dir, scan_map)
    vault_count = backup_all_baseline_files(target_dir, scan_map)

    console.print(Panel(
        f"[bold green]Baseline Initialized Successfully![/]\n"
        f"• Tracked Files: {len(scan_map)}\n"
        f"• Baseline DB: {b_path}\n"
        f"• HMAC Signature: {h_path}\n"
        f"• Vault Backups: {vault_count} files stored safely",
        title="🛡️ FIM Baseline Ready",
        border_style="green"
    ))

def cmd_check(target_dir: str, auto_approve: bool = False):
    """Run full check against HMAC baseline, run ML & AI SOC Analyst, and export report."""
    console.print(f"[bold cyan]Verifying baseline integrity...[/]")
    old_baseline, msg = load_baseline(target_dir)
    if not old_baseline:
        console.print(f"[bold red]{msg}[/]")
        sys.exit(1)
    
    console.print(f"[green]✓ {msg}[/]")
    console.print(f"[bold cyan]Scanning current file system state...[/]")
    current_scan = scan_directory(target_dir)

    diff_results = compare_scans(old_baseline, current_scan)

    new_count = len(diff_results["new"])
    mod_count = len(diff_results["modified"])
    del_count = len(diff_results["deleted"])
    mov_count = len(diff_results["moved"])
    unchanged_count = len(diff_results["unchanged"])

    table = Table(title="🔍 FIM Integrity Scan Overview")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="bold yellow")
    table.add_row("New Files", str(new_count))
    table.add_row("Modified Files", str(mod_count))
    table.add_row("Deleted Files", str(del_count))
    table.add_row("Moved/Renamed Files", str(mov_count))
    table.add_row("Unchanged Files", str(unchanged_count))
    console.print(table)

    all_changes = diff_results["modified"] + diff_results["new"] + diff_results["moved"] + diff_results["deleted"]
    if not all_changes:
        console.print("[bold green]✨ All files match baseline. Zero integrity anomalies detected.[/]")
        return

    console.print(f"\n[bold magenta]🤖 Launching Agentic AI SOC Analyst for {len(all_changes)} change event(s)...[/]")
    
    ml_detector = FIMAnomalyDetector()
    analyst = AnalystAgent()
    verdict_list = []

    for change in all_changes:
        is_anomaly, risk_score, ml_reason = ml_detector.predict(change)
        verdict = analyst.investigate_change(target_dir, change, is_anomaly, risk_score, all_changes)
        verdict_list.append(verdict)

        v_text = verdict.get("verdict")
        color = "red" if v_text == "MALICIOUS" else ("yellow" if v_text == "SUSPICIOUS" else "green")
        
        console.print(Panel(
            f"[bold {color}]Verdict: {v_text}[/] ({verdict.get('confidence')} Confidence)\n"
            f"[bold]Target File:[/] {verdict.get('target_file')}\n"
            f"[bold]MITRE ATT&CK:[/] {verdict.get('mitre_tactic')}\n"
            f"[bold]Reasoning:[/] {verdict.get('reasoning')}\n"
            f"[bold]Recommended Action:[/] {verdict.get('recommended_action')}",
            title=f"🚨 AI Analyst Investigation: {verdict.get('target_file')}",
            border_style=color
        ))

        # Dispatch Desktop Alert for threats
        if v_text in ("MALICIOUS", "SUSPICIOUS"):
            trigger_security_alert(
                target_file=verdict.get("target_file"),
                verdict=v_text,
                mitre_tactic=verdict.get("mitre_tactic"),
                reasoning=verdict.get("reasoning"),
                recommended_action=verdict.get("recommended_action")
            )

        # Execute response if needed
        execute_response_action(target_dir, verdict, auto_approve)

    report_file = generate_html_report(target_dir, diff_results, verdict_list)
    pdf_file = generate_pdf_report(target_dir, verdict_list)
    console.print(f"\n[bold green]📊 HTML Incident Report generated:[/] {report_file}")
    console.print(f"[bold green]📄 PDF Incident Report generated:[/] {pdf_file}")

def cmd_export_pdf(target_dir: str):
    """Generate PDF Incident Report for target directory."""
    old_baseline, msg = load_baseline(target_dir)
    if not old_baseline:
        console.print(f"[bold red]{msg}[/]")
        sys.exit(1)
    
    current_scan = scan_directory(target_dir)
    diff_results = compare_scans(old_baseline, current_scan)
    all_changes = diff_results["modified"] + diff_results["new"] + diff_results["moved"] + diff_results["deleted"]

    ml_detector = FIMAnomalyDetector()
    analyst = AnalystAgent()
    verdict_list = []

    for change in all_changes:
        is_anomaly, risk_score, ml_reason = ml_detector.predict(change)
        verdict = analyst.investigate_change(target_dir, change, is_anomaly, risk_score, all_changes)
        verdict_list.append(verdict)

    pdf_file = generate_pdf_report(target_dir, verdict_list)
    console.print(f"[bold green]📄 PDF Incident Report generated:[/] {pdf_file}")

def cmd_restore(target_dir: str, rel_path: str):
    """Restore a file from vault backup."""
    success, msg = restore_file_from_vault(target_dir, rel_path)
    if success:
        console.print(f"[bold green]✓ {msg}[/]")
    else:
        console.print(f"[bold red]✗ {msg}[/]")

def cmd_update(target_dir: str):
    """Accept current state as new clean baseline."""
    cmd_init(target_dir)
    console.print("[bold green]Baseline updated with current state.[/]")

def main():
    parser = argparse.ArgumentParser(description="Agentic AI SOC Analyst - File Integrity Checker")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # gui (Default Desktop Software GUI)
    parser_gui = subparsers.add_parser("gui", help="Launch native Desktop GUI Software window")

    # start (Default Zero-Input Entrypoint)
    parser_start = subparsers.add_parser("start", help="Auto-select targets, auto-baseline, and run live background monitoring")

    # init
    parser_init = subparsers.add_parser("init", help="Create baseline and vault backups for custom folder")
    parser_init.add_argument("dir", nargs="?", default=".", help="Target directory (default: current)")

    # check
    parser_check = subparsers.add_parser("check", help="Compare current files with baseline and run AI analysis")
    parser_check.add_argument("dir", nargs="?", default=".", help="Target directory (default: current)")
    parser_check.add_argument("--auto-approve", action="store_true", help="Auto-execute recommended responses")

    # export-pdf
    parser_pdf = subparsers.add_parser("export-pdf", help="Generate downloadable PDF Incident Report")
    parser_pdf.add_argument("dir", nargs="?", default=".", help="Target directory (default: current)")

    # restore
    parser_restore = subparsers.add_parser("restore", help="Restore a file from vault backup")
    parser_restore.add_argument("path", help="Relative file path to restore")
    parser_restore.add_argument("dir", nargs="?", default=".", help="Target directory (default: current)")

    # update
    parser_update = subparsers.add_parser("update", help="Update baseline to current state")
    parser_update.add_argument("dir", nargs="?", default=".", help="Target directory (default: current)")

    args = parser.parse_args()

    # Default to GUI if no subcommand given
    if not args.command or args.command == "gui":
        from gui_app import launch_gui
        launch_gui()
    elif args.command == "start":
        cmd_start()
    elif args.command == "init":
        cmd_init(args.dir)
    elif args.command == "check":
        cmd_check(args.dir, getattr(args, "auto_approve", False))
    elif args.command == "export-pdf":
        cmd_export_pdf(args.dir)
    elif args.command == "restore":
        cmd_restore(args.dir, args.path)
    elif args.command == "update":
        cmd_update(args.dir)

if __name__ == "__main__":
    main()

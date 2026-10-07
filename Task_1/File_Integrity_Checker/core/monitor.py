"""
Live File System Monitor using Watchdog Engine
"""
import time
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from typing import Dict, Any

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent

from config import is_path_ignored
from core.scanner import get_file_metadata
from analytics.entropy import calculate_file_entropy
from analytics.ml_anomaly import FIMAnomalyDetector
from analytics.burst_detector import BurstDetector
from agent.llm_analyst import AnalystAgent
from agent.response_engine import execute_response_action
from agent.alert_manager import trigger_security_alert
from reporting.pdf_report import generate_pdf_report
from memory.feedback_db import log_scan_event, log_analyst_verdict, is_known_false_positive

class FIMWatchHandler(FileSystemEventHandler):
    def __init__(self, target_dir: str, baseline_map: Dict[str, Dict[str, Any]], auto_approve: bool = False):
        self.target_dir = os.path.abspath(target_dir)
        self.baseline_map = baseline_map
        self.auto_approve = auto_approve
        self.ml_detector = FIMAnomalyDetector()
        self.burst_detector = BurstDetector()
        self.analyst = AnalystAgent()
        self.recent_events = []

    def process_event(self, event_type: str, src_path: str):
        if is_path_ignored(src_path, self.target_dir):
            return

        rel_path = os.path.relpath(src_path, self.target_dir).replace("\\", "/")
        print(f"\n⚡ [MONITOR EVENT] {event_type.upper()}: {rel_path}")

        current_meta = get_file_metadata(src_path, self.target_dir) if os.path.exists(src_path) else None
        old_meta = self.baseline_map.get(rel_path)

        change_event = {
            "event_type": event_type,
            "rel_path": rel_path,
            "old_meta": old_meta,
            "new_meta": current_meta,
            "entropy_delta": (current_meta["entropy"] - old_meta["entropy"]) if (current_meta and old_meta) else 0.0,
            "size_delta": (current_meta["size"] - old_meta["size"]) if (current_meta and old_meta) else 0
        }

        self.recent_events.append(change_event)

        # 1. Burst Ransomware Check
        is_burst, burst_msg = self.burst_detector.add_event(change_event)
        if is_burst:
            print(f"\n{burst_msg}")

        # 2. Check if user flagged as False Positive before
        if is_known_false_positive(self.target_dir, rel_path):
            print(f"ℹ️  Path {rel_path} was previously flagged as False Positive by operator. Downgrading alert.")
            log_scan_event(self.target_dir, rel_path, event_type, current_meta["sha256"] if current_meta else "", current_meta["entropy"] if current_meta else 0.0)
            return

        # 3. Isolation Forest ML Anomaly Score
        is_anomaly, risk_score, ml_reasoning = self.ml_detector.predict(change_event)

        # 4. Agentic AI Analyst Investigation
        verdict = self.analyst.investigate_change(
            self.target_dir, change_event, is_anomaly, risk_score, self.recent_events
        )

        print(f"🤖 [ANALYST VERDICT] {verdict.get('verdict')} ({verdict.get('confidence')} Confidence)")
        print(f"   Reasoning: {verdict.get('reasoning')}")
        if verdict.get("mitre_tactic") != "None":
            print(f"   MITRE ATT&CK: {verdict.get('mitre_tactic')}")

        # 5. Response Execution
        status, action_msg = execute_response_action(self.target_dir, verdict, self.auto_approve)
        log_analyst_verdict(self.target_dir, verdict, action_msg)
        log_scan_event(self.target_dir, rel_path, event_type, current_meta["sha256"] if current_meta else "", current_meta["entropy"] if current_meta else 0.0)

        # 6. Automatic Alert Dispatch & PDF Incident Report Generation
        if verdict.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
            trigger_security_alert(
                target_file=rel_path,
                verdict=verdict.get("verdict"),
                mitre_tactic=verdict.get("mitre_tactic"),
                reasoning=verdict.get("reasoning"),
                recommended_action=verdict.get("recommended_action")
            )
            generate_pdf_report(self.target_dir, [verdict])

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process_event("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.process_event("deleted", event.src_path)


def start_live_monitor(target_dir: str, baseline_map: Dict[str, Dict[str, Any]], auto_approve: bool = False):
    """Start watchdog observer loop."""
    target_dir = os.path.abspath(target_dir)
    event_handler = FIMWatchHandler(target_dir, baseline_map, auto_approve)
    observer = Observer()
    observer.schedule(event_handler, target_dir, recursive=True)
    observer.start()

    print(f"\n👁️  LIVE FIM MONITOR ACTIVE on {target_dir}")
    print("   Press Ctrl+C to stop monitoring...\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopping live monitor...")
    observer.join()

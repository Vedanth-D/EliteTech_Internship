"""
Native Desktop Software GUI Application (Tkinter + Watchdog + PyStray)
Consent-Based User Permission Model & Real-Time AI SOC Analyst Interface
"""
import os
import sys
import time
import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, Any, List

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from config import (
    get_approved_folders, add_approved_folder, remove_approved_folder,
    is_path_ignored
)
from core.scanner import scan_directory
from core.baseline import save_baseline, load_baseline, compare_scans
from core.vault import backup_all_baseline_files, restore_file_from_vault, quarantine_file
from core.monitor import FIMWatchHandler
from analytics.ml_anomaly import FIMAnomalyDetector
from agent.llm_analyst import AnalystAgent
from agent.alert_manager import trigger_security_alert
from reporting.pdf_report import generate_pdf_report

from watchdog.observers import Observer

class FIMGuiApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🛡️ Agentic AI SOC Analyst - File Integrity Guard")
        self.root.geometry("1180x720")
        self.root.configure(bg="#0b1329")

        self.observers = {}
        self.scan_in_progress = False

        self._setup_styles()
        self._build_header()
        self._build_body()
        self._load_approved_folders()
        self._start_watchdog_for_all()

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Configure Colors
        self.style.configure(".", background="#0b1329", foreground="#e2e8f0")
        self.style.configure("Treeview", 
                             background="#0f172a", 
                             foreground="#e2e8f0", 
                             fieldbackground="#0f172a", 
                             rowheight=28)
        self.style.configure("Treeview.Heading", 
                             background="#1e293b", 
                             foreground="#38bdf8", 
                             font=("Segoe UI", 9, "bold"))
        self.style.map("Treeview", background=[("selected", "#0284c7")])

    def _build_header(self):
        header_frame = tk.Frame(self.root, bg="#131e3a", padx=15, pady=12, bd=1, relief="solid")
        header_frame.pack(fill="x", side="top")

        title_lbl = tk.Label(
            header_frame, 
            text="🛡️ Agentic AI SOC Analyst — File Integrity Guard", 
            font=("Segoe UI", 16, "bold"), 
            fg="#38bdf8", 
            bg="#131e3a"
        )
        title_lbl.pack(anchor="w")

        subtitle = tk.Label(
            header_frame, 
            text="\"The software only accesses folders the user explicitly grants, builds a tamper-proof fingerprint baseline of them, and continuously guards their integrity.\"", 
            font=("Segoe UI", 9, "italic"), 
            fg="#94a3b8", 
            bg="#131e3a"
        )
        subtitle.pack(anchor="w", pady=(2, 0))

    def _build_body(self):
        main_frame = tk.Frame(self.root, bg="#0b1329", padx=15, pady=15)
        main_frame.pack(fill="both", expand=True)

        # Left Sidebar (Folder Manager & Consent Model)
        sidebar = tk.Frame(main_frame, bg="#131e3a", width=320, padx=12, pady=12, bd=1, relief="solid")
        sidebar.pack(side="left", fill="y", padx=(0, 15))
        sidebar.pack_propagate(False)

        side_title = tk.Label(sidebar, text="🛡️ Protected Folders (Consent)", font=("Segoe UI", 11, "bold"), fg="#e2e8f0", bg="#131e3a")
        side_title.pack(anchor="w", pady=(0, 10))

        self.folder_listbox = tk.Listbox(sidebar, bg="#0f172a", fg="#38bdf8", selectbackground="#0284c7", bd=1, font=("Segoe UI", 9))
        self.folder_listbox.pack(fill="both", expand=True, pady=(0, 10))

        btn_add = tk.Button(sidebar, text="➕ Add Folder to Protect", font=("Segoe UI", 9, "bold"), bg="#0284c7", fg="white", activebackground="#0369a1", bd=0, pady=6, command=self.add_folder_dialog)
        btn_add.pack(fill="x", pady=2)

        btn_remove = tk.Button(sidebar, text="➖ Remove Folder", font=("Segoe UI", 9), bg="#334155", fg="white", activebackground="#475569", bd=0, pady=4, command=self.remove_folder_action)
        btn_remove.pack(fill="x", pady=2)

        # Status Meter Card
        status_card = tk.Frame(sidebar, bg="#0f172a", padx=10, pady=10, bd=1, relief="solid")
        status_card.pack(fill="x", pady=(15, 0))

        tk.Label(status_card, text="SYSTEM STATUS", font=("Segoe UI", 8, "bold"), fg="#94a3b8", bg="#0f172a").pack(anchor="w")
        self.status_val = tk.Label(status_card, text="✓ SECURE", font=("Segoe UI", 14, "bold"), fg="#4ade80", bg="#0f172a")
        self.status_val.pack(anchor="w", pady=2)
        
        self.tracked_lbl = tk.Label(status_card, text="Tracked Files: 0", font=("Segoe UI", 8), fg="#cbd5e1", bg="#0f172a")
        self.tracked_lbl.pack(anchor="w")

        # Right Main Panel (Action Toolbar + Investigation Findings Table)
        right_panel = tk.Frame(main_frame, bg="#0b1329")
        right_panel.pack(side="right", fill="both", expand=True)

        # Action Toolbar
        toolbar = tk.Frame(right_panel, bg="#131e3a", padx=10, pady=8, bd=1, relief="solid")
        toolbar.pack(fill="x", pady=(0, 12))

        btn_scan = tk.Button(toolbar, text="⚡ Run AI Check", font=("Segoe UI", 9, "bold"), bg="#0284c7", fg="white", bd=0, padx=12, pady=5, command=self.run_ai_check_threaded)
        btn_scan.pack(side="left", padx=(0, 6))

        btn_pdf = tk.Button(toolbar, text="📄 Export PDF Report", font=("Segoe UI", 9, "bold"), bg="#dc2626", fg="white", bd=0, padx=12, pady=5, command=self.export_pdf_report_action)
        btn_pdf.pack(side="left", padx=6)

        btn_trust = tk.Button(toolbar, text="🛡️ Trust / Update Baseline", font=("Segoe UI", 9), bg="#059669", fg="white", bd=0, padx=10, pady=5, command=self.trust_baseline_action)
        btn_trust.pack(side="left", padx=6)

        btn_restore = tk.Button(toolbar, text="🔄 Restore File", font=("Segoe UI", 9), bg="#d97706", fg="white", bd=0, padx=10, pady=5, command=self.restore_file_action)
        btn_restore.pack(side="left", padx=6)

        btn_quarantine = tk.Button(toolbar, text="📦 Quarantine File", font=("Segoe UI", 9), bg="#7f1d1d", fg="white", bd=0, padx=10, pady=5, command=self.quarantine_file_action)
        btn_quarantine.pack(side="left", padx=6)

        # Findings Treeview
        columns = ("time", "file", "verdict", "mitre", "reasoning", "action")
        self.tree = ttk.Treeview(right_panel, columns=columns, show="headings", selectmode="browse")
        
        self.tree.heading("time", text="Timestamp")
        self.tree.heading("file", text="Folder / Target File")
        self.tree.heading("verdict", text="Verdict")
        self.tree.heading("mitre", text="MITRE ATT&CK")
        self.tree.heading("reasoning", text="Reasoning & Evidence")
        self.tree.heading("action", text="Action Needed")

        self.tree.column("time", width=110, anchor="center")
        self.tree.column("file", width=220)
        self.tree.column("verdict", width=95, anchor="center")
        self.tree.column("mitre", width=180)
        self.tree.column("reasoning", width=340)
        self.tree.column("action", width=95, anchor="center")

        # Treeview tags for severity formatting
        self.tree.tag_configure("MALICIOUS", foreground="#f87171", background="#450a0a")
        self.tree.tag_configure("SUSPICIOUS", foreground="#fde68a", background="#451a03")
        self.tree.tag_configure("BENIGN", foreground="#86efac", background="#052e16")

        scroll_y = ttk.Scrollbar(right_panel, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll_y.pack(side="right", fill="y")

    def _load_approved_folders(self):
        self.folder_listbox.delete(0, tk.END)
        folders = get_approved_folders()
        for f in folders:
            self.folder_listbox.insert(tk.END, f)

    def add_folder_dialog(self):
        folder = filedialog.askdirectory(title="Select a folder to protect")
        if not folder:
            return

        folder = os.path.abspath(folder)
        ok = messagebox.askyesno(
            "Grant Consent & Access",
            f"Allow this tool to read all files in:\n{folder}\n\n"
            "It will compute SHA-256 hashes, generate HMAC signatures, and monitor changes in real-time."
        )
        if ok:
            add_approved_folder(folder)
            self._load_approved_folders()
            
            # Auto-Baseline in background thread
            threading.Thread(target=self._auto_baseline_folder, args=(folder,), daemon=True).start()

    def _auto_baseline_folder(self, folder: str):
        self.status_val.config(text="⏳ SCANNING...", fg="#38bdf8")
        scan_map = scan_directory(folder)
        save_baseline(folder, scan_map)
        backup_all_baseline_files(folder, scan_map)
        
        self.root.after(0, lambda: self._update_status("✓ SECURE", "#4ade80", len(scan_map)))
        self._start_watchdog_for(folder)

    def remove_folder_action(self):
        sel = self.folder_listbox.curselection()
        if not sel:
            messagebox.showinfo("Selection Required", "Please select a folder to remove from protection.")
            return

        folder = self.folder_listbox.get(sel[0])
        if messagebox.askyesno("Revoke Consent", f"Revoke access and stop monitoring:\n{folder}?"):
            remove_approved_folder(folder)
            self._stop_watchdog_for(folder)
            self._load_approved_folders()

    def _start_watchdog_for_all(self):
        for folder in get_approved_folders():
            self._start_watchdog_for(folder)

    def _start_watchdog_for(self, folder: str):
        if folder in self.observers:
            return

        baseline_map, _ = load_baseline(folder)
        if not baseline_map:
            scan_map = scan_directory(folder)
            save_baseline(folder, scan_map)
            backup_all_baseline_files(folder, scan_map)
            baseline_map = scan_map

        handler = GuiFIMWatchHandler(folder, baseline_map, app_instance=self)
        obs = Observer()
        obs.schedule(handler, folder, recursive=True)
        obs.start()
        self.observers[folder] = obs

    def _stop_watchdog_for(self, folder: str):
        if folder in self.observers:
            self.observers[folder].stop()
            del self.observers[folder]

    def _update_status(self, status_text, color_hex, tracked_count=None):
        self.status_val.config(text=status_text, fg=color_hex)
        if tracked_count is not None:
            self.tracked_lbl.config(text=f"Tracked Files: {tracked_count}")

    def get_selected_folder(self) -> str:
        """Get the folder currently selected in the listbox or return first approved folder."""
        sel = self.folder_listbox.curselection()
        if sel:
            return self.folder_listbox.get(sel[0])
        folders = get_approved_folders()
        return folders[0] if folders else None

    def run_ai_check_threaded(self):
        target_dir = self.get_selected_folder()
        if not target_dir:
            messagebox.showwarning("No Folders", "Please add a folder to protect first using 'Add Folder to Protect'.")
            return

        threading.Thread(target=self._execute_full_check, args=(target_dir,), daemon=True).start()

    def _execute_full_check(self, target_dir: str):
        target_dir = os.path.abspath(target_dir)
        self.root.after(0, lambda: self._update_status("⏳ AI CHECK...", "#38bdf8"))
        
        # Clear previous tree items
        self.root.after(0, lambda: self.tree.delete(*self.tree.get_children()))

        old_baseline, _ = load_baseline(target_dir)
        if not old_baseline:
            scan_map = scan_directory(target_dir)
            save_baseline(target_dir, scan_map)
            backup_all_baseline_files(target_dir, scan_map)
            old_baseline = scan_map

        current_scan = scan_directory(target_dir)
        diff_results = compare_scans(old_baseline, current_scan)
        all_changes = diff_results["modified"] + diff_results["new"] + diff_results["moved"] + diff_results["deleted"]

        if not all_changes:
            self.root.after(0, lambda: self._add_info_row(target_dir, "BENIGN", "None", "All files match baseline. Zero integrity anomalies detected.", "NONE"))
            self.root.after(0, lambda: self._update_status("✓ SECURE", "#4ade80", len(current_scan)))
            return

        ml_detector = FIMAnomalyDetector()
        analyst = AnalystAgent()
        verdict_list = []

        has_malicious = False

        for change in all_changes:
            is_anomaly, risk_score, _ = ml_detector.predict(change)
            verdict = analyst.investigate_change(target_dir, change, is_anomaly, risk_score, all_changes)
            verdict_list.append(verdict)

            v_type = verdict.get("verdict", "BENIGN")
            if v_type == "MALICIOUS":
                has_malicious = True

            self.root.after(0, self._add_tree_item, target_dir, verdict)

        # Generate PDF report
        generate_pdf_report(target_dir, verdict_list)

        status_text = "🚨 ALERT" if has_malicious else "✓ SECURE"
        color_hex = "#f87171" if has_malicious else "#4ade80"
        self.root.after(0, lambda: self._update_status(status_text, color_hex, len(current_scan)))

    def _add_info_row(self, target_dir: str, verdict: str, mitre: str, reasoning: str, action: str):
        now_str = time.strftime("%H:%M:%S")
        self.tree.insert(
            "",
            "end",
            values=(now_str, os.path.basename(target_dir), verdict, mitre, reasoning, action),
            tags=(verdict,)
        )

    def _add_tree_item(self, target_dir: str, verdict: dict):
        now_str = time.strftime("%H:%M:%S")
        rel_file = verdict.get("target_file", "")
        v_type = verdict.get("verdict", "BENIGN")
        mitre = verdict.get("mitre_tactic", "None")
        reasoning = verdict.get("reasoning", "")
        action = verdict.get("recommended_action", "none")

        item_id = self.tree.insert(
            "", 
            "end", 
            values=(now_str, f"{os.path.basename(target_dir)}/{rel_file}", v_type, mitre, reasoning, action.upper()),
            tags=(v_type,)
        )
        self.tree.see(item_id)

    def export_pdf_report_action(self):
        folder = self.get_selected_folder()
        if not folder:
            messagebox.showinfo("Info", "No approved folder selected.")
            return

        pdf_path = os.path.join(folder, "fim_incident_report.pdf")
        if not os.path.exists(pdf_path):
            self.run_ai_check_threaded()
            time.sleep(1.5)

        if os.path.exists(pdf_path):
            os.startfile(pdf_path)
            messagebox.showinfo("PDF Exported", f"Exported PDF Incident Report:\n{pdf_path}")

    def trust_baseline_action(self):
        folder = self.get_selected_folder()
        if not folder:
            return
        scan_map = scan_directory(folder)
        save_baseline(folder, scan_map)
        backup_all_baseline_files(folder, scan_map)
        messagebox.showinfo("Baseline Updated", f"Accepted current state of {folder} as new clean baseline.")
        self._update_status("✓ SECURE", "#4ade80", len(scan_map))
        self.run_ai_check_threaded()

    def restore_file_action(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select File", "Please click on a row in the investigation table first.")
            return

        item = self.tree.item(sel[0])
        full_rel = item["values"][1]
        rel_path = full_rel.split("/", 1)[-1]
        folder = self.get_selected_folder()
        if not folder:
            return

        success, msg = restore_file_from_vault(folder, rel_path)
        messagebox.showinfo("Restore File", msg)
        if success:
            self.run_ai_check_threaded()

    def quarantine_file_action(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select File", "Please click on a row in the investigation table first.")
            return

        item = self.tree.item(sel[0])
        full_rel = item["values"][1]
        rel_path = full_rel.split("/", 1)[-1]
        folder = self.get_selected_folder()
        if not folder:
            return

        success, msg = quarantine_file(folder, rel_path)
        messagebox.showinfo("Quarantine File", msg)
        if success:
            self.run_ai_check_threaded()


class GuiFIMWatchHandler(FIMWatchHandler):
    def __init__(self, target_dir: str, baseline_map: dict, app_instance: FIMGuiApp):
        super().__init__(target_dir, baseline_map, auto_approve=True)
        self.app_instance = app_instance

    def process_event(self, event_type: str, src_path: str):
        if is_path_ignored(src_path, self.target_dir):
            return

        rel_path = os.path.relpath(src_path, self.target_dir).replace("\\", "/")
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

        is_anomaly, risk_score, _ = self.ml_detector.predict(change_event)
        verdict = self.analyst.investigate_change(self.target_dir, change_event, is_anomaly, risk_score, [change_event])

        # Dispatch alert
        if verdict.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
            trigger_security_alert(
                target_file=rel_path,
                verdict=verdict.get("verdict"),
                mitre_tactic=verdict.get("mitre_tactic"),
                reasoning=verdict.get("reasoning"),
                recommended_action=verdict.get("recommended_action")
            )

        # Update GUI Treeview safely
        self.app_instance.root.after(0, self.app_instance._add_tree_item, self.target_dir, verdict)


def launch_gui():
    root = tk.Tk()
    app = FIMGuiApp(root)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()

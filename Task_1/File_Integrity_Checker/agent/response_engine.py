"""
Response Engine & Human-in-the-Loop Approval Handler
"""
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from typing import Dict, Any, Tuple

from core.vault import quarantine_file, restore_file_from_vault
from memory.feedback_db import record_user_feedback

def execute_response_action(
    target_dir: str,
    analysis_verdict: Dict[str, Any],
    auto_approve: bool = False
) -> Tuple[str, str]:
    """
    Execute response action (quarantine/restore/alert) with optional human approval.
    Returns (status_result, action_taken).
    """
    target_file = analysis_verdict.get("target_file", "")
    verdict = analysis_verdict.get("verdict", "BENIGN")
    recommended_action = analysis_verdict.get("recommended_action", "none")
    reasoning = analysis_verdict.get("reasoning", "")

    if verdict == "BENIGN" or recommended_action == "none":
        return "SUCCESS", "No action needed (Benign change)."

    print("\n" + "=" * 60)
    print(f"⚠️  SECURITY RESPONDER INTERVENTION REQUIRED")
    print(f"Target File: {target_file}")
    print(f"Verdict: {verdict} | MITRE: {analysis_verdict.get('mitre_tactic')}")
    print(f"Reasoning: {reasoning}")
    print(f"Recommended Action: {recommended_action.upper()}")
    print("=" * 60)

    action_to_take = recommended_action

    if not auto_approve:
        user_choice = input(f"Approve action [{recommended_action.upper()}] for {target_file}? (y/n/false-positive): ").strip().lower()
        
        if user_choice == "false-positive" or user_choice == "fp":
            record_user_feedback(target_file, verdict, is_false_positive=True)
            return "FEEDBACK_LOGGED", "Marked as False Positive. Future alerts for this file will be downgraded."
            
        elif user_choice != 'y' and user_choice != 'yes':
            return "SKIPPED", "Action declined by human operator."

    if action_to_take == "quarantine":
        success, msg = quarantine_file(target_dir, target_file)
        return ("SUCCESS" if success else "FAILED"), msg

    elif action_to_take == "restore":
        success, msg = restore_file_from_vault(target_dir, target_file)
        return ("SUCCESS" if success else "FAILED"), msg

    return "ALERT_ONLY", f"Alert logged for operator review: {target_file}"

# playbook_groupA.py  —  Member 2
# Response Playbook: Group A — Authentication Attacks
# Covers: SSH brute-force, RDP brute-force, PAM failures,
# account lockouts, Kerberos attacks, credential stuffing,
# password spraying

import logging

logger = logging.getLogger(__name__)

PROTECTED_IPS = {
    "192.168.56.1",    # Windows Analyst
    "192.168.56.101",  # Wazuh Manager
    "192.168.56.102",  # Ubuntu Target
}

from config import UBUNTU_TARGET_IP
TARGET_VM_IP = UBUNTU_TARGET_IP

def run_safe_state(alert: dict) -> list:
    """
    Group A response playbook.
    Receives src_ip from main_pipeline.py.
    """

    src_ip = alert.get("src_ip", "0.0.0.0")

    # Missing IP safeguard
    if src_ip in ("0.0.0.0", "N/A", "", None):
        print("[ERROR] No valid source IP found — skipping block.")
        return []

    print(f"[DEBUG] Source IP: {src_ip}")

    # Protected systems → simulation only
    if src_ip in PROTECTED_IPS:

        print(
            f"[SIMULATION] Would block protected IP {src_ip}"
        )

        return [{
            "action": "simulation",
            "target_ip": TARGET_VM_IP,
            "command": f"Would block IP {src_ip}",
            "fix_type": "hardened",
            "reason": (
                f"Protected IP {src_ip} "
                f"not actually blocked"
            ),
            "priority": 1
        }]

    logger.warning(
        f"BRUTE FORCE DETECTED from {src_ip}! "
        f"Returning containment action."
    )

    # Real containment
    return [{
        "action": "block_ip",
        "target_ip": TARGET_VM_IP,
        "command": (
            f"sudo iptables -I INPUT "
            f"-s {src_ip} -j DROP"
        ),
        "fix_type": "hardened",
        "reason": (
            f"SSH brute-force attack "
            f"from {src_ip}"
        ),
        "priority": 1
    }]


def run_playbook_A(alert_or_alerts):
    """
    Compatibility wrapper used by dashboard/pipeline.
    """

    if isinstance(alert_or_alerts, list):
        if not alert_or_alerts:
            return []
        alert = alert_or_alerts[0]
    else:
        alert = alert_or_alerts

    return run_safe_state(alert)


if __name__ == "__main__":

    fake_ip = "192.168.56.30"

    for i in range(3):

        actions = run_safe_state({
            "src_ip": fake_ip,
            "rule_id": 5712
        })

        print(actions)
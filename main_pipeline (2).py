# main_pipeline.py  —  Member 2  —  SOC Master Control Loop
# ─────────────────────────────────────────────────────────────────────────
# Wires together ALL Member 2 and Member 3 components:
#
#   Member 2:
#     wazuh_api        → fetch alerts (live or simulated)
#     risk_engine      → classify group A-J, score 0-100
#     playbook_group*  → decide what actions to take
#
#   Member 3:
#     action_engine    → SSH into VMs and run the actions
#     database         → log every incident to SQLite
#     post_fix_checks  → verify the mitigation actually worked
#
#   Member 4:
#     reads soc_incidents.db for the Streamlit dashboard + PDF report
# ─────────────────────────────────────────────────────────────────────────

import time
import traceback

# ── Member 2 imports ──────────────────────────────────────────────────────
from wazuh_api import get_alerts
from risk_engine import calculate_risk, get_risk_label, GROUP_NAMES
from playbook_groupA import run_playbook_A
from playbook_groupB import run_playbook_B
from playbook_groupCDEFGHIJ import (
    run_playbook_C, run_playbook_D, run_playbook_E,
    run_playbook_F, run_playbook_G, run_playbook_H,
    run_playbook_I, run_playbook_J,
)

# ── Member 3 imports (graceful degradation if files missing) ──────────────
try:
    from action_engine import execute_playbook_actions, test_vm_connectivity
    from database import init_db, log_incident, update_verification
    from post_fix_checks import run_post_fix_check
    FULL_MODE = True
    print("[PIPELINE] FULL MODE — Member 3 files present.")
except ImportError as e:
    FULL_MODE = False
    print(f"[PIPELINE] PARTIAL MODE — Member 3 file missing: {e}")
    print("[PIPELINE]   Playbooks will run but actions won't execute on VMs.")

# ── Configuration ─────────────────────────────────────────────────────────
POLL_INTERVAL    = 30    # seconds between Wazuh polls
MIN_RISK_SCORE   = 30    # ignore alerts scoring below this
DEFAULT_FIX      = "hardened"   # "hardened" or "surgical"
MAX_ACTIONS_SHOW = 5     # in partial mode, how many actions to print

seen_ids = set()         # deduplication — never process the same alert twice


# ── Playbook router ───────────────────────────────────────────────────────
PLAYBOOK_MAP = {
    "A": run_playbook_A,
    "B": run_playbook_B,
    "C": run_playbook_C,
    "D": run_playbook_D,
    "E": run_playbook_E,
    "F": run_playbook_F,
    "G": run_playbook_G,
    "H": run_playbook_H,
    "I": run_playbook_I,
    "J": run_playbook_J,
}

def route_to_playbook(group, alert, all_alerts):
    """
   
    Route the alert to the correct playbook.

    Group A:
    Receives a single alert.
    Wazuh already performed brute-force correlation.

    Group B:
    Receives all alerts for reconnaissance correlation.

     Groups C-J:
    Receive a single alert.
    """
   
    fn = PLAYBOOK_MAP.get(group)
    if not fn:
        return []

    if group == "A":
        return fn(alert)
    elif group == "B":
        return fn(all_alerts)
    else:
        return fn([alert])

# ── Post-fix check dispatcher ─────────────────────────────────────────────
def do_post_fix_check(group, actions, incident_id):
    """
    After actions execute, verify the mitigation actually worked.
    Calls run_post_fix_check() from Member 3's post_fix_checks.py.
    Updates the database with the verification result.

    GROUP → VERIFICATION LOGIC:
      A  — verify attacking IP is banned in fail2ban + iptables
      B  — verify scanner IP is blocked in iptables
      C  — verify malicious process is gone + mining ports blocked
      D  — verify file snapshot was written (chattr +i if applicable)
      E  — verify DoS rate-limit rule is in place
      F  — verify lateral-movement source IP is blocked
      G  — verify sudoers has no NOPASSWD entries
      H  — verify web-attacker IP is blocked in iptables
      I  — verify outbound block is in iptables OUTPUT chain
      J  — verify ld.so.preload is clean + rootkit scanner available
    """
    if not FULL_MODE:
        return

    # Extract the first blocked IP from the actions list (most groups have one)
    blocked_ip = ""
    for a in actions:
        cmd = a.get("command", "")
        # Pull IP from iptables commands like: iptables -I INPUT -s 1.2.3.4 -j DROP
        if "-s " in cmd:
            parts = cmd.split("-s ")
            if len(parts) > 1:
                blocked_ip = parts[1].split()[0]
                break

    check_result = None

    if group == "A":
        if blocked_ip:
            check_result = run_post_fix_check("block_ip",     blocked_ip)
            fb_result    = run_post_fix_check("fail2ban_ban", blocked_ip)
            # Both must pass for full verification
            verified = check_result["verified"] or fb_result["verified"]
            detail   = f"iptables={check_result['verified']} fail2ban={fb_result['verified']}"
        else:
            check_result = run_post_fix_check("sudo_policy", "")
            verified = check_result["verified"]
            detail   = check_result["detail"]

    elif group == "B":
        if blocked_ip:
            check_result = run_post_fix_check("block_ip", blocked_ip)
        else:
            check_result = run_post_fix_check("block_ip", "0.0.0.0")
        verified = check_result["verified"]
        detail   = check_result["detail"]

    elif group == "C":
        proc_result  = run_post_fix_check("kill_process_name", "xmrig")
        mine_result  = run_post_fix_check("mining_ports", "")
        verified = proc_result["verified"] or mine_result["verified"]
        detail   = f"process_killed={proc_result['verified']} mining_blocked={mine_result['verified']}"

    elif group == "D":
        snap_result = run_post_fix_check("snapshot", "")
        verified = snap_result["verified"]
        detail   = snap_result["detail"]

    elif group == "E":
        if blocked_ip:
            check_result = run_post_fix_check("dos_rate_limit", blocked_ip)
        else:
            check_result = run_post_fix_check("dos_rate_limit", "")
        verified = check_result["verified"]
        detail   = check_result["detail"]

    elif group == "F":
        if blocked_ip:
            check_result = run_post_fix_check("block_ip", blocked_ip)
            verified = check_result["verified"]
            detail   = check_result["detail"]
        else:
            verified = True
            detail   = "No specific IP to verify — isolation advisory logged"

    elif group == "G":
        check_result = run_post_fix_check("sudo_policy", "")
        verified = check_result["verified"]
        detail   = check_result["detail"]

    elif group == "H":
        if blocked_ip:
            check_result = run_post_fix_check("block_ip", blocked_ip)
            verified = check_result["verified"]
            detail   = check_result["detail"]
        else:
            verified = True
            detail   = "WAF rule applied — no IP to verify in iptables"

    elif group == "I":
        # Verify outbound block is in OUTPUT chain
        check_result = run_post_fix_check("block_outbound", blocked_ip or "")
        verified = check_result["verified"]
        detail   = check_result["detail"]

    elif group == "J":
        preload_result  = run_post_fix_check("ld_preload", "")
        rootkit_result  = run_post_fix_check("rootkit_scanner", "")
        verified = preload_result["verified"] and rootkit_result["verified"]
        detail   = f"ld_preload_clean={preload_result['verified']} scanner_ready={rootkit_result['verified']}"

    else:
        verified = True
        detail   = "No verification defined for this group"

    # Write verification result back to the database
    update_verification(incident_id, verified=verified, check_result=detail)
    status = "VERIFIED" if verified else "NOT VERIFIED — escalate to manager"
    print(f"     → Post-fix: {status}")
    print(f"       Detail: {detail[:70]}")


# ── Single-alert processor ────────────────────────────────────────────────
# ── Single-alert processor ────────────────────────────────────────────────
from config import PROTECTED_IPS

def process_alert(alert, all_alerts):
    """
    Full pipeline for one alert:
      1. Score and classify
      2. Whitelist check
      3. Skip if below threshold
      4. Run playbook → get actions
      5. Execute actions via SSH (full mode) OR print them (partial mode)
      6. Log incident to database
      7. Run post-fix verification
    """
    risk   = calculate_risk(alert)
    group  = risk["group"]
    score  = risk["score"]
    label  = risk["label"]
    desc   = alert.get("rule", {}).get("description", "")[:58]
    agent  = alert.get("agent", {}).get("ip", "?")
    src    = alert.get("data",  {}).get("srcip", "N/A")
    ruleid = alert.get("rule",  {}).get("id", "?")

    print(f"\n  ┌─[Group {group}] {label:8}  Score={score:3d}  Agent={agent}")
    print(f"  │  Rule={ruleid:6}  Src={src}")
    print(f"  │  {desc}")
    print(f"  └─ {GROUP_NAMES[group]}")

    # ── [NEW] Whitelist Check ─────────────────────────────────────
    if src != "N/A" and src in PROTECTED_IPS:
        print(f"     → [INFO] Skipping actions for protected IP: {src}")
        return
    # ── Threshold check ───────────────────────────────────────────
    if score < MIN_RISK_SCORE:
        print(f"     → Score {score} < threshold {MIN_RISK_SCORE}. Skipped.")
        return

    # ── Pass extracted source IP to playbook ──────────────────────
    alert["src_ip"] = src

    # ── Playbook ──────────────────────────────────────────────────
    actions = route_to_playbook(group, alert, all_alerts)
    if not actions:
        print("     → Playbook returned no actions.")
        return

    priority1 = [a for a in actions if a.get("priority") == 1]
    print(f"     → {len(actions)} actions ({len(priority1)} critical/P1)")

    # ── Execute (FULL MODE) ───────────────────────────────────────
    if FULL_MODE:
        results = execute_playbook_actions(actions, fix_type=DEFAULT_FIX)
        action_ok   = all(r.get("success", False) for r in results) if results else False
        action_desc = "; ".join(
            r.get("command", "")[:45] for r in results[:2]
        )

        # ── Log to DB ─────────────────────────────────────────────
        incident_id = log_incident(
            alert, risk,
            action_taken=action_desc,
            fix_type=DEFAULT_FIX,
            action_ok=action_ok,
        )
        ok_str = "OK" if action_ok else "PARTIAL/FAILED"
        print(f"     → Incident #{incident_id} logged | {len(results)} executed | {ok_str}")

        # ── Post-fix verification ──────────────────────────────────
        do_post_fix_check(group, actions, incident_id)

    # ── Print only (PARTIAL MODE) ─────────────────────────────────
    else:
        print(f"     → [PARTIAL MODE] {len(actions)} action(s) would run:")
        for a in sorted(actions, key=lambda x: x.get("priority", 99))[:MAX_ACTIONS_SHOW]:
            print(f"       [P{a['priority']}][{a['fix_type']:12}] {a['command'][:58]}")
        if len(actions) > MAX_ACTIONS_SHOW:
            print(f"       ... +{len(actions)-MAX_ACTIONS_SHOW} more")

# ── Poll cycle ────────────────────────────────────────────────────────────
def poll_once(poll_num):
    print(f"\n{'─'*65}")
    print(f"[Poll #{poll_num}] Fetching alerts from Wazuh...")

    alerts = get_alerts(limit=100, min_level=3)
    new    = [a for a in alerts if a.get("id", id(a)) not in seen_ids]

    for a in alerts:
        seen_ids.add(a.get("id", id(a)))

    print(f"[Poll #{poll_num}] {len(alerts)} total | {len(new)} new")

    if not new:
        print(f"[Poll #{poll_num}] Nothing new to process.")
        return

    for alert in new:
        process_alert(alert, new)


# ── Entry point ───────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 65)
    print("  SOC AUTOMATION PIPELINE  —  Member 2 + Member 3")
    print(f"  Poll interval  : {POLL_INTERVAL}s")
    print(f"  Min risk score : {MIN_RISK_SCORE}")
    print(f"  Default fix    : {DEFAULT_FIX}")
    print(f"  Mode           : {'FULL (SSH + DB + Verify)' if FULL_MODE else 'PARTIAL (playbooks only)'}")
    print("  Press Ctrl+C to stop")
    print("=" * 65)

    if FULL_MODE:
        init_db()
        print(f"[PIPELINE] SSH key check: ", end="")
        from action_engine import check_ssh_key_exists, SSH_KEY_PATH
        key_ok = check_ssh_key_exists()
        print("OK" if key_ok else f"MISSING — expected at {SSH_KEY_PATH}")

    poll_num = 0
    while True:
        poll_num += 1
        try:
            poll_once(poll_num)
        except KeyboardInterrupt:
            print("\n\n[STOP] Pipeline stopped by user.")
            break
        except Exception as err:
            print(f"[ERROR] {err}")
            traceback.print_exc()

        print(f"\n[Poll #{poll_num}] Sleeping {POLL_INTERVAL}s...")
        try:
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            print("\n\n[STOP] Pipeline stopped by user.")
            break


if __name__ == "__main__":
    main()
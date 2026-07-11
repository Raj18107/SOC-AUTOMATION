# =============================================================
# action_engine.py  —  Member 3  —  SSH Remote Execution Engine
#
# PURPOSE:
#   This is the "Hands" of the SOC. Member 2's playbooks return
#   lists of action dictionaries describing what SHOULD happen.
#   This file makes them actually HAPPEN by SSHing into the
#   Target VM or Wazuh Manager and running the commands.
#
# HOW IT FITS IN:
#   main_pipeline.py
#       → playbook returns actions list
#       → execute_playbook_actions(actions, fix_type)   ← this file
#           → run_remote_command(ip, command)            ← this file
#               → SSH into VM → run command → return result
#
# DEPENDENCY:
#   pip install paramiko
#   SSH key must be set up:  ssh-keygen + ssh-copy-id
#
# WORKS OFFLINE: The self-test checks SSH connectivity to the
#   Target VM. Set TARGET_VM_IP to your VM's actual IP.
# =============================================================

import paramiko
import os
import time
import datetime
import socket

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────

# Path to your SSH private key.
# This key must be copied to the Target VM's authorized_keys.
# Windows path uses raw string (r"...") to handle backslashes.
if os.name == "nt":   # Windows
    SSH_KEY_PATH = os.path.expanduser(r"~\.ssh\soc_key")
else:                 # Mac / Linux
    SSH_KEY_PATH = os.path.expanduser(r"~/.ssh/soc_key")

# The Linux  on your Target VM and Wazuh Manager
SSH_USERNAME = "targetuser"

# IPs of your VMs (used by the self-test and verification)
from config import UBUNTU_TARGET_IP, WAZUH_MANAGER_IP
TARGET_VM_IP  = UBUNTU_TARGET_IP
MANAGER_VM_IP = WAZUH_MANAGER_IP

# How many seconds to wait before giving up on a connection
SSH_CONNECT_TIMEOUT = 10

# How many seconds to wait for a command to finish
COMMAND_TIMEOUT = 30


# ─────────────────────────────────────────────────────────────
# CORE FUNCTION: run_remote_command
# ─────────────────────────────────────────────────────────────

def run_remote_command(target_ip, command, timeout=COMMAND_TIMEOUT):
    """
    SSH into target_ip and run command.

    HOW IT WORKS:
    1. Create a new SSH connection using your private key
    2. Send the command to the remote machine
    3. Read stdout (normal output) and stderr (error output)
    4. Get the exit code (0 = success, anything else = failure)
    5. Close the connection
    6. Return everything as a dictionary

    Parameters:
        target_ip  — IP address of the VM to connect to
        command    — the exact Linux shell command to run
                     e.g. "sudo iptables -I INPUT 1 -s 1.2.3.4 -j DROP"
        timeout    — seconds to wait before giving up

    Returns a dict:
    {
        "command":   "sudo iptables ...",
        "output":    "the command's normal output (stdout)",
        "error":     "any error text (stderr)",
        "exit_code": 0,     # 0 = OK, non-zero = something failed
        "success":   True,  # True only when exit_code == 0
        "target":    "192.168.56.20",
        "timestamp": "2024-01-15T10:30:00",
    }
    """
    # Create a new SSH client object
    ssh = paramiko.SSHClient()

    # AutoAddPolicy: automatically accept the remote host's key fingerprint
    # on first connection. This avoids the interactive "yes/no" prompt
    # that would block automation.
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    timestamp = datetime.datetime.now().isoformat(timespec="seconds")

    try:
        # Connect to the target machine using the SSH key (no password)
        ssh.connect(
            hostname=target_ip,
            username="wazuh-user" if target_ip == MANAGER_VM_IP else SSH_USERNAME,
            key_filename=SSH_KEY_PATH,
            timeout=SSH_CONNECT_TIMEOUT,
            look_for_keys=False,   # only use our specific key
            allow_agent=False,     # don't use SSH agent
        )

        # Send the command.
        # exec_command returns three "stream" objects:
        #   stdin  — for sending input (we don't need this)
        #   stdout — normal command output
        #   stderr — error output
        stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)

        # .read() gets all the bytes, .decode() converts to text,
        # .strip() removes leading/trailing whitespace and newlines
        output   = stdout.read().decode("utf-8", errors="replace").strip()
        error    = stderr.read().decode("utf-8", errors="replace").strip()

        # recv_exit_status() waits for the command to fully finish
        # and returns its exit code. 0 means success.
        exit_code = stdout.channel.recv_exit_status()

        return {
            "command":   command,
            "output":    output,
            "error":     error,
            "exit_code": exit_code,
            "success":   (exit_code == 0),
            "target":    target_ip,
            "timestamp": timestamp,
        }

    except paramiko.AuthenticationException:
        return {
            "command":   command,
            "output":    "",
            "error":     (
                f"SSH authentication failed for {target_ip}.\n"
                "Fix: Check that your SSH key was copied correctly.\n"
                "Run: ssh-copy-id -i ~/.ssh/soc_key.pub ubuntu@" + target_ip
            ),
            "exit_code": -1,
            "success":   False,
            "target":    target_ip,
            "timestamp": timestamp,
        }

    except (paramiko.ssh_exception.NoValidConnectionsError, socket.error, OSError) as e:
        return {
            "command":   command,
            "output":    "",
            "error":     (
                f"Cannot connect to {target_ip}: {e}\n"
                "Fix 1: Is the VM running? Check VirtualBox.\n"
                "Fix 2: Is SSH running? On VM: sudo systemctl start ssh\n"
                "Fix 3: Can you ping the VM? ping " + target_ip
            ),
            "exit_code": -2,
            "success":   False,
            "target":    target_ip,
            "timestamp": timestamp,
        }

    except Exception as e:
        return {
            "command":   command,
            "output":    "",
            "error":     f"Unexpected error: {type(e).__name__}: {e}",
            "exit_code": -3,
            "success":   False,
            "target":    target_ip,
            "timestamp": timestamp,
        }

    finally:
        # ALWAYS close the SSH connection, even if an error occurred.
        # "finally" runs no matter what happens above.
        try:
            ssh.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# CORE FUNCTION: execute_playbook_actions
# ─────────────────────────────────────────────────────────────

def execute_playbook_actions(actions, fix_type="hardened"):
    """
    Run a list of action dicts returned by any playbook.

    Member 2's playbooks return lists like:
    [
        {
            "fix_type": "hardened",
            "command":  "sudo iptables -I INPUT 1 -s 1.2.3.4 -j DROP",
            "priority": 1,
            "reason":   "Block port scanner",
            "target_ip": "192.168.56.20",   # optional, defaults to TARGET_VM_IP
        },
        ...
    ]

    This function:
    1. Filters to only actions matching fix_type
       ("hardened" = permanent, "surgical" = targeted)
    2. Sorts by priority (lower number = run first)
    3. Runs each command on the appropriate VM via SSH
    4. Returns a list of result dicts

    Parameters:
        actions  — list of action dicts from a playbook
        fix_type — "hardened" or "surgical"
                   Member 4's dashboard lets the Security Manager choose.
                   For automatic responses, DEFAULT_FIX in pipeline = "hardened"

    Returns:
        List of result dicts (one per action executed)
    """
    # Filter: only keep actions of the selected fix_type
    # Some action dicts use "fix_type" containing the type name,
    # others use it as a category. We match both ways.
    chosen = [
        a for a in actions
        if (a.get("fix_type", "") == fix_type or
            fix_type in a.get("fix_type", ""))
    ]

    if not chosen:
        print(f"    [ACTION ENGINE] No '{fix_type}' actions to execute.")
        return []

    # Sort by priority so critical actions run first
    chosen.sort(key=lambda x: x.get("priority", 99))

    results = []

    for action in chosen:
        command   = action.get("command", "")
        target_ip = action.get("target_ip", TARGET_VM_IP)
        fix       = action.get("fix_type", fix_type)
        reason    = action.get("reason", "")
        priority  = action.get("priority", 99)
         # ─────────────────────────────────────────────
        # SIMULATION ACTIONS
        # Used when we want to demonstrate what would
        # happen without actually modifying the target.
        # ─────────────────────────────────────────────
        if action.get("action") == "simulation":

            print(f"    [SIMULATION] {command}")
            print(f"                 WHY: {reason[:65]}")

            result = {
                "command": command,
                "output": f"SIMULATED: {command}",
                "error": "",
                "exit_code": 0,
                "success": True,
                "target": target_ip,
                "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
                "simulation": True,
            }

            result["action"] = action.get("action", "simulation")
            result["priority"] = priority
            result["reason"] = reason

            results.append(result)

            continue
        if not command:
            continue

        print(f"    [ACTION] P{priority} [{fix:12}] on {target_ip}")
        print(f"             CMD: {command[:70]}")
        print(f"             WHY: {reason[:65]}")

        # Some commands are "advisory" — they describe what to do
        # but cannot be run automatically (e.g. "rebuild_host", "enable_mfa")
        # We detect these by checking if they start with known non-shell prefixes
        advisory_prefixes = (
            "send_soc_alert", "isolate_host", "check_threat_intel",
            "enable_mfa", "rebuild_host", "restore_from_backup",
            "trigger_breach_notification", "enable_dlp", "deploy_edr",
            "configure_ids", "firewall_rule", "enforce_ssh_policy",
            "enable_secure_boot", "configure_port_knocking",
            "collect_forensics", "run_av_scan", "run_rootkit_scanner",
            "list_kernel_modules", "audit_cron", "audit_startup_scripts",
            "apply_application_whitelist", "network_block",
            "trigger_emergency_backup", "capture_traffic",
            "scan_open_ports", "honeypot_redirect", "log_event",
        )
        is_advisory = any(command.strip().startswith(p) for p in advisory_prefixes)

        if is_advisory:
            # Log it but don't SSH-execute it
            result = {
                "command":   command,
                "output":    "[ADVISORY] Logged — requires manual/external tool",
                "error":     "",
                "exit_code": 0,
                "success":   True,
                "target":    target_ip,
                "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
                "advisory":  True,
            }
            print(f"             ADVISORY — logged, not auto-executed")
        else:
            # Actually run it via SSH
            result = run_remote_command(target_ip, command)
            status = "SUCCESS" if result["success"] else "FAILED"
            detail = result["output"] or result["error"] or "(no output)"
            print(f"             {status}: {detail[:80]}")

        result["action"]   = action.get("fix_type", "unknown")
        result["priority"] = priority
        result["reason"]   = reason
        results.append(result)

        # Small delay between commands to avoid overwhelming the VM
        time.sleep(0.3)

    return results


# ─────────────────────────────────────────────────────────────
# HELPER: check_ssh_key_exists
# ─────────────────────────────────────────────────────────────

def check_ssh_key_exists():
    """
    Return True if the SSH private key file exists.
    Used at startup to give a helpful error message if key is missing.
    """
    return os.path.isfile(SSH_KEY_PATH)


# ─────────────────────────────────────────────────────────────
# HELPER: test_vm_connectivity
# ─────────────────────────────────────────────────────────────

def test_vm_connectivity(ip):
    """
    Quick check: can we open a TCP connection to port 22 (SSH) on this IP?
    Returns True if reachable, False if not.
    Does NOT do a full SSH login — just tests network reachability.
    """
    try:
        sock = socket.create_connection((ip, 22), timeout=5)
        sock.close()
        return True
    except (socket.timeout, socket.error, OSError):
        return False


# ─────────────────────────────────────────────────────────────
# SELF-TEST
# Run:  python action_engine.py
# Tests real SSH connectivity to the Target VM.
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 65)
    print("  action_engine.py — Self-Test")
    print("=" * 65)
    print()

    # ── Pre-flight checks ─────────────────────────────────────────
    print("Pre-flight checks:")

    # Check SSH key exists
    key_ok = check_ssh_key_exists()
    print(f"  SSH key exists at {SSH_KEY_PATH}: {key_ok}")
    if not key_ok:
        print()
        print("  SETUP NEEDED: Generate an SSH key pair:")
        print("  Windows:   ssh-keygen -t rsa -b 4096 -f %USERPROFILE%\\.ssh\\soc_key -N \"\"")
        print("  Mac/Linux: ssh-keygen -t rsa -b 4096 -f ~/.ssh/soc_key -N \"\"")
        print()
        print("  Then copy to Target VM:")
        print("  Mac/Linux: ssh-copy-id -i ~/.ssh/soc_key.pub ubuntu@192.168.56.20")
        print("  Windows:   see guide for manual copy steps")
        print()
        print("  Cannot continue without SSH key. Exiting.")
        exit(1)

    # Check network reachability
    reachable = test_vm_connectivity(TARGET_VM_IP)
    print(f"  Target VM {TARGET_VM_IP} reachable on port 22: {reachable}")
    if not reachable:
        print()
        print(f"  Cannot reach {TARGET_VM_IP}.")
        print("  Fix 1: Is the Target VM running in VirtualBox?")
        print("  Fix 2: Start the VM and try again.")
        print("  Continuing with limited tests...")
        print()

    print()

    if not reachable:
        print("Skipping SSH tests — Target VM not reachable.")
        print("Start the VM and re-run this test.")
        exit(0)

    # ── Test 1: Basic SSH connection ──────────────────────────────
    print("─── Test 1: Basic SSH connection ───")
    r = run_remote_command(TARGET_VM_IP, "whoami")
    if r["success"]:
        print(f"  PASS — Connected as user: {r['output']}")
    else:
        print(f"  FAIL — {r['error']}")
        exit(1)

    # ── Test 2: Several safe read-only commands ───────────────────
    print("\n─── Test 2: Safe read-only commands ───")
    safe_commands = [
        ("hostname",          "Get machine hostname"),
        ("uptime",            "How long VM has been running"),
        ("free -h | head -2", "Memory usage"),
        ("df -h | head -3",   "Disk usage"),
        ("ip addr show | grep 'inet ' | head -3", "IP addresses"),
    ]
    for cmd, desc in safe_commands:
        r = run_remote_command(TARGET_VM_IP, cmd)
        status = "PASS" if r["success"] else "FAIL"
        output = r["output"].split("\n")[0][:55]  # first line only
        print(f"  {status} — {desc}: {output}")

    # ── Test 3: Check iptables rules (requires sudo) ──────────────
    print("\n─── Test 3: Check current firewall rules ───")
    r = run_remote_command(TARGET_VM_IP, "sudo iptables -L INPUT -n --line-numbers | head -10")
    if r["success"]:
        print(f"  PASS — iptables accessible. Current INPUT rules:")
        for line in r["output"].split("\n")[:5]:
            print(f"    {line}")
    else:
        print(f"  FAIL — {r['error']}")
        print("  Fix: Add ubuntu to sudoers or run visudo to allow passwordless sudo")

    # ── Test 4: execute_playbook_actions with sample actions ──────
    print("\n─── Test 4: execute_playbook_actions (safe test) ───")
    sample_actions = [
        {
            "fix_type": "hardened",
            "command":  "sudo iptables -L INPUT -n --line-numbers | wc -l",
            "priority": 1,
            "reason":   "Count existing firewall rules (safe read-only test)",
            "target_ip": TARGET_VM_IP,
        },
        {
            "fix_type": "hardened",
            "command":  "cat /var/log/auth.log | tail -3",
            "priority": 2,
            "reason":   "Read last 3 lines of auth log (safe read-only)",
            "target_ip": TARGET_VM_IP,
        },
        # This one is advisory — should NOT be executed via SSH
        {
            "fix_type": "hardened",
            "command":  "send_soc_alert --level INFO --msg 'Test alert'",
            "priority": 3,
            "reason":   "Advisory action — should be logged, not executed",
            "target_ip": TARGET_VM_IP,
        },
    ]

    results = execute_playbook_actions(sample_actions, fix_type="hardened")

    print(f"\n  Results: {len(results)} actions processed")
    for res in results:
        status = "PASS" if res["success"] else "FAIL"
        adv    = " (ADVISORY)" if res.get("advisory") else ""
        print(f"  {status}{adv} — exit_code={res['exit_code']}  {res['command'][:50]}")

    # ── Test 5: Test Wazuh Manager connection ─────────────────────
    print("\n─── Test 5: Can we reach Wazuh Manager? ───")
    mgr_reachable = test_vm_connectivity(MANAGER_VM_IP)
    if mgr_reachable:
        r = run_remote_command(MANAGER_VM_IP, "sudo systemctl status wazuh-manager --no-pager | head -3")
        if r["success"]:
            print(f"  PASS — Wazuh Manager reachable. Status:")
            for line in r["output"].split("\n")[:3]:
                print(f"    {line}")
        else:
            print(f"  PARTIAL — Reached manager but SSH failed: {r['error']}")
    else:
        print(f"  SKIP — Wazuh Manager {MANAGER_VM_IP} not reachable (OK if on Laptop A)")

    print()
    print("=" * 65)
    print("  action_engine.py self-test complete!")
    print("  If Tests 1-4 show PASS, action_engine.py is ready.")
    print("=" * 65)

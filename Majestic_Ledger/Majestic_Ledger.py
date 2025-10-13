#!/usr/bin/env python3
"""
Majestic_Ledger.py  (v1.3)

Scan hosts (Linux via ssh, Windows via WinRM), compare against baseline,
and interactively request approval to remediate out-of-baseline local accounts.

- Dry-run by default.
- Pass --execute to allow remediation actions to be run.
- Even with --execute, for each action you must type a specific APPROVE string.

v1.1:
- Discover actual hostname from targets and optionally write it back to baseline
  (--update-hostnames, optional --baseline-out).

v1.2:
- Retry logic: Try up to 3 times per host before skipping.
- Log unreachable hosts to remediation_log_UTC.jsonl.

v1.3:
- Password rotation for *allowed_users* local accounts:
  --rotate-passwords [--password-file PATH] [--pw-length N]
  - Linux: chpasswd via stdin
  - Windows: Set-LocalUser with SecureString
  - Per-account explicit approval (APPROVE ROTATE)
  - Passwords saved locally to CSV; never printed to console
"""
import json, argparse, subprocess, shlex, sys, os, datetime, getpass, time, secrets, string, csv, stat
from typing import List, Dict, Any, Optional

try:
    import winrm
    HAVE_WINRM = True
except Exception:
    HAVE_WINRM = False

LOG_PATH = "remediation_log_UTC.jsonl"
MAX_ATTEMPTS = 3
RETRY_DELAY_SEC = 5

def log_entry(entry: Dict[str, Any]):
    entry["logged_at_utc"] = datetime.datetime.utcnow().isoformat() + "Z"
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

def load_baseline(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def lowercase_set(lst):
    return set([s.lower() for s in lst])

def with_retries(func, *, max_attempts=MAX_ATTEMPTS, delay=RETRY_DELAY_SEC, err_is_retry=lambda r: False, **kwargs):
    last_result = None
    for attempt in range(1, max_attempts + 1):
        try:
            result = func(**kwargs)
            if err_is_retry(result):
                print(f"  Attempt {attempt}/{max_attempts} failed: {result[0] if isinstance(result, list) else result}")
                last_result = result
            else:
                return result
        except Exception as e:
            print(f"  Attempt {attempt}/{max_attempts} exception: {e}")
            last_result = [{"error": "exception", "detail": str(e)}]
        if attempt < max_attempts:
            time.sleep(delay)
    print(f"  Host unreachable after {max_attempts} tries. Skipping.")
    return last_result or [{"error": "unreachable"}]

def looks_like_error_list(x):
    return isinstance(x, list) and x and isinstance(x[0], dict) and "error" in x[0]

def enum_linux_users_via_ssh(ip: str, ssh_user: Optional[str] = None, ssh_key: Optional[str] = None, extra_opts: str = "") -> List[Dict[str,Any]]:
    userinfo = []
    ssh_target = f"{ssh_user}@{ip}" if ssh_user else ip
    cmd = "getent passwd || cat /etc/passwd"
    ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if ssh_key:
        ssh_cmd += ["-i", os.path.expanduser(ssh_key)]
    if extra_opts:
        ssh_cmd += shlex.split(extra_opts)
    ssh_cmd += [ssh_target, cmd]
    try:
        proc = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        out = proc.stdout.strip()
        if not out:
            raise RuntimeError(f"Empty response from {ip}: {proc.stderr.strip()}")
        for line in out.splitlines():
            if not line.strip() or line.startswith(("#")):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                username, passwd, uid, gid, gecos, home, shell = parts[:7]
                userinfo.append({
                    "username": username,
                    "uid": int(uid) if uid.isdigit() else None,
                    "gid": int(gid) if gid.isdigit() else None,
                    "home": home,
                    "shell": shell
                })
    except Exception as e:
        return [{"error":"ssh_error","detail":str(e)}]
    return userinfo

def enum_windows_users_via_winrm(ip: str, winrm_user: str, winrm_pass: str, transport: str = "ntlm") -> List[Dict[str,Any]]:
    if not HAVE_WINRM:
        return [{"error":"pywinrm_not_installed"}]
    try:
        session = winrm.Session(target=ip, auth=(winrm_user, winrm_pass), transport=transport)
        ps = r"Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json -Compress"
        r = session.run_ps(ps)
        if r.status_code != 0:
            return [{"error":"winrm_error","detail":r.std_err.decode('utf-8', errors='ignore')}]
        txt = r.std_out.decode('utf-8', errors='ignore').strip()
        if not txt:
            return [{"error":"winrm_empty_output"}]
        data = json.loads(txt)
        users = []
        if isinstance(data, dict):
            data = [data]
        for u in data:
            users.append({"username": u.get("Name"), "enabled": u.get("Enabled", True)})
        return users
    except Exception as e:
        return [{"error":"winrm_exception","detail":str(e)}]

def get_linux_hostname_via_ssh(ip: str, ssh_user: Optional[str] = None, ssh_key: Optional[str] = None, extra_opts: str = "") -> Optional[str]:
    ssh_target = f"{ssh_user}@{ip}" if ssh_user else ip
    cmd = "hostnamectl --static 2>/dev/null || hostname"
    ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if ssh_key:
        ssh_cmd += ["-i", os.path.expanduser(ssh_key)]
    if extra_opts:
        ssh_cmd += shlex.split(extra_opts)
    ssh_cmd += [ssh_target, cmd]
    try:
        proc = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        hn = proc.stdout.strip().splitlines()[0].strip() if proc.stdout else ""
        return hn or None
    except Exception:
        return None

def get_windows_hostname_via_winrm(ip: str, winrm_user: str, winrm_pass: str, transport: str = "ntlm") -> Optional[str]:
    if not HAVE_WINRM:
        return None
    try:
        session = winrm.Session(target=ip, auth=(winrm_user, winrm_pass), transport=transport)
        r = session.run_ps("[Environment]::MachineName")
        if r.status_code == 0:
            return r.std_out.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    return None

def linux_disable_user_via_ssh(ip: str, user_to_disable: str, ssh_user: Optional[str] = None, ssh_key: Optional[str] = None) -> Dict[str,Any]:
    target = f"{ssh_user}@{ip}" if ssh_user else ip
    ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if ssh_key:
        ssh_cmd += ["-i", os.path.expanduser(ssh_key)]
    cmd = f"sudo usermod -L {shlex.quote(user_to_disable)} && sudo chage -E 0 {shlex.quote(user_to_disable)} && (sudo usermod -s /usr/sbin/nologin {shlex.quote(user_to_disable)} || true)"
    ssh_cmd += [target, cmd]
    try:
        proc = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        return {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as e:
        return {"error":"ssh_exec_exception", "detail": str(e)}

def linux_delete_user_via_ssh(ip: str, user_to_delete: str, ssh_user: Optional[str] = None, ssh_key: Optional[str] = None) -> Dict[str,Any]:
    target = f"{ssh_user}@{ip}" if ssh_user else ip
    ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if ssh_key:
        ssh_cmd += ["-i", os.path.expanduser(ssh_key)]
    cmd = f"sudo userdel {shlex.quote(user_to_delete)}"
    ssh_cmd += [target, cmd]
    try:
        proc = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        return {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as e:
        return {"error":"ssh_exec_exception", "detail": str(e)}

def windows_disable_local_user_via_winrm(ip: str, winrm_user: str, winrm_pass: str, user_to_disable: str, transport: str = "ntlm"):
    if not HAVE_WINRM:
        return {"error":"pywinrm_not_installed"}
    try:
        session = winrm.Session(target=ip, auth=(winrm_user, winrm_pass), transport=transport)
        ps = f"""
try {{
  if (Get-Command -Name Disable-LocalUser -ErrorAction SilentlyContinue) {{
    Disable-LocalUser -Name "{user_to_disable}"
  }} else {{
    net user "{user_to_disable}" /active:no
  }}
  Write-Output "OK"
}} catch {{
  Write-Output "ERR: $($_.Exception.Message)"
  exit 1
}}
"""
        r = session.run_ps(ps)
        return {"rc": r.status_code, "stdout": r.std_out.decode('utf-8', errors='ignore'), "stderr": r.std_err.decode('utf-8', errors='ignore')}
    except Exception as e:
        return {"error":"winrm_exception", "detail":str(e)}

def windows_delete_local_user_via_winrm(ip: str, winrm_user: str, winrm_pass: str, user_to_delete: str, transport: str = "ntlm"):
    if not HAVE_WINRM:
        return {"error":"pywinrm_not_installed"}
    try:
        session = winrm.Session(target=ip, auth=(winrm_user, winrm_pass), transport=transport)
        ps = f"""
try {{
  Remove-LocalUser -Name "{user_to_delete}"
  Write-Output "OK"
}} catch {{
  Write-Output "ERR: $($_.Exception.Message)"
  exit 1
}}
"""
        r = session.run_ps(ps)
        return {"rc": r.status_code, "stdout": r.std_out.decode('utf-8', errors='ignore'), "stderr": r.std_err.decode('utf-8', errors='ignore')}
    except Exception as e:
        return {"error":"winrm_exception", "detail":str(e)}

def gen_password(length: int = 24) -> str:
    alphabet = (string.ascii_letters + string.digits + "!@#$%^&*()_-+=[]{}:,./?")
    return "".join(secrets.choice(alphabet) for _ in range(length))

def init_password_file(path: str):
    new_file = not os.path.exists(path)
    try:
        os.umask(0o177)
    except Exception:
        pass
    if new_file:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["time_utc","host","ip","platform","username","password"])
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

def write_password_record(path: str, host: str, ip: str, platform: str, username: str, password: str):
    with open(path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([datetime.datetime.utcnow().isoformat()+"Z", host, ip, platform, username, password])

def linux_set_password_via_ssh(ip: str, account: str, new_password: str, ssh_user: Optional[str]=None, ssh_key: Optional[str]=None) -> Dict[str,Any]:
    target = f"{ssh_user}@{ip}" if ssh_user else ip
    cmd = "sudo chpasswd"
    ssh_cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if ssh_key:
        ssh_cmd += ["-i", os.path.expanduser(ssh_key)]
    ssh_cmd += [target, cmd]
    try:
        to_send = f"{account}:{new_password}\n"
        proc = subprocess.run(ssh_cmd, input=to_send, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        return {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as e:
        return {"error":"ssh_exec_exception", "detail": str(e)}

def windows_set_password_via_winrm(ip: str, winrm_user: str, winrm_pass: str, account: str, new_password: str, transport: str="ntlm") -> Dict[str,Any]:
    if not HAVE_WINRM:
        return {"error":"pywinrm_not_installed"}
    try:
        session = winrm.Session(target=ip, auth=(winrm_user, winrm_pass), transport=transport)
        ps = f"""
$u = "{account}"
$pw = "{new_password}"
try {{
  $sec = ConvertTo-SecureString -String $pw -AsPlainText -Force
  if (Get-Command -Name Set-LocalUser -ErrorAction SilentlyContinue) {{
    Set-LocalUser -Name $u -Password $sec
  }} else {{
    net user "$u" "$pw"
  }}
  Write-Output "OK"
}} catch {{
  Write-Output ("ERR: " + $_.Exception.Message)
  exit 1
}}
"""
        r = session.run_ps(ps)
        return {"rc": r.status_code, "stdout": r.std_out.decode('utf-8', errors='ignore'), "stderr": r.std_err.decode('utf-8', errors='ignore')}
    except Exception as e:
        return {"error":"winrm_exception","detail":str(e)}

def interactive_prompt(prompt_text: str) -> str:
    try:
        return input(prompt_text).strip()
    except EOFError:
        return ""

def inspect_host_and_prompt(host: Dict[str,Any], discovered_users: List[Dict[str,Any]], baseline_allowed: set, global_opts: Dict[str,Any]):
    ip = host.get("ip")
    name = host.get("hostname")
    platform = host.get("platform", "").lower()
    per_host_ssh = host.get("ssh", {}) or {}
    per_host_winrm = host.get("winrm", {}) or {}
    print(f"\n=== Host: {name} ({ip}) platform={platform} ===")

    disc_usernames = []
    for entry in discovered_users:
        if isinstance(entry, dict) and "error" in entry:
            continue
        uname = (entry.get("username") or entry.get("Name") or "").strip()
        if uname:
            disc_usernames.append(uname)

    for uname in sorted(set(disc_usernames), key=lambda s: s.lower()):
        allowed_on_host = uname.lower() in baseline_allowed
        if allowed_on_host:
            continue
        print(f"\nOUT-OF-BASELINE: Host={name} IP={ip} User={uname}")
        ent = next((e for e in discovered_users if isinstance(e, dict) and e.get("username","").lower()==uname.lower()), {})
        enrichment = []
        if ent.get("uid") is not None: enrichment.append(f"uid={ent.get('uid')}")
        if ent.get("enabled") is not None: enrichment.append(f"enabled={ent.get('enabled')}")
        if ent.get("home"): enrichment.append(f"home={ent.get('home')}")
        print("  details:", ", ".join(enrichment) if enrichment else "(none)")
        print("  baseline allowed users:", sorted(list(baseline_allowed))[:10])
        print("Actions: [s]kip, [d]isable_local, [q]uarantine_local, [r]emove_local, [v]iew_raw")
        action = interactive_prompt("Choose action (s/d/q/r/v) [s]: ") or "s"
        if action.lower() == "v":
            print("raw discovery entry:", json.dumps(ent, indent=2))
            action = interactive_prompt("Now choose action (s/d/q/r) [s]: ") or "s"
        if action.lower() == "s":
            log_entry({"host": name, "ip": ip, "username": uname, "action": "skipped", "operator": getpass.getuser()})
            print("skipped.")
            continue

        map_act = {"d":"disable", "q":"quarantine", "r":"delete"}
        if action.lower() not in map_act:
            print("unknown choice; skipping.")
            log_entry({"host": name, "ip": ip, "username": uname, "action": "skip_unknown", "operator": getpass.getuser()})
            continue

        chosen = map_act[action.lower()]
        print(f"Selected: {chosen} for {uname} on {name} ({ip}).")
        if not global_opts.get("execute"):
            print("DRY-RUN: no action performed (use --execute to permit).")
            log_entry({"host": name, "ip": ip, "username": uname, "action": f"selected_{chosen}_dryrun", "operator": getpass.getuser()})
            continue

        approve_str = interactive_prompt(f"To perform this action, type: APPROVE {chosen} (case-sensitive): ")
        if approve_str != f"APPROVE {chosen}":
            print("Approval string mismatch; aborting action for this account.")
            log_entry({"host": name, "ip": ip, "username": uname, "action": f"approval_failed_{chosen}", "operator": getpass.getuser()})
            continue

        result = {"not_executed": True}
        if platform == "linux":
            ssh_user = global_opts.get("ssh_user") or per_host_ssh.get("user")
            ssh_key = per_host_ssh.get("ssh_key") or global_opts.get("ssh_key")
            if chosen == "disable":
                result = linux_disable_user_via_ssh(ip, uname, ssh_user=ssh_user, ssh_key=ssh_key)
            elif chosen == "delete":
                confirm = interactive_prompt("Final confirm: DELETE will remove the account (type DELETE_NOW): ")
                if confirm == "DELETE_NOW":
                    result = linux_delete_user_via_ssh(ip, uname, ssh_user=ssh_user, ssh_key=ssh_key)
                else:
                    print("Delete not confirmed; skipping.")
                    log_entry({"host": name, "ip": ip, "username": uname, "action": "delete_not_confirmed", "operator": getpass.getuser()})
                    continue
            elif chosen == "quarantine":
                result = linux_disable_user_via_ssh(ip, uname, ssh_user=ssh_user, ssh_key=ssh_key)

        elif platform == "windows":
            winrm_user = global_opts.get("winrm_user") or per_host_winrm.get("user")
            winrm_pass = global_opts.get("winrm_pass") or per_host_winrm.get("password")
            if not (winrm_user and winrm_pass):
                print("No WinRM credentials for this host; cannot remediate. Skipping.")
                log_entry({"host": name, "ip": ip, "username": uname, "action": "no_winrm_creds", "operator": getpass.getuser()})
                continue
            if chosen in ("disable", "quarantine"):
                result = windows_disable_local_user_via_winrm(ip, winrm_user, winrm_pass, uname)
            elif chosen == "delete":
                confirm = interactive_prompt("Final confirm: DELETE will remove the local account (type DELETE_NOW): ")
                if confirm == "DELETE_NOW":
                    result = windows_delete_local_user_via_winrm(ip, winrm_user, winrm_pass, uname)
                else:
                    print("Delete not confirmed; skipping.")
                    log_entry({"host": name, "ip": ip, "username": uname, "action": "delete_not_confirmed", "operator": getpass.getuser()})
                    continue
        else:
            print(f"Unknown platform {platform}; skipping remediation.")
            log_entry({"host": name, "ip": ip, "username": uname, "action": "unsupported_platform", "platform": platform, "operator": getpass.getuser()})
            continue

        print("Action result:", result)
        log_entry({"host": name, "ip": ip, "username": uname, "action": chosen, "result": result, "operator": getpass.getuser()})

def rotate_allowed_users_for_host(host: Dict[str,Any], global_opts: Dict[str,Any], pw_len: int, pw_file: str):
    ip = host.get("ip")
    name = host.get("hostname")
    platform = (host.get("platform") or "").lower()
    allowed_users = host.get("allowed_users", []) or []

    if not allowed_users:
        return

    print(f"\n*** Password rotation on {name} ({ip}) [{platform}] for {len(allowed_users)} allowed user(s) ***")

    if not global_opts.get("execute"):
        print("DRY-RUN: Rotation requested but --execute not set. No changes will be made.")
        return

    for acct in allowed_users:
        acct = acct.strip()
        if not acct:
            continue

        prompt = f"Rotate password for '{acct}' on {name}? Type: APPROVE ROTATE  (or press Enter to skip): "
        if interactive_prompt(prompt) != "APPROVE ROTATE":
            print(f"  Skipped {acct}.")
            log_entry({"host": name, "ip": ip, "username": acct, "action": "rotate_skipped", "operator": getpass.getuser()})
            continue

        new_pw = gen_password(pw_len)

        result = None
        if platform == "linux":
            ssh_user = (host.get("ssh") or {}).get("user") or global_opts.get("ssh_user")
            ssh_key  = (host.get("ssh") or {}).get("ssh_key") or global_opts.get("ssh_key")
            result = linux_set_password_via_ssh(ip, acct, new_pw, ssh_user=ssh_user, ssh_key=ssh_key)
        elif platform == "windows":
            winrm_user = (host.get("winrm") or {}).get("user") or global_opts.get("winrm_user")
            winrm_pass = (host.get("winrm") or {}).get("password") or global_opts.get("winrm_pass")
            if not (winrm_user and winrm_pass):
                print("  No WinRM creds for this host; cannot rotate.")
                log_entry({"host": name, "ip": ip, "username": acct, "action": "rotate_no_winrm_creds", "operator": getpass.getuser()})
                continue
            result = windows_set_password_via_winrm(ip, winrm_user, winrm_pass, acct, new_pw)
        else:
            print(f"  Unsupported platform {platform}; skipping.")
            log_entry({"host": name, "ip": ip, "username": acct, "action": "rotate_unsupported_platform", "platform": platform, "operator": getpass.getuser()})
            continue

        ok = isinstance(result, dict) and result.get("rc", 1) == 0 and "error" not in result
        if ok:
            write_password_record(pw_file, name, ip, platform, acct, new_pw)
            print(f"  Rotated {acct} ✔ (saved to {pw_file})")
            log_entry({"host": name, "ip": ip, "username": acct, "action": "password_rotated", "result": {"rc": result.get("rc", 0)}})
        else:
            print(f"  Rotation failed for {acct}: {result}")
            log_entry({"host": name, "ip": ip, "username": acct, "action": "password_rotate_failed", "result": result, "operator": getpass.getuser()})

def main():
    p = argparse.ArgumentParser(description="Baseline scanner and interactive remediation assistant")
    p.add_argument("--baseline", required=True, help="Path to baseline JSON")
    p.add_argument("--ssh-user", help="Default SSH user for Linux hosts")
    p.add_argument("--ssh-key", help="Default SSH key path for Linux hosts")
    p.add_argument("--winrm-user", help="Default WinRM user for Windows hosts")
    p.add_argument("--winrm-pass", help="Default WinRM password for Windows hosts (or leave blank to prompt)")
    p.add_argument("--execute", action="store_true", help="Allow remediation/rotation actions (default: dry-run)")
    p.add_argument("--timeout", type=int, default=10, help="SSH/WinRM connection timeout seconds (used for ssh)")
    p.add_argument("--update-hostnames", action="store_true", help="Write discovered hostnames back into the baseline")
    p.add_argument("--baseline-out", help="Optional path to write updated baseline if --update-hostnames is set")
    p.add_argument("--rotate-passwords", action="store_true", help="Rotate passwords for allowed_users (local accounts only)")
    p.add_argument("--password-file", default="rotated_passwords_UTC.csv", help="Local CSV file to save rotated passwords")
    p.add_argument("--pw-length", type=int, default=24, help="Password length for rotation")

    args = p.parse_args()

    baseline = load_baseline(args.baseline)
    hosts = baseline.get("hosts", [])

    global_opts = {
        "ssh_user": args.ssh_user,
        "ssh_key": args.ssh_key,
        "winrm_user": args.winrm_user,
        "winrm_pass": args.winrm_pass,
        "execute": args.execute,
        "timeout": args.timeout
    }

    if args.winrm_user and args.winrm_pass is None:
        args.winrm_pass = getpass.getpass(prompt="WinRM password (will reuse for all Windows hosts without per-host creds): ")
        global_opts["winrm_pass"] = args.winrm_pass

    dirty = False

    if args.rotate_passwords:
        init_password_file(args.password_file)
        print(f"Password file: {args.password_file}  (ensure this lives on an encrypted volume with restricted access)")

    for host in hosts:
        ip = host.get("ip")
        plat = (host.get("platform") or "").lower()
        allowed = lowercase_set(host.get("allowed_users", []))
        discovered = []

        print(f"\n--- Enumerating {host.get('hostname')} ({ip}) [{plat}] ---")

        per_ssh = host.get("ssh", {}) or {}
        per_winrm = host.get("winrm", {}) or {}

        if plat == "linux":
            ssh_user = per_ssh.get("user") or global_opts.get("ssh_user")
            ssh_key  = per_ssh.get("ssh_key") or global_opts.get("ssh_key")
            actual_hn = get_linux_hostname_via_ssh(ip, ssh_user=ssh_user, ssh_key=ssh_key)
            if actual_hn and actual_hn != host.get("hostname"):
                print(f"  Hostname mismatch: baseline '{host.get('hostname')}' → discovered '{actual_hn}'")
                host["hostname"] = actual_hn
                dirty = True
            discovered = with_retries(
                enum_linux_users_via_ssh,
                ip=ip, ssh_user=ssh_user, ssh_key=ssh_key,
                err_is_retry=looks_like_error_list
            )

        elif plat == "windows":
            winrm_user = per_winrm.get("user") or global_opts.get("winrm_user")
            winrm_pass = per_winrm.get("password") or global_opts.get("winrm_pass")
            if not winrm_user or not winrm_pass:
                print("No WinRM creds available for this Windows host; will only enumerate if possible.")
                discovered = [{"error":"no_winrm_creds_for_host"}]
            else:
                actual_hn = get_windows_hostname_via_winrm(ip, winrm_user, winrm_pass)
                if actual_hn and actual_hn != host.get("hostname"):
                    print(f"  Hostname mismatch: baseline '{host.get('hostname')}' → discovered '{actual_hn}'")
                    host["hostname"] = actual_hn
                    dirty = True
                discovered = with_retries(
                    enum_windows_users_via_winrm,
                    ip=ip, winrm_user=winrm_user, winrm_pass=winrm_pass,
                    err_is_retry=looks_like_error_list
                )
        else:
            print("Unsupported platform; skipping.")
            log_entry({"host": host.get("hostname"), "ip": ip, "action": "unsupported_platform", "platform": plat})
            continue

        if looks_like_error_list(discovered):
            log_entry({"host": host.get("hostname"), "ip": ip, "platform": plat, "action": "host_unreachable", "error": discovered[0]})
            continue

        inspect_host_and_prompt(host, discovered, allowed, global_opts)

        if args.rotate_passwords:
            rotate_allowed_users_for_host(host, global_opts, args.pw_length, args.password_file)

    if args.update_hostnames and dirty:
        out_path = args.baseline_out or args.baseline
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(baseline, fh, indent=2)
        print(f"\nUpdated hostnames written to {out_path}")
    elif dirty:
        print("\nNote: hostnames changed during scan. Re-run with --update-hostnames to persist them.")

    print("\nAll hosts processed. See", LOG_PATH, "for an audit trail.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json, argparse, os

p = argparse.ArgumentParser()
p.add_argument("--baseline", required=True)
p.add_argument("--hostname", required=True)
p.add_argument("--ip", required=True)
p.add_argument("--platform", choices=["windows","linux"], required=True)
p.add_argument("--allowed-users", nargs="+", required=True)
p.add_argument("--ssh-user")
p.add_argument("--ssh-key")
p.add_argument("--winrm-user")
p.add_argument("--winrm-pass", help=argparse.SUPPRESS)
args = p.parse_args()
if args.winrm_pass is not None:
    p.error("--winrm-pass is disabled because command-line passwords can be exposed; enter the password at the scanner's hidden prompt")
if os.path.basename(os.path.realpath(args.baseline)).lower() == "baseline.example.json":
    p.error("the published example baseline is read-only; copy it to baseline.local.json before adding hosts")

with open(args.baseline, "r", encoding="utf-8") as fh:
    data = json.load(fh)
if any("password" in (host.get("winrm") or {}) for host in data.get("hosts", [])):
    p.error("baseline contains winrm.password; remove stored passwords and enter them at the scanner's hidden prompt")

host = {
    "hostname": args.hostname,
    "ip": args.ip,
    "platform": args.platform,
    "allowed_users": args.allowed_users
}

if args.platform == "linux":
    if args.ssh_user:
        host.setdefault("ssh", {})["user"] = args.ssh_user
    if args.ssh_key:
        host.setdefault("ssh", {})["ssh_key"] = args.ssh_key.replace("\\", "/")
elif args.platform == "windows":
    if args.winrm_user:
        host.setdefault("winrm", {})["user"] = args.winrm_user

data.setdefault("hosts", []).append(host)

with open(args.baseline, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
print(f"Added host {args.hostname} ({args.ip})")

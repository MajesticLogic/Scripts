# Majestic_Leadger.py

Multi-platform baseline & user remediation assistant for Windows (WinRM) and Linux (SSH).

**Features**
- Enumerate local users on each host and compare to a host-specific baseline
- Human-in-the-loop remediation (disable/quarantine/delete) with explicit approval prompts
- Hostname discovery and optional persistence back to baseline (`--update-hostnames`)
- Retry logic (3 attempts per host) before skipping
- Optional rotation of *allowed user* local passwords, saving new passwords locally to an encrypted/locked CSV
- Audit log to `remediation_log_UTC.jsonl`

> **Security Notes**
> - This touches *local* accounts. Domain account changes must be done via AD runbooks.
> - Store rotated-password CSV on an encrypted volume with restricted ACLs.
> - Keep baseline in source control; require PRs for changes.

## Quickstart

```powershell
# Optional: only needed for Windows WinRM actions
pip install pywinrm

# Dry-run: enumerate + compare only
python .\Majestic_Ledger.py --baseline .\baseline.json --ssh-user mr.majestic --winrm-user mr.majestic

# Remediation (still requires per-account approval prompts)
python .\Majestic_Ledger.py --baseline .\baseline.json --ssh-user mr.majestic --winrm-user mr.majestic --execute

# Persist discovered hostnames back into baseline
python .\Majestic_Ledger.py --baseline .\baseline.json --ssh-user mr.majestic --winrm-user mr.majestic --update-hostnames

# Rotate passwords for allowed users (per-account APPROVE prompt, saves to CSV locally)
python .\Majestic_Ledger.py --baseline .\baseline.json --ssh-user mr.majestic --winrm-user mr.majestic --rotate-passwords --execute
```

## Baseline format

See [`baseline.json`](baseline.json).

## Add a host programmatically

```powershell
python .\baseline_add_host.py --baseline .\baseline.json `
  --hostname host-linux-02 --ip 10.0.1.23 --platform linux `
  --allowed-users root sysadmin bob `
  --ssh-user mr.majestic --ssh-key C:/Users/mr.majestic/.ssh/id_rsa
```

## License

MIT

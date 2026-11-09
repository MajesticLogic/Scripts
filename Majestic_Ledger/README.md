# Majestic Ledger

Multi-platform baseline and user remediation assistant for Windows (WinRM) and Linux (SSH).

**Features**
- Enumerate local users on each host and compare them with a host-specific baseline
- Request explicit approval before disabling, quarantining, or deleting an out-of-baseline local account
- Discover hostnames and optionally save them to a local baseline (`--update-hostnames`)
- Retry unreachable hosts and write an audit log to `remediation_log_UTC.jsonl`

> **Security notes**
> - The [example baseline](baseline.example.json) is fictional. Its `192.0.2.0/24` addresses are reserved for documentation and will not reach your hosts.
> - Copy it to `baseline.local.json`, replace the sample values, and keep that local file and audit logs out of source control. The repository `.gitignore` helps prevent accidental commits but does not encrypt files or remove files already committed.
> - Do not put passwords or other secrets in a baseline. Enter a WinRM password at the prompt instead of using `--winrm-pass` on the command line.
> - Password rotation is disabled. Earlier versions wrote rotated passwords to an unencrypted CSV. Use an approved password manager and platform runbook for rotations until a secure storage and recovery flow is implemented.
> - This tool changes *local* accounts only. Domain account changes require an Active Directory runbook.

## Quickstart

Run these commands from the `Majestic_Ledger` directory. Edit the local copy before scanning real hosts.

```powershell
# Optional dependency for Windows WinRM actions
pip install pywinrm

# Create a local inventory from the fictional example
Copy-Item .\baseline.example.json .\baseline.local.json

# Dry run: enumerate and compare only
python .\Majestic_Ledger.py --baseline .\baseline.local.json --ssh-user example-admin --winrm-user example-admin

# After reviewing the findings, allow individual remediation approval prompts
python .\Majestic_Ledger.py --baseline .\baseline.local.json --ssh-user example-admin --winrm-user example-admin --execute

# Persist discovered hostnames to the ignored local inventory
python .\Majestic_Ledger.py --baseline .\baseline.local.json --ssh-user example-admin --winrm-user example-admin --update-hostnames
```

Replace `example-admin` and the sample host addresses in `baseline.local.json` before scanning. The script requires an explicit `--baseline` path; it does not load the published example automatically. The example cannot be updated in place. `--execute` still requires a typed approval for each remediation action.

## Baseline format

See [`baseline.example.json`](baseline.example.json). It contains no usable credentials or live host addresses.

## Add a host programmatically

```powershell
python .\baseline_add_host.py --baseline .\baseline.local.json `
  --hostname example-linux-02 --ip 192.0.2.30 --platform linux `
  --allowed-users root example-operator `
  --ssh-user example-admin --ssh-key C:/path/to/key
```

Use a real host address and key path only in your ignored local inventory.

## License

MIT

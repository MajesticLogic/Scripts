# CheckMate.ps1

## Purpose

CheckMate.ps1 is a "fire-and-forget" Windows remediation script intended for use by incident responders and analysts. The script automates the rapid removal of known malicious persistence and artifacts you specify, such as local user accounts, processes, services, scheduled tasks, and files.

> **Important:** This script can be destructive. Use the audit mode (`$PerformActions = $false`) to review intended changes before enabling remediation.

---

## Quick overview of what it does

- Validates execution environment (admin privileges, required cmdlets).
- Enumerates configured indicators defined at the top of the script (users, processes, services, files, scheduled tasks).
- In **audit mode** (default safe option) it prints the actions it would take without making changes.
- In **remediation mode** it forcibly stops/kills processes, disables and removes services, deletes files, removes local user accounts (and optionally profiles), and deletes scheduled tasks as defined.

---

## Prerequisites

1. Administrative privileges on the target host (required for most remediation actions).
2. PowerShell 5.1 or later recommended for widest cmdlet coverage; the script detects availability of some cmdlets and attempts fallback behavior when possible.
3. A secure channel to the target host (PowerShell Remoting / Velociraptor / other remote execution tooling) if you will run the script remotely.
4. A backup/evidence plan — collect and hash evidence before running destructive actions whenever practical.

---

## Configuration

Open the script in a text editor and update the following variables at the top of the file to match your case:

- `$PerformActions` — set to `$false` to run an audit-only dry-run, set to `$true` to perform destructive remediation.
- `$UsersToRemove` — array of local account names you want removed.
- `$Services` — array of service names or patterns to stop/disable/remove.
- `$Processes` — array of process names or patterns to terminate.
- `$Files` — array of file paths to remove.
- Additional switches and logging destinations (if present) — review these and update paths if you want output centralized.

**Recommendation:** Always run with `$PerformActions = $false` first. Review the script output and ensure indicators are correct.

---

## Running the script locally (analyst desktop)

1. Copy `CheckMate.ps1` to your analyst workstation.
2. Open an **elevated PowerShell** window (Run as Administrator).
3. Run in audit mode first:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Path\To\CheckMate.ps1   # edit $PerformActions in the script or pass as env/param if supported
```

4. If output looks correct, edit the script to set `$PerformActions = $true`, then re-run the script from the same elevated session.

**Note:** You can also copy the script to a removable evidence drive or a secure evidence share if policy requires.

---

## Running the script on a remote Windows host using PowerShell Remoting

> **Before you run:** Confirm you have administrative credentials, the target allows PowerShell Remoting (WinRM/HTTPS), and remote execution is authorized by policy.

### Option A — Using `Invoke-Command` and copying the script

1. Copy the script to the remote machine (temporary location) and then invoke it.

```powershell
# Copy the script to the remote host
$session = New-PSSession -ComputerName TARGET_HOST -Credential (Get-Credential)
Copy-Item -Path .\CheckMate.ps1 -Destination C:\Windows\Temp\CheckMate.ps1 -ToSession $session

# Audit-only run
Invoke-Command -Session $session -ScriptBlock { powershell -ExecutionPolicy Bypass -File 'C:\Windows\Temp\CheckMate.ps1' }

# If OK, run remediation
Invoke-Command -Session $session -ScriptBlock { powershell -ExecutionPolicy Bypass -File 'C:\Windows\Temp\CheckMate.ps1' }

Remove-PSSession $session
```

### Option B — Run directly from your workstation without persisting a copy

```powershell
$script = Get-Content -Raw -Path .\CheckMate.ps1
Invoke-Command -ComputerName TARGET_HOST -Credential (Get-Credential) -ScriptBlock { param($s) Invoke-Expression $s } -ArgumentList $script
```

**Caveats & best practices:**
- Use HTTPS/WinRM over the network or an authenticated management channel (e.g., Jump host) — avoid cleartext.
- Keep an evidence copy and record checksums of removed files before deletion where possible.
- Prefer invoking the script from a trusted analyst workstation rather than executing arbitrary one-liners from web paste sites.

---

## Running the script via Velociraptor

Velociraptor has built-in client artifacts for running PowerShell or shell commands on endpoints. Use the `Windows.System.PowerShell` artifact to run arbitrary PowerShell commands (the client typically runs as SYSTEM when Velociraptor has appropriate permissions). You can either upload the script to a reachable location on your file server and instruct Velociraptor to download & execute it, or you can embed the script into a Velociraptor collection that runs the script on the client.

**Minimal safe flow:**
1. Upload `CheckMate.ps1` to a secure internal HTTPS server or network share that the clients can reach.
2. In the Velociraptor web UI create a new collection and select the `Windows.System.PowerShell` artifact (or use an appropriate exec artifact).
3. Provide a command such as:

```
powershell -ExecutionPolicy Bypass -File "C:\Windows\Temp\CheckMate.ps1"
```

or as a one-liner that downloads then executes (if your environment allows downloading):

```powershell
$u='https://internal.server/CheckMate.ps1'; $p='C:\Windows\Temp\CheckMate.ps1'; Invoke-WebRequest -Uri $u -OutFile $p; powershell -ExecutionPolicy Bypass -File $p
```

**Notes:**
- Velociraptor may run commands as SYSTEM; ensure this behavior is acceptable for your workflow. The artifact requires elevated EXECVE permissions to run arbitrary commands. (Velociraptor docs describe `Windows.System.PowerShell` and `Windows.Memory.Acquisition` artifacts.)
- Increase timeouts for long-running tasks such as memory acquisition.

---

## Logging & evidence

- Collect output, STDOUT/STDERR and any tool logs. If possible, make Velociraptor store the output to your secure evidence store.
- Record hashes of files you will remove (append them to your `hashes.txt` evidence file) and add line entries to your custody ledger before performing destructive actions.

---

## Safety & operational cautions

- Always perform an **evidence collection** step before deletion (file copies to an evidence share, registry exports, memory capture if needed).
- Test in an isolated lab before using in production.
- Coordinate with system owners and follow your organization’s incident response policy.
- Use the audit-only mode extensively until you are confident the listed indicators are correct.


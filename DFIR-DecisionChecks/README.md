Windows-only deconfliction sheet of what The DFIR-DecisionChecks.ps1 **remote, read-only survey script** leaves behind.

# On the target endpoint

## Logons and remoting

* **Security** log

  * **4624** (Logon) with **LogonType 3** (Network) for the WinRM session, and the matching **4634** (Logoff).
  * **4672** (Special privileges) if the account is admin.
  * **4648** (Logon with explicit credentials) may appear if you supplied `-Credential`.
* **Microsoft-Windows-WinRM/Operational**

  * Session creation/teardown and plugin activity for the WSMan (WinRM) connection.

## PowerShell telemetry (if logging is enabled)

* **Microsoft-Windows-PowerShell/Operational**

  * **400** (Engine start) and **403** (Engine stop).
  * **4103** (Module logging) and/or **4104** (Script Block Logging) showing CIM/Invoke-Command activity.

## WMI/CIM activity

* **Microsoft-Windows-WMI-Activity/Operational**

  * Provider access by **WmiPrvSE.exe** driven by the remoting session (queries behind `Get-CimInstance`).

## Process creation (depends on your auditing/Sysmon)

* **Security 4688** (Process Creation) and/or **Sysmon Event 1** for:

  * **wsmprovhost.exe** (WinRM provider host that runs your commands).
  * **w32tm.exe** (time query).
  * **vssadmin.exe** (shadow snapshot listing).
  * Potential in-process **powershell.exe** instances hosted by wsmprovhost (environment-dependent).

## Prefetch (client SKUs; often disabled on Server SKUs)

* `C:\Windows\Prefetch\W32TM.EXE-*.pf`
* `C:\Windows\Prefetch\VSSADMIN.EXE-*.pf`
* `C:\Windows\Prefetch\POWERSHELL.EXE-*.pf`
* `C:\Windows\Prefetch\WSMPROVHOST.EXE-*.pf`

## Network traces

* Inbound TCP **5985** flows from your analysis host (HTTP WinRM).
* Local firewall/NetFlow/EDR may record the session as WinRM/WSMan traffic.

## Domain controller (if applicable; not on the endpoint itself)

* **Kerberos**: **4768/4769** (TGT/TGS) on the DC when Kerberos auth is used.
* **NTLM**: **4776** (NTLM auth) on the DC if NTLM was used (e.g., IP + `TrustedHosts`).

## File system and registry writes on the target

* **None by the script.** It does not create files, change services, policies, or registry keys on the target.
* Normal OS components may update their own logs, caches, or telemetry (as listed above).

---

# Quick queries you can run during deconfliction

Run these **on the target** to show your activity window. Replace the time window, user, and analyst IP as needed.

```powershell
# WinRM session traces
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 200 |
  Where-Object TimeCreated -ge (Get-Date).AddHours(-4) |
  Select TimeCreated, Id, LevelDisplayName, Message

# Logon/Logoff around the session (Network logon type 3)
$start=(Get-Date).AddHours(-4)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$start} |
  Where-Object { $_.Message -match 'Logon Type:\s+3' } |
  Select TimeCreated, Id, @{n='Account';e={$_.Properties[5].Value}}, @{n='IP';e={($_.Message -split '\r?\n' | ? {$_ -match 'Source Network Address'}) -replace '.*:\s+',''}}

# Process creation for WinRM host and the two utilities
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$start} |
  Where-Object { $_.Message -match '\\(wsmprovhost|vssadmin|w32tm)\.exe' } |
  Select TimeCreated, Id, @{n='NewProcess';e={($_.Message -split '\r?\n' | ? {$_ -match 'New Process Name'}) -replace '.*:\s+',''}},
                       @{n='Parent';e={($_.Message -split '\r?\n' | ? {$_ -match 'Creator Process Name'}) -replace '.*:\s+',''}}

# PowerShell operational (engine/script logging)
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 200 |
  Where-Object TimeCreated -ge $start |
  Where-Object Id -in 400,403,4103,4104 |
  Select TimeCreated, Id, Message

# WMI/CIM activity
Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' -MaxEvents 200 |
  Where-Object TimeCreated -ge $start |
  Select TimeCreated, Id, Message
```

**Sysmon equivalent (if present):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$start} |
  Where-Object { $_.Message -match '\\(wsmprovhost|vssadmin|w32tm)\.exe' } |
  Select TimeCreated, Id, Message
```

---

# One-liner you can paste into your case notes

Remote, read-only survey executed via WinRM (HTTP/5985) from `<analyst host>` at `<UTC window>`. Expected artifacts on target: Security 4624/4634 (logon/logoff, type 3; 4672 if admin; 4648 if explicit creds), WinRM Operational session entries, PowerShell Operational 400/403/4103/4104 if enabled, process-creation events for `wsmprovhost.exe`, `w32tm.exe`, `vssadmin.exe` (Security 4688 and/or Sysmon 1), Prefetch updates for those binaries on client OS, and inbound TCP 5985 from analyst host. No files written to the target by the script.

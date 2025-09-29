# CheckMate.ps1
# Fire-and-forget remediation script.
# WARNING: Destructive. Test with $PerformActions = $false first. Run elevated.

# ----------------------------
# Edit Indicators before running
# ----------------------------
$PerformActions = $true   # Set to $true to perform destructive actions
$UsersToRemove  = @('evil','evil.2')
$Services       = @('EvilService')
$Processes      = @('EvilBroker','EvilScheduler','EvilUpdate','evilsvc','Evilx')
$Files          = @(
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\EvilScheduler.exe',
    'C:\Users\evil\AppData\Local\Google\EvilUpdate.exe',
    'C:\Users\evil.2\AppData\Local\Google\Chrome\EvilBroker.exe',
    'C:\Windows\System32\evilsvc.exe',
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\EvilScheduler.exe',
    'C:\Users\susan.olsen\AppData\Local\Microsoft\Windows\winx\Evilx.exe'
)

# ----------------------------
# PRECHECK: elevation
# ----------------------------
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}
if (-not $isAdmin) {
    Write-Output "ERROR: script requires administrative privileges. Exiting."
    exit 1
}

# detect environment features
$HasGetScheduledTask = (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) -ne $null
$HasGetLocalUser     = (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) -ne $null
$HasGetLocalGroup    = (Get-Command -Name Get-LocalGroup -ErrorAction SilentlyContinue) -ne $null
$HasGetLocalGroupMember = (Get-Command -Name Get-LocalGroupMember -ErrorAction SilentlyContinue) -ne $null
$HasRemoveLocalGroupMember = (Get-Command -Name Remove-LocalGroupMember -ErrorAction SilentlyContinue) -ne $null
$ProfileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

$overallSuccess = $true

# helper to print section results
function Print-Section {
    param($Name, $Obj)
    Write-Output "=== SECTION: $Name ==="
    Write-Output ("Success: {0}" -f $Obj.success)
    if ($Obj.findings -and $Obj.findings.Count -gt 0) {
        foreach ($it in $Obj.findings) { Write-Output (" - {0}" -f $it) }
    } else {
        Write-Output " - none found"
    }
    if ($Obj.message) { Write-Output ("Message: {0}" -f $Obj.message) }
    Write-Output ""
}

# ----------------------------
# Section: Services
# ----------------------------
$sec = @{ success=$true; findings=@(); message=$null }
try {
    foreach ($svc in $Services) {
        try {
            $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($svcObj) {
                if ($PerformActions) {
                    try { Stop-Service -Name $svc -Force -ErrorAction Stop } catch {}
                    try { sc.exe delete $svc > $null 2>&1 } catch {}
                }
                $sec.findings += "service_present_and_removed:$svc"
            } else {
                $sec.findings += "service_not_present:$svc"
            }
        } catch {
            $err = $_.Exception.Message
            $sec.success = $false
            $sec.message = ("Error handling service {0}: {1}" -f $svc, $err)
        }
    }
} catch {
    $err = $_.Exception.Message
    $sec.success = $false
    $sec.message = ("Services section failed: {0}" -f $err)
}
if (-not $sec.success) { $overallSuccess = $false }
Print-Section "Services" $sec

# ----------------------------
# Section: Scheduled Tasks
# ----------------------------
$sec = @{ success=$true; findings=@(); message=$null }
try {
    if ($HasGetScheduledTask) {
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        if ($allTasks) {
            $suspiciousNames = @('JavaUpdateScheduler','GoogleUpdateBroker','vscsvc','winx')
            foreach ($t in $allTasks) {
                try {
                    $principal = $null
                    try { $principal = $t.Principal.UserId } catch { $principal = $null }
                    $matchUser = $false
                    foreach ($u in $UsersToRemove) { if ($principal -and ($principal -match [regex]::Escape($u))) { $matchUser = $true; break } }
                    $matchName = $false
                    foreach ($s in $suspiciousNames) { if ($t.TaskName -and ($t.TaskName -match $s)) { $matchName = $true; break } }
                    if ($matchUser -or $matchName) {
                        if ($PerformActions) { try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue } catch {} }
                        $sec.findings += ("task_unregistered:{0}{1}" -f $t.TaskPath, $t.TaskName)
                    }
                } catch {
                    $err = $_.Exception.Message
                    $sec.success = $false
                    $sec.message = ("Scheduled task item failure: {0}" -f $err)
                }
            }
            if (-not $sec.findings) { $sec.findings += 'none_found' }
        } else {
            $sec.findings += 'no_tasks_found'
        }
    } else {
        $sec.findings += 'Get-ScheduledTask_not_available'
    }
} catch {
    $err = $_.Exception.Message
    $sec.success = $false
    $sec.message = ("Scheduled tasks section failed: {0}" -f $err)
}
if (-not $sec.success) { $overallSuccess = $false }
Print-Section "Scheduled Tasks" $sec

# ----------------------------
# Section: Startup & Run keys
# ----------------------------
$sec = @{ success=$true; findings=@(); message=$null }
try {
    foreach ($f in $Files) {
        try {
            if ($f -and (Test-Path $f -PathType Leaf)) {
                if ($PerformActions) { try { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } catch {} }
                $sec.findings += "startup_file_removed:$f"
            } else {
                $sec.findings += "startup_file_not_present:$f"
            }
        } catch {
            $err = $_.Exception.Message
            $sec.success = $false
            $sec.message = ("Startup file handling error: {0}" -f $err)
        }
    }

    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($rk in $runKeys) {
        try {
            if (Test-Path $rk) {
                $propsObj = $null
                try { $propsObj = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue } catch { $propsObj = $null }
                if ($propsObj) {
                    $propNames = @()
                    try { $propNames = $propsObj.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | Select-Object -ExpandProperty Name } catch { $propNames = @() }
                    foreach ($prop in $propNames) {
                        foreach ($s in @('JavaUpdateScheduler','GoogleUpdate','GoogleUpdateBroker','vscsvc','winx')) {
                            try {
                                if ($prop -and ($prop -match $s)) {
                                    if ($PerformActions) { try { Remove-ItemProperty -Path $rk -Name $prop -ErrorAction SilentlyContinue } catch {} }
                                    $sec.findings += ("runkey_removed:{0}::{1}" -f $rk, $prop)
                                }
                            } catch {
                                $err = $_.Exception.Message
                                $sec.success = $false
                                $sec.message = ("Run key handling error: {0}" -f $err)
                            }
                        }
                    }
                } else {
                    $sec.findings += ("run_key_not_populated:{0}" -f $rk)
                }
            } else {
                $sec.findings += ("run_key_missing:{0}" -f $rk)
            }
        } catch {
            $err = $_.Exception.Message
            $sec.success = $false
            $sec.message = ("Run keys section failed: {0}" -f $err)
        }
    }

    if (-not $sec.findings) { $sec.findings += 'none_found' }
} catch {
    $err = $_.Exception.Message
    $sec.success = $false
    $sec.message = ("Startup/Run keys section failed: {0}" -f $err)
}
if (-not $sec.success) { $overallSuccess = $false }
Print-Section "Startup & Run keys" $sec

# ----------------------------
# Section: Processes
# ----------------------------
$sec = @{ success=$true; findings=@(); message=$null }
try {
    foreach ($p in $Processes) {
        try {
            $procs = Get-Process -Name $p -ErrorAction SilentlyContinue
            if ($procs) {
                foreach ($pr in $procs) {
                    if ($PerformActions) { try { Stop-Process -Id $pr.Id -Force -ErrorAction SilentlyContinue } catch {} }
                    $sec.findings += ("process_stopped:{0}:pid:{1}" -f $pr.ProcessName, $pr.Id)
                }
            } else {
                $sec.findings += ("process_not_found:{0}" -f $p)
            }
        } catch {
            $err = $_.Exception.Message
            $sec.success = $false
            $sec.message = ("Process handling error: {0}" -f $err)
        }
    }
} catch {
    $err = $_.Exception.Message
    $sec.success = $false
    $sec.message = ("Processes section failed: {0}" -f $err)
}
if (-not $sec.success) { $overallSuccess = $false }
if (-not $sec.findings) { $sec.findings += 'none_found' }
Print-Section "Processes" $sec

# ----------------------------
# Section: Files
# ----------------------------
$sec = @{ success=$true; findings=@(); message=$null }
try {
    foreach ($file in $Files) {
        try {
            if ($file -and (Test-Path $file -PathType Leaf)) {
                if ($PerformActions) { try { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue } catch {} }
                $sec.findings += ("file_deleted:{0}" -f $file)
            } else {
                $sec.findings += ("file_not_found:{0}" -f $file)
            }
        } catch {
            $err = $_.Exception.Message
            $sec.success = $false
            $sec.message = ("File deletion error: {0}" -f $err)
        }
    }
} catch {
    $err = $_.Exception.Message
    $sec.success = $false
    $sec.message = ("Files section failed: {0}" -f $err)
}
if (-not $sec.success) { $overallSuccess = $false }
if (-not $sec.findings) { $sec.findings += 'none_found' }
Print-Section "Files" $sec

# ----------------------------
# Section: Users
# ----------------------------
$sec = @{ success=$true; findings=@(); message=$null }
try {
    foreach ($user in $UsersToRemove) {
        try {
            if (-not $user) { $sec.findings += "empty_username_skipped"; continue }

            # existence check
            $userExists = $false
            try {
                if ($HasGetLocalUser) {
                    $lu = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
                    if ($lu) { $userExists = $true }
                } else {
                    try { net user $user > $null 2>&1 } catch {}
                    if ($LASTEXITCODE -eq 0) { $userExists = $true }
                }
            } catch { $userExists = $false }

            if (-not $userExists) {
                $sec.findings += ("user_not_found:{0}" -f $user)
                continue
            }

            # disable account
            try {
                if ($PerformActions) {
                    if ($HasGetLocalUser) { try { Disable-LocalUser -Name $user -ErrorAction SilentlyContinue } catch {} }
                    else { try { net user $user /active:no > $null 2>&1 } catch {} }
                }
                $sec.findings += ("user_disabled:{0}" -f $user)
            } catch {
                $err = $_.Exception.Message
                $sec.findings += ("user_disable_failed:{0}" -f $user)
                $sec.success = $false
                $sec.message = ("Failed disabling {0}: {1}" -f $user, $err)
            }

            # remove from groups (cmdlets preferred, fallback to net localgroup)
            try {
                if ($HasGetLocalGroup -and $HasGetLocalGroupMember -and $HasRemoveLocalGroupMember) {
                    foreach ($g in Get-LocalGroup -ErrorAction SilentlyContinue) {
                        try {
                            $members = Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue
                            if ($members) {
                                foreach ($m in $members) {
                                    try {
                                        $mn = $m.Name -replace '^[^\\]+\\',''
                                        if ($mn -and ($mn -ieq $user)) {
                                            if ($PerformActions) { Remove-LocalGroupMember -Group $g.Name -Member $m.Name -ErrorAction SilentlyContinue -Confirm:$false }
                                            $sec.findings += ("removed_from_group:{0}:{1}" -f $user, $g.Name)
                                        }
                                    } catch {}
                                }
                            }
                        } catch {}
                    }
                } else {
                    # quick removal from common groups
                    foreach ($gname in @('Administrators','Users','Remote Desktop Users')) {
                        try {
                            if ($PerformActions) { net localgroup $gname $user /delete > $null 2>&1 }
                            $sec.findings += ("attempted_remove_from_group:{0}:{1}" -f $user, $gname)
                        } catch {}
                    }
                    # enumerate groups and remove if present
                    try {
                        $groupsOut = net localgroup 2>$null
                        if ($LASTEXITCODE -eq 0 -and $groupsOut) {
                            $glist = $groupsOut | ForEach-Object { $_.Trim() } | Where-Object { ($_ -ne '') -and ($_ -notmatch '^(Aliases for group|Members|The command completed|^-+)') }
                            foreach ($grp in $glist) {
                                try {
                                    $membersOut = net localgroup $grp 2>$null
                                    if ($LASTEXITCODE -eq 0 -and $membersOut) {
                                        $mLines = $membersOut | ForEach-Object { $_.Trim() } | Where-Object { ($_ -ne '') -and ($_ -notmatch '^(Aliases for group|Members|The command completed|^-+)') }
                                        foreach ($line in $mLines) {
                                            try {
                                                $mn = $line -replace '^[^\\]+\\',''
                                                if ($mn -ieq $user) {
                                                    if ($PerformActions) { net localgroup $grp $user /delete > $null 2>&1 }
                                                    $sec.findings += ("removed_from_group_via_net:{0}:{1}" -f $user, $grp)
                                                }
                                            } catch {}
                                        }
                                    }
                                } catch {}
                            }
                        }
                    } catch {}
                }
            } catch {
                $err = $_.Exception.Message
                $sec.success = $false
                $sec.message = ("Group removal error for {0}: {1}" -f $user, $err)
            }

            # unregister scheduled tasks for that user (if supported)
            try {
                if ($HasGetScheduledTask) {
                    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Principal.UserId -and ($_.Principal.UserId -match [regex]::Escape($user)) }
                    foreach ($t in $tasks) {
                        try {
                            if ($PerformActions) { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue }
                            $sec.findings += ("unregistered_task_for_user:{0}:{1}{2}" -f $user, $t.TaskPath, $t.TaskName)
                        } catch {}
                    }
                }
            } catch {
                $err = $_.Exception.Message
                $sec.success = $false
                $sec.message = ("User task cleanup error for {0}: {1}" -f $user, $err)
            }

            # remove profile
            try {
                $profilePath = "C:\Users\$user"
                if ($profilePath -and (Test-Path $profilePath -PathType Container)) {
                    if ($PerformActions) { Remove-Item -LiteralPath $profilePath -Recurse -Force -ErrorAction SilentlyContinue }
                    $sec.findings += ("profile_removed:{0}" -f $profilePath)
                } else {
                    $sec.findings += ("profile_not_found:{0}" -f $profilePath)
                }
            } catch {
                $err = $_.Exception.Message
                $sec.success = $false
                $sec.message = ("Profile removal error for {0}: {1}" -f $user, $err)
            }

            # remove ProfileList registry entries if present
            try {
                if (Test-Path $ProfileListPath) {
                    foreach ($sid in Get-ChildItem $ProfileListPath -ErrorAction SilentlyContinue) {
                        try {
                            $val = $null
                            try { $val = (Get-ItemProperty -Path $sid.PSPath -ErrorAction SilentlyContinue).ProfileImagePath } catch { $val = $null }
                            if ($val -and ($val -like "*\$user")) {
                                if ($PerformActions) { Remove-Item -LiteralPath $sid.PSPath -Recurse -Force -ErrorAction SilentlyContinue }
                                $sec.findings += ("profilelist_removed:{0}:{1}" -f $user, $sid.PSPath)
                            }
                        } catch {}
                    }
                }
            } catch {
                $err = $_.Exception.Message
                $sec.success = $false
                $sec.message = ("ProfileList cleanup error for {0}: {1}" -f $user, $err)
            }

            # delete local account
            try {
                if ($PerformActions) {
                    if ($HasGetLocalUser) { Remove-LocalUser -Name $user -ErrorAction SilentlyContinue } else { net user $user /delete > $null 2>&1 }
                }
                $sec.findings += ("account_deleted_or_attempted:{0}" -f $user)
            } catch {
                $err = $_.Exception.Message
                $sec.success = $false
                $sec.message = ("Account deletion error for {0}: {1}" -f $user, $err)
            }

        } catch {
            $err = $_.Exception.Message
            $sec.success = $false
            $sec.message = ("User loop error for {0}: {1}" -f $user, $err)
        }
    }
} catch {
    $err = $_.Exception.Message
    $sec.success = $false
    $sec.message = ("Users section failed: {0}" -f $err)
}
if (-not $sec.success) { $overallSuccess = $false }
if (-not $sec.findings) { $sec.findings += 'none_found' }
Print-Section "Users" $sec

# ----------------------------
# Section: Final sweep
# ----------------------------
$sec = @{ success=$true; findings=@(); message=$null }
try {
    foreach ($p in $Processes) {
        try {
            $procs = Get-Process -Name $p -ErrorAction SilentlyContinue
            if ($procs) {
                foreach ($pr in $procs) {
                    if ($PerformActions) { Stop-Process -Id $pr.Id -Force -ErrorAction SilentlyContinue }
                    $sec.findings += ("final_process_killed:{0}:pid:{1}" -f $pr.ProcessName, $pr.Id)
                }
            }
        } catch {}
    }
    foreach ($svc in $Services) {
        try { if ($PerformActions) { sc.exe delete $svc > $null 2>&1 } } catch {}
    }
    foreach ($file in $Files) {
        try { if ($file -and (Test-Path $file -PathType Leaf)) { if ($PerformActions) { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }; $sec.findings += ("final_file_deleted:{0}" -f $file) } } catch {}
    }
} catch {
    $err = $_.Exception.Message
    $sec.success = $false
    $sec.message = ("Final sweep failed: {0}" -f $err)
}
if (-not $sec.success) { $overallSuccess = $false }
if (-not $sec.findings) { $sec.findings += 'none_found' }
Print-Section "Final sweep" $sec

# ----------------------------
# Summary & exit
# ----------------------------
Write-Output "=== SUMMARY ==="
Write-Output ("Overall success: {0}" -f $overallSuccess)
if ($overallSuccess) { exit 0 } else { exit 2 }

# SPDX-License-Identifier: MIT
#
# install-agent-task.ps1 — registers wgctl-agent-windows.ps1 as a
# recurring Task Scheduler task, running as the current user with NO
# elevation (heartbeat/peers are plain HTTPS calls; only adapter
# creation needs admin rights, and this agent never touches that).
#
# Usage:
#   powershell -File scripts/install-agent-task.ps1              # install, every 60s
#   powershell -File scripts/install-agent-task.ps1 -IntervalSec 30
#   powershell -File scripts/install-agent-task.ps1 -Uninstall

param(
    [int]$IntervalSec = 60,
    [switch]$Uninstall
)

$TaskName = "WgctlAgentWindows"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$AgentScript = Join-Path $RepoRoot "scripts\wgctl-agent-windows.ps1"

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task '$TaskName' (if it existed)."
    return
}

if (-not (Test-Path $AgentScript)) {
    throw "agent script not found at $AgentScript"
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AgentScript`""

# One-time trigger "now", repeating every $IntervalSec indefinitely.
# Task Scheduler's minimum repetition granularity is 1 minute; for
# sub-minute intervals this still creates the task but repeats at 1
# minute (Windows limitation), which is fine for a status heartbeat.
$repetitionInterval = [TimeSpan]::FromSeconds([Math]::Max($IntervalSec, 60))
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval $repetitionInterval -RepetitionDuration ([TimeSpan]::MaxValue)

$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Limited   # Limited = no elevation, no UAC

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName', running every $([Math]::Max($IntervalSec,60))s as $env:USERNAME (no elevation)."
Write-Host "Logs: $RepoRoot\config\wgctl-agent.log"
Write-Host "Uninstall: powershell -File scripts\install-agent-task.ps1 -Uninstall"

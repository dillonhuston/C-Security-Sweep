# =============================================================================
# run_sweep.ps1
# =============================================================================
# Weekly security sweep wrapper for Windows Task Scheduler.
# Runs security_sweep.py, saves a JSON report, and emails you if any HIGH
# severity findings are detected.
#
# SETUP:
#   1. Fill in the $Config section below with your email details.
#   2. Register the scheduled task by running (as Administrator):
#        .\run_sweep.ps1 -Register
#   3. To run manually at any time:
#        .\run_sweep.ps1
#
# REQUIREMENTS:
#   - Python 3.x on PATH  (or set $PythonExe below)
#   - pip install colorama psutil  (done once)
#   - An SMTP server you can relay through (Gmail example included)
# =============================================================================

param(
    [switch]$Register   # Pass -Register to create the scheduled task
)

# ---------------------------------------------------------------------------
# CONFIGURATION — edit these values
# ---------------------------------------------------------------------------
$Config = @{
    # Full path to this script's directory (auto-detected)
    ScriptDir      = $PSScriptRoot

    # Path to python.exe — leave as "python" to use whatever is on PATH
    PythonExe      = "python"

    # Path to security_sweep.py (defaults to same folder as this script)
    SweepScript    = Join-Path $PSScriptRoot "security_sweep.py"

    # Report output format: "json" or "txt"
    ReportFormat   = "json"

    # Checks to disable (comma-separated), or empty string to run all
    # Example: "packages,writable"
    DisableChecks  = ""

    # ---- Email settings ----
    SendEmail      = $true          # Set to $false to skip email entirely
    SmtpServer     = "smtp.gmail.com"
    SmtpPort       = 587
    SmtpUseSsl     = $true
    SmtpUser       = "your.email@gmail.com"       # <-- change this
    SmtpPassword   = "your-app-password"           # <-- use an App Password for Gmail
    EmailFrom      = "your.email@gmail.com"        # <-- change this
    EmailTo        = "your.email@gmail.com"        # <-- change this (can be different)
    EmailSubject   = "[Security Sweep] HIGH severity issues found on $env:COMPUTERNAME"

    # ---- Scheduled task settings (used with -Register) ----
    TaskName       = "WeeklySecuritySweep"
    TaskDescription = "Weekly home-machine security sweep"
    # Run every Sunday at 08:00
    TaskTriggerDay  = "Sunday"
    TaskTriggerTime = "08:00"
}
# ---------------------------------------------------------------------------

# Resolve script directory when run from Task Scheduler (PSScriptRoot may be empty)
if (-not $Config.ScriptDir) {
    $Config.ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# ---------------------------------------------------------------------------
# REGISTER SCHEDULED TASK
# ---------------------------------------------------------------------------
if ($Register) {
    Write-Host "Registering scheduled task '$($Config.TaskName)'..." -ForegroundColor Cyan

    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" `
        -WorkingDirectory $Config.ScriptDir

    $trigger = New-ScheduledTaskTrigger `
        -Weekly `
        -DaysOfWeek $Config.TaskTriggerDay `
        -At $Config.TaskTriggerTime

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable:$false

    # Run as current user with highest privileges
    $principal = New-ScheduledTaskPrincipal `
        -UserId "$env:USERDOMAIN\$env:USERNAME" `
        -LogonType Interactive `
        -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $Config.TaskName `
        -Description $Config.TaskDescription `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Force | Out-Null

    Write-Host "Task registered. It will run every $($Config.TaskTriggerDay) at $($Config.TaskTriggerTime)." -ForegroundColor Green
    Write-Host "To run it now: Start-ScheduledTask -TaskName '$($Config.TaskName)'"
    exit 0
}

# ---------------------------------------------------------------------------
# RUN THE SWEEP
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  Starting security sweep on $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

# Build argument list for security_sweep.py
$sweepArgs = @("--output", $Config.ReportFormat)
if ($Config.DisableChecks -ne "") {
    $sweepArgs += @("--disable", $Config.DisableChecks)
}

# Run the Python script; capture exit code
& $Config.PythonExe $Config.SweepScript @sweepArgs
$exitCode = $LASTEXITCODE

Write-Host ""
if ($exitCode -eq 1) {
    Write-Host "HIGH severity findings detected (exit code 1)." -ForegroundColor Red
} else {
    Write-Host "Sweep complete — no HIGH severity findings." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# FIND THE MOST RECENT REPORT FILE
# ---------------------------------------------------------------------------
$reportFile = Get-ChildItem -Path $Config.ScriptDir `
    -Filter "security_report_*.$($Config.ReportFormat)" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

# ---------------------------------------------------------------------------
# SEND EMAIL IF HIGH FINDINGS EXIST
# ---------------------------------------------------------------------------
if ($Config.SendEmail -and $exitCode -eq 1 -and $reportFile) {

    Write-Host "Sending alert email to $($Config.EmailTo)..." -ForegroundColor Yellow

    # Build a plain-text email body from the report
    if ($Config.ReportFormat -eq "json") {
        $reportData = Get-Content $reportFile.FullName | ConvertFrom-Json
        $highFindings = $reportData.findings | Where-Object { $_.severity -eq "HIGH" }
        $body = "Security sweep on $env:COMPUTERNAME found $($reportData.summary.high) HIGH severity issue(s).`n`n"
        $body += "Generated: $($reportData.generated)`n"
        $body += "Total findings: $($reportData.summary.total) "
        $body += "(HIGH: $($reportData.summary.high), MEDIUM: $($reportData.summary.medium), LOW: $($reportData.summary.low))`n`n"
        $body += "--- HIGH SEVERITY FINDINGS ---`n"
        foreach ($f in $highFindings) {
            $body += "  [HIGH] $($f.message)`n"
        }
        $body += "`nFull report attached.`n"
    } else {
        $body = "Security sweep on $env:COMPUTERNAME found HIGH severity issues.`n`n"
        $body += "See attached report for details.`n"
    }

    # Build SMTP credential
    $securePass = ConvertTo-SecureString $Config.SmtpPassword -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential(
        $Config.SmtpUser, $securePass
    )

    try {
        Send-MailMessage `
            -From      $Config.EmailFrom `
            -To        $Config.EmailTo `
            -Subject   $Config.EmailSubject `
            -Body      $body `
            -SmtpServer $Config.SmtpServer `
            -Port      $Config.SmtpPort `
            -UseSsl:$Config.SmtpUseSsl `
            -Credential $credential `
            -Attachments $reportFile.FullName

        Write-Host "Email sent successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to send email: $_" -ForegroundColor Red
        Write-Host "Report is saved at: $($reportFile.FullName)" -ForegroundColor Yellow
    }

} elseif ($Config.SendEmail -and $exitCode -eq 0) {
    Write-Host "No HIGH findings — email not sent." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# DONE
# ---------------------------------------------------------------------------
Write-Host ""
if ($reportFile) {
    Write-Host "Report saved: $($reportFile.FullName)" -ForegroundColor Cyan
}
Write-Host "Sweep finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
exit $exitCode

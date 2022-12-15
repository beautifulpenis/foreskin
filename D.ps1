# Based on https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1
# Updates:
#   14.03.2022: Added a way to get system for disabling tamper protection
# Usage:
#  >> powershell -ExecutionPolicy Bypass -File .\disable-windows-defender.ps1


## STEP 1 : Disable everything we can with immediate effect
Write-Host "    [+] Add exclusions"

# Add the whole system in Defender exclusions

67..90|foreach-object{
    $drive = [char]$_
    Add-MpPreference -ExclusionPath "$($drive):\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "$($drive):\*" -ErrorAction SilentlyContinue
}

Write-Host "    [+] Disable scanning engines (Set-MpPreference)"

Set-MpPreference -DisableArchiveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisablePrivacyMode $true -ErrorAction Ignore
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -ErrorAction Ignore
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Ignore
Set-MpPreference -MAPSReporting 0 -ErrorAction Ignore
Set-MpPreference -SevereThreatDefaultAction 6 -ErrorAction Ignore
Set-MpPreference -PUAProtection disable -ErrorAction Ignore

Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

$tasks = @(
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
)

foreach ($task in $tasks) {
    $parts = $task.split('\')
    $name = $parts[-1]
    $path = $parts[0..($parts.length-2)] -join '\'

    Write-Output "Trying to disable scheduled task $name"
    Disable-ScheduledTask -TaskName "$name" -TaskPath "$path"
}

Write-Output "Disabling Windows Defender via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 1
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 1

Write-Output "Disabling Windows Defender Services"
Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend")
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 3


Write-Host "    [+] Set default actions to Allow (Set-MpPreference)"

Set-MpPreference -LowThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction SilentlyContinue

Write-Host "    [+] Disable services"

$need_reboot = $false

# WdNisSvc Network Inspection Service 
# WinDefend Antivirus Service
# Sense : Advanced Protection Service

$svc_list = @("WdNisSvc", "WinDefend", "Sense")
foreach($svc in $svc_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
            Write-Host "        [i] Service $svc already disabled"
        } else {
            Write-Host "        [i] Disable service $svc (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
            $need_reboot = $true
        }
    } else {
        Write-Host "        [i] Service $svc already deleted"
    }
}

Write-Host "    [+] Disable drivers"

# WdnisDrv : Network Inspection System Driver
# wdfilter : Mini-Filter Driver
# wdboot : Boot Driver

$drv_list = @("WdnisDrv", "wdfilter", "wdboot")
foreach($drv in $drv_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
            Write-Host "        [i] Driver $drv already disabled"
        } else {
            Write-Host "        [i] Disable driver $drv (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4
            $need_reboot = $true
        }
    } else {
        Write-Host "        [i] Driver $drv already deleted"
    }
}

# Check if service running or not
if($(GET-Service -Name WinDefend).Status -eq "Running") {   
    Write-Host "    [+] WinDefend Service still running (reboot required)"
    $need_reboot = $true
} else {
    Write-Host "    [+] WinDefend Service not running"
}

if($need_reboot) {
    Write-Host "    [+] Please reboot and start again."

} else {

    # Configure the Defender registry to disable it (and the TamperProtection)
    # editing HKLM:\SOFTWARE\Microsoft\Windows Defender\ requires to be SYSTEM
    # So let's use a scheduled task as System as attackers do ;-)
    
    Write-Host "    [+] Disable all functionnalities with registry keys (SYSTEM privilege)"

    $commands = @(
    # Cloud-delivered protection:
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SpyNetReporting -Value 0',
    # Automatic Sample submission
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SubmitSamplesConsent -Value 0',
    # Tamper protection
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -Value 4',
    # Disable in registry
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1',
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1'
    )

    foreach ($command in $commands) {
        # To bypass escaping characters (doubles quotes), I'm using base64 encoded commands.
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $encodedcommand = [Convert]::ToBase64String($Bytes)
        $Time = New-ScheduledTaskTrigger -At 00:00 -Once
        $Action = New-ScheduledTaskAction -Execute PowerShell.exe -Argument "-NoProfile -encodedcommand $encodedcommand"
        $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName "Elevated-Command" -Trigger $Time -Action $Action -RunLevel Highest -User "nt authority\system" -Settings $Settings
        Start-ScheduledTask -TaskPath "\" -TaskName "Elevated-Command"
        Start-Sleep 2
        Unregister-ScheduledTask -TaskName "Elevated-Command" -Confirm:$false
    }

}

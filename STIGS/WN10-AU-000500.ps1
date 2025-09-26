
<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Daniel Osgood
    LinkedIn        : linkedin.com/in/daniel-osgood-672866289/
    GitHub          : github.com/CyberDanOsgood/LOGN_PACIFIC
    Date Created    : 2025-09-25
    Last Modified   : 2025-09-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE

    PS C:\> .\STIG-ID-WN10-AU-000500.ps1 
#>

# Run this script as Administrator

# Define values 
$regPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 0x8000  # 32768 KB = 32 MB

# Ensure the key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the registry value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type DWord

# Confirm the result
Get-ItemProperty -Path $regPath | Select-Object $valueName

<#
.SYNOPSIS
    This PowerShell script ensures that autorun commands are prevented from executing.

.NOTES
    Author          : Daniel Osgood
    LinkedIn        : linkedin.com/in/daniel-osgood-672866289/
    GitHub          : github.com/CyberDanOsgood/LOGN_PACIFIC
    Date Created    : 2025-09-26
    Last Modified   : 2025-09-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000185

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE

    PS C:\> .\STIG-ID-WN10-CC-000185.ps1 
#>

# Run this script as Administrator

# Define values 
$regPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoAutorun"
$valueData = 0x00000001

# Ensure the key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the registry value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type DWord

# Confirm the result
Get-ItemProperty -Path $regPath | Select-Object $valueName

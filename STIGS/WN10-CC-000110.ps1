<#
.SYNOPSIS
    This PowerShell script prevents the client computer from printing over HTTP.

.NOTES
    Author          : Daniel Osgood
    LinkedIn        : linkedin.com/in/daniel-osgood-672866289/
    GitHub          : github.com/CyberDanOsgood/LOGN_PACIFIC
    Date Created    : 2025-09-26
    Last Modified   : 2025-09-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000110

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE

    PS C:\> .\STIG-ID-WN10-CC-000110.ps1 
#>

# Run script as admin

# Define values 
$regPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$valueName = "DisableHTTPPrinting"
$valueData = 0x00000001

# Ensure the key exists
if (-not (Test-Path $regPath)) {
   New-Item -Path $regPath -Force -ItemType Directory | Out-Null
}

# Set the registry value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type DWord

# Confirm the result
Get-ItemProperty -Path $regPath | Select-Object $valueName

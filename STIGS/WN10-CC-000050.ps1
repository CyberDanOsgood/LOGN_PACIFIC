<#
.SYNOPSIS
    

.NOTES
    Author          : Daniel Osgood
    LinkedIn        : linkedin.com/in/daniel-osgood-672866289/
    GitHub          : github.com/CyberDanOsgood/LOGN_PACIFIC
    Date Created    : 2025-09-26
    Last Modified   : 2025-09-26
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000050

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE

    PS C:\> .\STIG-ID-WN10-CC-000050.ps1 
#>

# Run this script as Administrator

# Define values 
$regPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
$values = @{
    "\\*\SYSVOL"   = "RequireMutualAuthentication=1, RequireIntegrity=1"
    "\\*\NETLOGON" = "RequireMutualAuthentication=1, RequireIntegrity=1"
}

# Ensure the key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the registry values
foreach ($name in $values.Keys) {
    New-ItemProperty -Path $regPath -Name $name -Value $values[$name] -PropertyType String -Force | Out-Null
}

# Confirm the result
Get-ItemProperty -Path $regPath | Select-Object $valueName

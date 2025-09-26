<#
.SYNOPSIS
    This PowerShell script ensures that the account lockout duration is set to 15 minutes.

.NOTES
    Author          : Daniel Osgood
    LinkedIn        : linkedin.com/in/daniel-osgood-672866289/
    GitHub          : github.com/CyberDanOsgood/LOGN_PACIFIC
    Date Created    : 2025-09-25
    Last Modified   : 2025-09-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    PS C:\> .\STIG-ID-WN10-AC-000005.ps1 
#>

# Run as admin

# Set account lockout duration to 15 minutes
net accounts /lockoutduration:15

<#
.SYNOPSIS
Read-only sample for reviewing risky users in an approved lab tenant.

.DESCRIPTION
Demonstrates the shape of a Microsoft Graph risky user review without changing accounts,
sessions, policies, or tenant settings. Demo/reference only.

.EXAMPLE
.\Get-RiskyUsers-Sample.ps1 -UserPrincipalName user@example.com

.NOTES
Use only in lab/dev after review. Do not paste secrets, tokens, tenant IDs, or production data.
#>
param(
    [string]$UserPrincipalName = "user@example.com"
)

Write-Host "Sample read-only risky user review for $UserPrincipalName"
Write-Host "In a lab, review risk state, detections, recent sign-ins, MFA results, and device context."
Write-Host "Example read-only Graph cmdlet shape: Get-MgRiskyUser -Filter `"userPrincipalName eq '$UserPrincipalName'`""

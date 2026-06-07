<#
.SYNOPSIS
Read-only sample for reviewing Entra MFA status indicators.

.DESCRIPTION
Shows the type of MFA registration and sign-in context an analyst may review.
This reference does not change authentication methods, sessions, users, or policies.

.EXAMPLE
.\Get-EntraMFAStatus-Sample.ps1 -UserPrincipalName user@example.com
#>
param(
    [string]$UserPrincipalName = "user@example.com"
)

Write-Host "Sample read-only MFA status review for $UserPrincipalName"
Write-Host "Review MFA registration, recent failures, denied prompts, unfamiliar devices, and conditional access outcomes."
Write-Host "Example read-only review: compare user risk, sign-in risk, and authentication method details."

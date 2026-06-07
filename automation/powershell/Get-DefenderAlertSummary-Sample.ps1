<#
.SYNOPSIS
Read-only sample for summarizing Defender alert context.

.DESCRIPTION
Shows safe investigation fields to collect from Defender-style alert output.
This script does not isolate devices, delete files, change alert state, or modify tenant settings.

.EXAMPLE
.\Get-DefenderAlertSummary-Sample.ps1 -DeviceName DEVICE-NAME
#>
param(
    [string]$DeviceName = "DEVICE-NAME"
)

Write-Host "Sample read-only Defender alert summary for $DeviceName"
Write-Host "Collect alert title, severity, device, user, process tree, file path, hash, URL, and remediation status."
Write-Host "Example read-only review: query alert and evidence tables, then validate with a human analyst."

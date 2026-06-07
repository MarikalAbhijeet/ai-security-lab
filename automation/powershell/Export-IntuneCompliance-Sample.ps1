<#
.SYNOPSIS
Read-only sample for exporting Intune compliance context.

.DESCRIPTION
Demonstrates safe device-compliance fields to review during identity or endpoint triage.
This reference does not change compliance policies, device settings, or assignments.

.EXAMPLE
.\Export-IntuneCompliance-Sample.ps1 -DeviceName DEVICE-NAME
#>
param(
    [string]$DeviceName = "DEVICE-NAME"
)

Write-Host "Sample read-only Intune compliance review for $DeviceName"
Write-Host "Review compliance state, last check-in time, owner, OS version, and management status."
Write-Host "Example read-only cmdlet shape: Get-MgDeviceManagementManagedDevice -Filter `"deviceName eq '$DeviceName'`""

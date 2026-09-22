# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Security findings detection for the customer demo. Thin shell
    around scripts/security_finder.py.

    Runs six detection rules over the inventory CSV:
      orphaned_managed_disk, orphaned_public_ip, orphaned_load_balancer,
      orphaned_nat_gateway, empty_security_group, public_ip_on_unprotected_vm.

    Writes security_findings.csv and security_summary.json next to the
    inventory.

.PARAMETER InventoryPath
    Path to azure_inventory.csv (from Collect-ArmInventory.ps1).

.PARAMETER OutputDir
    Directory for outputs. Default: directory containing InventoryPath.

.EXAMPLE
    .\Collect-Security.ps1 -InventoryPath .\azure_inventory.csv
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InventoryPath,

    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

if (-not $OutputDir) {
    $OutputDir = Split-Path -Parent $InventoryPath
}
$null = New-Item -ItemType Directory -Force -Path $OutputDir

if (-not (Test-Path $InventoryPath)) {
    throw "inventory CSV not found at $InventoryPath. Run Collect-ArmInventory.ps1 first."
}

$findingsPath = Join-Path $OutputDir "security_findings.csv"
$summaryPath = Join-Path $OutputDir "security_summary.json"

$finderScript = Join-Path (Split-Path -Parent $PSScriptRoot) "scripts/security_finder.py"
if (-not (Test-Path $finderScript)) {
    throw "security_finder.py not found at $finderScript"
}

Write-Host "[security] invoking security_finder.py"
& python3 $finderScript $InventoryPath $findingsPath $summaryPath

if ($LASTEXITCODE -ne 0) {
    throw "security_finder.py exited with code $LASTEXITCODE"
}

$summary = Get-Content -Raw -Path $summaryPath | ConvertFrom-Json
Write-Host "[security] findings: total=$($summary.total_findings) high=$($summary.by_severity.high) medium=$($summary.by_severity.medium) low=$($summary.by_severity.low)"
Write-Host "[security] estimated_monthly_savings (synthetic): $($summary.estimated_monthly_savings_total)"
Write-Host "[security] findings CSV: $findingsPath"
Write-Host "[security] summary: $summaryPath"

exit 0

# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Cost-data collection for the customer demo. Thin shell around
    scripts/cost_router.py.

    If roles.json says can_read_cost_management=true, fetch Cost Management
    grouped queries (by resource) for the current RG scope. The actual
    data goes to actual_cost.json. Then shell out to cost_router.py with
    roles.json + inventory.csv + actual_cost.json; the Python script does
    the routing decision (actual vs synthetic) and writes back the updated
    inventory rows + a cost summary.

    If the role disallows, skip the API call entirely and let cost_router
    apply synthetic estimates via the rate card.

.PARAMETER InventoryPath
    Path to azure_inventory.csv (from Collect-ArmInventory.ps1).

.PARAMETER RolesPath
    Path to roles.json (from Test-Roles.ps1). Default: ./roles.json.

.PARAMETER OutputDir
    Directory for outputs. Default: directory containing InventoryPath.

.PARAMETER DemoId
    Identifier for the demo run. Used in the cost_router summary so
    downstream files can be tied back to a specific run.

.PARAMETER Multiplier
    Synthetic cost multiplier, clamped to [0.5, 2.0] in cost_router. Not
    applied to actual cost data.

.PARAMETER ForceCostStrategy
    Override the cost strategy for testing. One of:
      auto      (default) use the role-derived can_read_cost_management
      actual    force the Cost Management API path (CUR), regardless of role
      synthetic force the rate-card fallback path, regardless of role
    This lets you test BOTH data paths deterministically against the same
    environment, even when the operator's real role only grants one.

.EXAMPLE
    .\Collect-Cost.ps1 -InventoryPath .\azure_inventory.csv -DemoId "demo-2026-08-24-01"
    .\Collect-Cost.ps1 -InventoryPath .\azure_inventory.csv -ForceCostStrategy actual
    .\Collect-Cost.ps1 -InventoryPath .\azure_inventory.csv -ForceCostStrategy synthetic
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InventoryPath,

    [string]$RolesPath = ".\roles.json",
    [string]$OutputDir = "",
    [string]$DemoId = (([guid]::NewGuid()).ToString().Substring(0, 8)),
    [double]$Multiplier = 1.0,
    [ValidateSet("auto", "actual", "synthetic")]
    [string]$ForceCostStrategy = "auto"
)

$ErrorActionPreference = "Stop"

# ---- Setup ----

if (-not $OutputDir) {
    $OutputDir = Split-Path -Parent $InventoryPath
}
$null = New-Item -ItemType Directory -Force -Path $OutputDir

if (-not (Test-Path $RolesPath)) {
    throw "roles.json not found at $RolesPath. Run Test-Roles.ps1 first."
}
if (-not (Test-Path $InventoryPath)) {
    throw "inventory CSV not found at $InventoryPath. Run Collect-ArmInventory.ps1 first."
}

$roles = Get-Content -Raw -Path $RolesPath | ConvertFrom-Json
$roleCanActual = $roles.capabilities.can_read_cost_management

# Honor the -ForceCostStrategy override. This is a TEST hook: it lets us
# exercise both the CUR (actual) and fallback (synthetic) paths against the
# same environment regardless of the operator's real role.
switch ($ForceCostStrategy) {
    "actual"    { $canActual = $true;  Write-Host "[cost] FORCED strategy=actual (CUR path)" }
    "synthetic" { $canActual = $false; Write-Host "[cost] FORCED strategy=synthetic (fallback path)" }
    default     { $canActual = $roleCanActual }
}

Write-Host "[cost] demo_id: $DemoId"
Write-Host "[cost] can_read_cost_management (role): $roleCanActual"
Write-Host "[cost] can_read_cost_management (effective): $canActual"

# ---- Fetch actual cost data (best-effort) ----

$actualCostPath = Join-Path $OutputDir "actual_cost_by_resource.json"
$actualCostMap = @{}

if ($canActual) {
    Write-Host "[cost] can_read_cost_management=true; querying Cost Management API"

    try {
        # Get-AzAccessToken fails under az-token-bridge login (access-token auth
        # holds no refresh token). Fall back to the harness-exported ARM token.
        if ($env:DISIPATE_ARM_TOKEN) {
            $armToken = [string]$env:DISIPATE_ARM_TOKEN
        } else {
            $armToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
        }

        $ctx = Get-AzContext
        $subId = $ctx.Subscription.Id
        $rg = Get-AzResourceGroup -ErrorAction SilentlyContinue | Select-Object -First 1
        $scope = if ($rg) { "subscriptions/$subId/resourceGroups/$($rg.ResourceGroupName)" } else { "subscriptions/$subId" }

        # Cost Management grouped-by-ResourceId query. Timeframe MonthToDate.
        # Mirrors the msp_fallback_r2/Collect-ArmInventory.ps1 -IncludeActualAzureCosts
        # path, but RG-scoped and only the resource-grouping query (the demo
        # doesn't need by-service / by-location breakdowns).
        $body = @{
            type       = "Usage"
            timeframe  = "MonthToDate"
            dataset    = @{
                granularity = "None"
                aggregation = @{
                    totalCost = @{
                        name     = "Cost"
                        function = "Sum"
                    }
                }
                grouping = @(
                    @{
                        type = "Dimension"
                        name = "ResourceId"
                    }
                )
            }
        } | ConvertTo-Json -Depth 10 -Compress

        $url = "https://management.azure.com/$scope/providers/Microsoft.CostManagement/query?api-version=2023-03-01"

        $resp = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Body $body -Headers @{ Authorization = "Bearer $armToken" } -TimeoutSec 60

        # Response shape: { properties: { columns: [{name: "Cost"}, {name: "ResourceId"}], rows: [[73.0, "/x/y"], ...] } }
        if ($resp.properties -and $resp.properties.rows) {
            $colIndex = @{}
            for ($i = 0; $i -lt $resp.properties.columns.Count; $i++) {
                $colIndex[$resp.properties.columns[$i].name] = $i
            }
            $costIdx = $colIndex["Cost"]
            $ridIdx = $colIndex["ResourceId"]

            foreach ($row in $resp.properties.rows) {
                $rid = [string]$row[$ridIdx]
                $cost = [double]$row[$costIdx]
                if ($rid -and $cost -gt 0) {
                    # Extrapolate monthly from MTD cost. We're at MTD so
                    # this isn't perfect; but for a demo the order of
                    # magnitude is what matters, and the actual_cost
                    # flag in the manifest tells the operator this is MTD,
                    # not full-month.
                    $actualCostMap[$rid] = @{
                        estimated_hourly_cost  = [math]::Round($cost / 730, 6)
                        estimated_monthly_cost = [math]::Round($cost, 2)
                    }
                }
            }
        }

        Write-Host "[cost] got actual cost for $($actualCostMap.Count) resources"
    } catch {
        Write-Warning "[cost] Cost Management API call failed: $($_.Exception.Message). Falling back to synthetic."
        $actualCostMap = @{}
    }
} else {
    Write-Host "[cost] can_read_cost_management=false; using synthetic rate card only"
}

# Write actual cost map to JSON for cost_router.py
$actualCostMap | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $actualCostPath -Encoding utf8

# ---- Invoke cost_router.py ----

$routerScript = Join-Path (Split-Path -Parent $PSScriptRoot) "scripts/cost_router.py"
if (-not (Test-Path $routerScript)) {
    throw "cost_router.py not found at $routerScript"
}

$updatedInvPath = Join-Path $OutputDir "azure_inventory.csv"
$summaryPath = Join-Path $OutputDir "cost_summary.json"

Write-Host "[cost] invoking cost_router.py"
& python3 $routerScript $RolesPath $InventoryPath $actualCostPath $updatedInvPath $summaryPath $DemoId $Multiplier

if ($LASTEXITCODE -ne 0) {
    throw "cost_router.py exited with code $LASTEXITCODE"
}

# Surface the strategy decision to the operator (and to the orchestrator
# which greps for this line).
$summary = Get-Content -Raw -Path $summaryPath | ConvertFrom-Json
if ($summary.cost_strategy -eq "actual") {
    Write-Host "[cost] DEMO MODE: actual costs collected from Cost Management"
} else {
    Write-Host "[cost] DEMO MODE: estimated costs only (synthetic — Cost Management role not available or query failed)"
}
Write-Host "[cost] summary: strategy=$($summary.cost_strategy) resources_total=$($summary.resources_total) resources_with_actual=$($summary.resources_with_actual_cost) estimated_monthly_total=$($summary.estimated_monthly_cost_total)"

Write-Host "[cost] done. Updated inventory: $updatedInvPath"
Write-Host "[cost] cost summary: $summaryPath"

exit 0

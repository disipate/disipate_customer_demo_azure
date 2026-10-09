# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Pulls the full Azure resource inventory for the current RG (or specified
    scope) via Resource Graph, paging past the 1,000-record-per-call limit,
    and writes azure_inventory.csv.

    Customer-demo variant of the standard Mode-C ARM inventory collector.
    Differences from the msp_fallback_r2 reference:

      * Default scope is RG (subscriptions/<id>/resourceGroups/<name>),
        not the whole subscription.
      * VM metrics use raw REST + UrlEncode (the script.ps1 pattern; never
        Get-AzMetric in Cloud Shell).
      * -DemoMode switch writes to <output>/demo/<run-id>/ and calls
        obfuscate.py against the output before returning.
      * Emits azure_metrics.csv with header-only rows when the operator
        lacks Monitoring Reader / Reader at the scope.

.PARAMETER Scope
    Azure scope to query. Defaults to current subscription + first RG
    in the current context.

.PARAMETER OutputDir
    Directory for output files. Default: ./azure_inventory relative
    to the script.

.PARAMETER DemoMode
    When set, run obfuscate.py against the output after writing.

.PARAMETER SaltPath
    Path to the per-run salt.bin. Required when -DemoMode is set.

.EXAMPLE
    .\Collect-ArmInventory.ps1 -DemoMode -SaltPath .\review\salt.bin -OutputDir .\review
#>

param(
    [string]$Scope = "",
    [string]$OutputDir = ".\azure_inventory",
    [switch]$DemoMode,
    [string]$SaltPath = ""
)

$ErrorActionPreference = "Stop"

# ---- Helpers ----

function Get-Scope {
    if ($Scope) { return $Scope }
    $ctx = Get-AzContext
    if (-not $ctx) { throw "No Az context. Run Connect-AzAccount first." }
    $subId = $ctx.Subscription.Id
    $rg = Get-AzResourceGroup -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($rg) {
        return "subscriptions/$subId/resourceGroups/$($rg.ResourceGroupName)"
    }
    return "subscriptions/$subId"
}

function Get-FullInventory {
    param([string]$ResourceGraphScope, [string]$KqlQuery)

    # Search-AzGraph has no -ResourceGroup parameter. RG scoping must be
    # injected into the KQL itself (filter before the final projection).
    $rgName = $null
    if ($ResourceGraphScope -match "^subscriptions/([^/]+)/resourceGroups/([^/]+)$") {
        $subId = $Matches[1]
        $rgName = $Matches[2]
    } elseif ($ResourceGraphScope -match "^subscriptions/([^/]+)$") {
        $subId = $Matches[1]
    } else {
        throw "Unsupported scope '$ResourceGraphScope'. Expected subscriptions/<sub>/resourceGroups/<rg> or subscriptions/<sub>."
    }

    if ($rgName) {
        # Escape single quotes for the KQL string literal.
        $escaped = $rgName -replace "'", "''"
        $KqlQuery = $KqlQuery -replace "\| project ", "| where resourceGroup == '$escaped' | project "
    }

    $all = [System.Collections.Generic.List[object]]::new()
    $skipToken = $null
    $pageSize = 1000

    do {
        $params = @{
            Query        = $KqlQuery
            First        = $pageSize
            Subscription = @($subId)
        }
        if ($skipToken) { $params["SkipToken"] = $skipToken }

        $resp = Search-AzGraph @params
        if ($resp.Data) { $all.AddRange([object[]]$resp.Data) }
        Write-Host "[inventory] page returned $($resp.Data.Count); total $($all.Count)"
        $skipToken = $resp.SkipToken
    } while ($skipToken)

    return $all
}

function Get-VmMetricsRest {
    <#
    Raw REST with [System.Web.HttpUtility]::UrlEncode. The script.ps1 pattern.
    Get-AzMetric is unreliable inside Cloud Shell for the standard VM metric
    set, so we never use it here.

    Returns a hashtable of metric_name -> average (or $null on failure).
    #>
    param(
        [string]$ResourceId,
        [string]$ArmToken,
        [string]$Timespan = "P7D"
    )

    $metricNames = "Percentage CPU,Network In Total,Network Out Total,Disk Read Operations/Sec,Disk Write Operations/Sec"
    $encoded = [System.Web.HttpUtility]::UrlEncode($metricNames)
    $url = "https://management.azure.com$ResourceId/providers/Microsoft.Insights/metrics?api-version=2021-05-01&metricnames=$encoded&aggregation=Average&interval=PT1H&timespan=$Timespan"

    try {
        $resp = Invoke-RestMethod -Uri $url -Headers @{ Authorization = "Bearer $ArmToken" } -Method Get -TimeoutSec 30
        $out = @{}
        foreach ($m in @($resp.value)) {
            $name = $m.name.value
            $avg = $null
            foreach ($ts in @($m.timeseries)) {
                foreach ($d in @($ts.data)) {
                    if ($null -ne $d.average) {
                        if ($null -eq $avg) { $avg = 0 }
                        $avg += [math]::Round([double]$d.average, 4)
                    }
                }
            }
            $out[$name] = $avg
        }
        return $out
    } catch {
        Write-Warning "[metrics] $ResourceId failed: $($_.Exception.Message)"
        return @{}
    }
}

# ---- Main ----

$null = New-Item -ItemType Directory -Force -Path $OutputDir

$effectiveScope = Get-Scope
Write-Host "[inventory] scope: $effectiveScope"
Write-Host "[inventory] output: $OutputDir"

# KQL: project the columns Disipate cares about.
$Query = @"
Resources
| project id, name, type, location, resourceGroup, subscriptionId, tags, sku, kind, properties
| order by id asc
"@

$resources = Get-FullInventory -ResourceGraphScope $effectiveScope -KqlQuery $Query

# Flatten each resource row to a stable schema row matching the existing
# azure_inventory.csv contract.
$inventoryRows = [System.Collections.Generic.List[object]]::new()
foreach ($r in @($resources)) {
    $skuName = ""
    $skuTier = ""
    if ($r.sku) {
        $skuName = [string]$r.sku.name
        $skuTier = [string]$r.sku.tier
    }
    $tagsJson = "{}"
    if ($r.tags) {
        try { $tagsJson = ($r.tags | ConvertTo-Json -Depth 5 -Compress) } catch { $tagsJson = "{}" }
    }
    $propsJson = "{}"
    if ($r.properties) {
        try { $propsJson = ($r.properties | ConvertTo-Json -Depth 10 -Compress) } catch { $propsJson = "{}" }
    }

    $row = [ordered]@{
        cloud_provider                     = "azure"
        subscription_id                    = [string]$r.subscriptionId
        resource_group                     = [string]$r.resourceGroup
        resource_id                        = [string]$r.id
        resource_name                      = [string]$r.name
        resource_type                      = [string]$r.type
        location                           = [string]$r.location
        sku_name                           = $skuName
        sku_tier                           = $skuTier
        kind                               = [string]$r.kind
        tags_json                          = $tagsJson
        properties_json                    = $propsJson
        owner_tag                          = ""
        environment_tag                    = ""
        estimated_hourly_cost              = ""
        estimated_monthly_cost             = ""
        cost_is_synthetic                  = ""
        actual_cost_available_for_subscription = ""
        cost_estimation_method             = ""
        collected_at                       = (Get-Date).ToUniversalTime().ToString("o")
    }
    $inventoryRows.Add([pscustomobject]$row)
}

$inventoryPath = Join-Path $OutputDir "azure_inventory.csv"
$inventoryRows | Export-Csv -Path $inventoryPath -NoTypeInformation -Encoding utf8
Write-Host "[inventory] wrote $($inventoryRows.Count) rows to $inventoryPath"

# ---- VM metrics ----

# Only attempt metrics for VMs. Skip if the operator lacks arm-metrics
# capability (capability hint is in roles.json — Test-Roles.ps1 wrote it).
$canReadMetrics = $true
$rolesPath = Join-Path (Split-Path -Parent $OutputDir) "roles.json"
if (Test-Path $rolesPath) {
    try {
        $roles = Get-Content -Raw -Path $rolesPath | ConvertFrom-Json
        if ($roles.capabilities.can_read_arm_metrics -eq $false) {
            $canReadMetrics = $false
        }
    } catch {}
}

$metricRows = [System.Collections.Generic.List[object]]::new()
if ($canReadMetrics) {
    # Get-AzAccessToken fails under az-token-bridge login (access-token auth holds
    # no refresh token, so Az can't re-mint without hitting a possibly-blocked app).
    # Fall back to the ARM token the harness exported (DISIPATE_ARM_TOKEN).
    if ($env:DISIPATE_ARM_TOKEN) {
        $armTokenPlain = [string]$env:DISIPATE_ARM_TOKEN
    } else {
        $armToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com" -AsSecureString).Token
        # Convert SecureString to plain text. The script runs in Cloud Shell
        # where the local user owns the token; never logged or persisted.
        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($armToken)
        try {
            $armTokenPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ssPtr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
        }
    }

    foreach ($r in @($resources)) {
        if ($r.type -ne "Microsoft.Compute/virtualMachines") { continue }
        $m = Get-VmMetricsRest -ResourceId $r.id -ArmToken $armTokenPlain
        $metricRows.Add([pscustomobject][ordered]@{
            subscription_id         = [string]$r.subscriptionId
            resource_id             = [string]$r.id
            resource_name           = [string]$r.name
            resource_group          = [string]$r.resourceGroup
            location                = [string]$r.location
            avg_cpu_percent         = $m["Percentage CPU"]
            avg_network_in_total    = $m["Network In Total"]
            avg_network_out_total   = $m["Network Out Total"]
            avg_disk_read_ops       = $m["Disk Read Operations/Sec"]
            avg_disk_write_ops      = $m["Disk Write Operations/Sec"]
            metric_timespan         = "P7D"
            collected_at            = (Get-Date).ToUniversalTime().ToString("o")
        })
    }
} else {
    Write-Host "[inventory] can_read_arm_metrics=false; writing header-only azure_metrics.csv"
}

$metricsPath = Join-Path $OutputDir "azure_metrics.csv"
$metricRows | Export-Csv -Path $metricsPath -NoTypeInformation -Encoding utf8
Write-Host "[inventory] wrote $($metricRows.Count) metric rows to $metricsPath"

# ---- Demo-mode obfuscation ----

if ($DemoMode) {
    if (-not $SaltPath) {
        throw "-DemoMode requires -SaltPath (the per-run salt.bin)."
    }
    if (-not (Test-Path $SaltPath)) {
        throw "salt file not found: $SaltPath"
    }
    Write-Host "[inventory] demo mode: obfuscating outputs"
    $obfuscateScript = Join-Path (Split-Path -Parent $PSScriptRoot) "scripts/obfuscate.py"
    $multiplier = 1.0  # Collect-Cost.ps1 overwrites inventory cost columns; multiplier here only affects raw rows
    $manifestPath = Join-Path $OutputDir "azure_inventory.obfuscation_manifest.json"

    & python3 $obfuscateScript $inventoryPath $inventoryPath $SaltPath $manifestPath $multiplier | Out-Null
    Write-Host "[inventory] obfuscation manifest written to $manifestPath"
}

Write-Host "[inventory] done"
exit 0

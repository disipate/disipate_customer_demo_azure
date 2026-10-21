# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Enumerates the signed-in operator's Azure RBAC assignments across tenant
    root, every management group, and every visible active subscription, then
    produces a capabilities hint for downstream collectors.

    Customer-demo variant of the role probe. Adds two capability flags
    on top of the standard set:

      can_read_cost_management  - Cost Management Reader/Contributor at the
                                  current scope (drives Collect-Cost.ps1
                                  routing: actual vs synthetic)
      can_write_blob            - can the operator PUT to the Disipate demo
                                  blob container (either Storage Blob Data
                                  Contributor on the container, or a
                                  working SAS URL via $env:DISIPATE_SAS_URL)

    Writes roles.json with the per-scope assignments and a top-level
    capabilities block. Writes a one-line capability summary to stdout that
    the orchestrator can grep.

.DESCRIPTION
    Probe reports DIRECT role assignments only. RBAC inheritance via Entra
    ID group membership is the realistic case for an operator in a customer's
    tenant, so the capability hint can be conservatively false-negative.
    Documented in roles.json.notes.

.PARAMETER Scope
    The Azure scope to probe. Defaults to the current subscription
    context (subscriptions/<sub-id>/resourceGroups/<rg-name>). The
    demo collector operates RG-scoped, not subscription-scoped.

.PARAMETER RolesPath
    Where to write the JSON output. Default is ./roles.json next to the
    script.

.PARAMETER DisipateSasUrl
    Optional. The SAS URL the operator pasted at install time. When present,
    the probe does a HEAD probe against the container to confirm it
    works, and sets can_write_blob accordingly.

.EXAMPLE
    .\Test-Roles.ps1 -Scope "subscriptions/<sub>/resourceGroups/<rg>"
#>

param(
    [string]$Scope = "",
    [string]$RolesPath = ".\roles.json",
    [string]$DisipateSasUrl = $env:DISIPATE_SAS_URL
)

$ErrorActionPreference = "Stop"

# ---- Helpers ----

function Get-OperatorIdentity {
    <#
    Resolve the signed-in principal. Order matters:
      1. Get-AzADUser by mail (after stripping upn/ or oid/ prefix)
      2. Get-AzADUser by UserPrincipalName
      3. Get-AzADServicePrincipal for SP principals (rare in Cloud Shell)
      4. Fall back to "Unknown" with the raw id
    #>
    $ctx = Get-AzContext
    if (-not $ctx) { return @{ id = "Unknown"; type = "unknown"; display_name = "Unknown" } }

    $accountId = $ctx.Account.Id
    $bare = $accountId -replace '^[^/]+/', ''

    try {
        $u = Get-AzADUser -Mail $bare -ErrorAction SilentlyContinue
        if ($u) { return @{ id = $bare; type = "user"; display_name = $u.DisplayName } }
    } catch {}

    try {
        $u = Get-AzADUser -UserPrincipalName $bare -ErrorAction SilentlyContinue
        if ($u) { return @{ id = $bare; type = "user"; display_name = $u.DisplayName } }
    } catch {}

    try {
        $sp = Get-AzADServicePrincipal -ServicePrincipalName "https://graph.microsoft.com/accounts/$bare" -ErrorAction SilentlyContinue
        if ($sp) { return @{ id = $bare; type = "service_principal"; display_name = $sp.DisplayName } }
    } catch {}

    return @{ id = $bare; type = "unknown"; display_name = "Unknown" }
}

function Get-DirectRoleAssignments {
    <#
    Enumerate direct role assignments at a given scope.
    Returns an array of @{ role_name; scope; principal_id }.
    #>
    param([string]$ScopeId)

    if (-not $ScopeId) { return @() }
    # Get-AzRoleAssignment requires the scope to start with a leading '/',
    # but collector scopes are conventionally passed WITHOUT one (e.g.
    # "subscriptions/<sub>/resourceGroups/<rg>"). Normalize so the probe
    # doesn't silently error into an empty assignment set / false negatives.
    $norm = if ($ScopeId.StartsWith("/")) { $ScopeId } else { "/$ScopeId" }
    try {
        $assigns = Get-AzRoleAssignment -Scope $norm -ErrorAction SilentlyContinue
        $out = @()
        foreach ($a in @($assigns)) {
            $out += [ordered]@{
                role_name    = $a.RoleDefinitionName
                scope        = $a.Scope
                principal_id = $a.ObjectId
            }
        }
        return $out
    } catch {
        Write-Warning "[roles] $ScopeId unreachable: $($_.Exception.Message)"
        return @()
    }
}

function Test-CostManagementCapability {
    <#
    Cost Management Reader / Contributor / Reader at the scope grants
    can_read_cost_management. Reader (the general one) at the scope also
    grants it, since Reader inherits all read actions.
    #>
    param([string]$ScopeId, [array]$Assignments)

    $costRoles = @(
        "Cost Management Contributor",
        "Cost Management Reader",
        "Contributor",
        "Owner",
        "Reader"
    )
    foreach ($a in $Assignments) {
        if ($costRoles -contains $a.role_name) { return $true }
    }
    return $false
}

function Test-ArmInventoryCapability {
    param([array]$Assignments)
    $armRoles = @("Reader", "Contributor", "Owner")
    foreach ($a in $Assignments) {
        if ($armRoles -contains $a.role_name) { return $true }
    }
    return $false
}

function Test-ArmMetricsCapability {
    <#
    Monitoring Reader is the specific role for VM metrics; Reader at the
    scope also gets it.
    #>
    param([array]$Assignments)
    $metricsRoles = @("Monitoring Reader", "Reader", "Contributor", "Owner")
    foreach ($a in $Assignments) {
        if ($metricsRoles -contains $a.role_name) { return $true }
    }
    return $false
}

function Test-BlobWriteCapability {
    <#
    Either:
      (a) Storage Blob Data Contributor at the container scope (rare for
          a customer — they wouldn't normally have rights on Disipate infra)
      (b) A working SAS URL pasted in. We probe with HEAD + ?comp=list.

    Returns $true if either path works.
    #>
    param([string]$SasUrl, [array]$Assignments)

    if ($SasUrl) {
        try {
            $probeUri = "$SasUrl&comp=list" -replace "&comp=list&comp=list", "&comp=list"
            if ($probeUri -notmatch "\?") { $probeUri = "$SasUrl`?comp=list" }
            $resp = Invoke-WebRequest -Uri $probeUri -Method Head -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            if ($resp.StatusCode -lt 400) { return $true }
        } catch {
            # The exception message can echo the probe URI, SAS query included.
            $msg = $_.Exception.Message -replace '(?i)\b(sig|sv|se|sp|spr|sr|sktid|skoid|skt|ske|sks|skv)=[^&\s"]*', '$1=<redacted>'
            Write-Warning "[blob] SAS probe failed: $msg"
        }
    }

    foreach ($a in $Assignments) {
        if ($a.role_name -in @("Storage Blob Data Contributor", "Owner", "Contributor")) {
            return $true
        }
    }
    return $false
}

# ---- Main ----

$operator = Get-OperatorIdentity

# Resolve the scope to probe. If -Scope wasn't passed, derive it from
# the current Az context (RG if available, else subscription).
if (-not $Scope) {
    $ctx = Get-AzContext
    if (-not $ctx) {
        throw "No Az context. Run Connect-AzAccount first."
    }
    $subId = $ctx.Subscription.Id
    $rg = Get-AzResourceGroup -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($rg) {
        $Scope = "subscriptions/$subId/resourceGroups/$($rg.ResourceGroupName)"
    } else {
        $Scope = "subscriptions/$subId"
    }
}

Write-Host "[roles] operator: $($operator.display_name) ($($operator.id))"
Write-Host "[roles] scope: $Scope"

# Probe direct assignments at the chosen scope.
$assignments = Get-DirectRoleAssignments -ScopeId $Scope

# Also enumerate management groups and active subscriptions so the manifest
# is complete enough for downstream scripts to reason about.
$mgs = @()
try {
    $mgs = @(Get-AzManagementGroup -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
} catch {}
Write-Host "[roles] management groups: $($mgs.Count)"

$subs = @()
try {
    $subs = @(Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Active" } | ForEach-Object { $_.Id })
} catch {}
Write-Host "[roles] active subscriptions: $($subs.Count)"

# Build capability hint.
$can_read_arm_inventory = Test-ArmInventoryCapability -Assignments $assignments
$can_read_arm_metrics = Test-ArmMetricsCapability -Assignments $assignments
$can_read_cost_management = Test-CostManagementCapability -ScopeId $Scope -Assignments $assignments
$can_write_blob = Test-BlobWriteCapability -SasUrl $DisipateSasUrl -Assignments $assignments
$is_owner = $false
foreach ($a in $assignments) { if ($a.role_name -eq "Owner") { $is_owner = $true; break } }

$rolesDoc = [ordered]@{
    collected_at  = (Get-Date).ToUniversalTime().ToString("o")
    tenant_id     = (Get-AzContext).Tenant.Id
    account_id    = (Get-AzContext).Account.Id
    scope         = $Scope
    operator      = $operator
    capabilities  = [ordered]@{
        can_read_arm_inventory   = $can_read_arm_inventory
        can_read_arm_metrics     = $can_read_arm_metrics
        can_read_cost_management = $can_read_cost_management
        can_read_billing         = $false  # NEVER in this mode
        can_write_blob           = $can_write_blob
        is_owner                 = $is_owner
    }
    assignments_at_scope = $assignments
    management_groups    = $mgs
    subscription_ids     = $subs
    notes = @(
        "Direct role assignments only. RBAC inheritance via Entra ID group membership is not expanded; capability hint may be conservatively false-negative.",
        "can_read_billing is hardcoded to false in demo mode; customers almost never have Billing Reader / EA Enrollment Reader."
    )
}

$rolesDoc | ConvertTo-Json -Depth 10 | Out-File -FilePath $RolesPath -Encoding utf8

# One-line capability summary for orchestrator to grep.
$summary = "capabilities: arm_inventory=$can_read_arm_inventory arm_metrics=$can_read_arm_metrics cost_mgmt=$can_read_cost_management write_blob=$can_write_blob"
Write-Host "[roles] $summary"
Write-Host "[roles] written to $RolesPath"

# Exit codes: 0 = probe succeeded; manifest written.
exit 0

# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Orchestrator for the Disipate Azure customer demo collector. Runs the
    full pipeline in sequence: role probe, ARM inventory, cost, security,
    obfuscation, then pauses for customer review before upload.

    Flag matrix (per plan §8.5):

      (no flag)              Inspect mode. Default. Prompt + wait.
      -Inspect               Same as default.
      -AutoApprove           Skip prompt, log auto-approve, upload immediately.
      -DryRun                Skip prompt, never upload. Inspect only.
      -Review <run-id>       Re-display REVIEW.md from a previous run.
      -Reject <run-id>       Discard artifacts for a previous run.
      -CleanupSalt           Shred every salt.bin under the review dir tree.

    Exit codes:
      0  success (or upload approved)
      1  pre-flight failed (no Az context, missing roles.json, etc.)
      2  collector stage failed
      3  Customer rejected the upload
      4  non-interactive invocation with no flag (see plan §8.5)

.PARAMETER Scope
    Azure scope to probe. Default: current RG.

.PARAMETER OutputDir
    Directory for review artifacts. Default: $HOME/clouddrive/disipate-demo-review/<run-id>.

.PARAMETER DisipateSasUrl
    Override for $env:DISIPATE_SAS_URL when the operator wants to pass it inline.

.EXAMPLE
    .\Collect-All.ps1    # default: run, prompt for approval
#>

param(
    [string]$Scope = "",
    [string]$OutputDir = "",
    [string]$DisipateSasUrl = $env:DISIPATE_SAS_URL,
    [switch]$Inspect,
    [switch]$AutoApprove,
    [switch]$DryRun,
    [string]$Review = "",
    [string]$Reject = "",
    [switch]$CleanupSalt
)

$ErrorActionPreference = "Stop"

$collectorsDir = $PSScriptRoot
$scriptsDir = Join-Path (Split-Path -Parent $collectorsDir) "scripts"
$templatesDir = Join-Path (Split-Path -Parent $collectorsDir) "templates"

# ---- Handle management flags first (no collector run needed) ----

if ($CleanupSalt) {
    $cloudDrive = Join-Path $env:HOME "clouddrive"
    $root = Join-Path $cloudDrive "disipate-demo-review"
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Recurse -Filter "salt.bin" | ForEach-Object {
            Remove-Item -Path $_.FullName -Force
            Write-Host "[cleanup] shredded $($_.FullName)"
        }
        Write-Host "[cleanup] done"
    } else {
        Write-Host "[cleanup] no review directory at $root; nothing to do"
    }
    exit 0
}

if ($Review) {
    $cloudDrive = Join-Path $env:HOME "clouddrive"
    $reviewDir = Join-Path $cloudDrive "disipate-demo-review/$Review"
    $reviewMd = Join-Path $reviewDir "REVIEW.md"
    if (-not (Test-Path $reviewMd)) {
        Write-Error "REVIEW.md not found at $reviewMd"
        exit 1
    }
    Get-Content -Raw $reviewMd | Out-Host
    exit 0
}

if ($Reject) {
    $cloudDrive = Join-Path $env:HOME "clouddrive"
    $reviewDir = Join-Path $cloudDrive "disipate-demo-review/$Reject"
    if (Test-Path $reviewDir) {
        Get-ChildItem -Path $reviewDir -Recurse -Filter "salt.bin" | Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $reviewDir -Recurse -Force
        Write-Host "[reject] discarded $reviewDir (including salt)"
    } else {
        Write-Host "[reject] no review directory at $reviewDir; nothing to do"
    }
    exit 0
}

# ---- Determine the upload-gate behavior ----

# Detect non-interactive invocation: piped stdin, "run as script" button,
# scheduled task, etc. The reliable test is [Console]::IsInputRedirected.
$isInteractive = -not [Console]::IsInputRedirected
$skipPrompt = $AutoApprove -or $DryRun

if (-not $isInteractive -and -not $skipPrompt) {
    Write-Error "Non-interactive mode detected. Re-run with -AutoApprove to upload without prompting, or -DryRun to skip upload entirely."
    exit 4
}

# ---- Set up the run directory ----

$runId = ([guid]::NewGuid()).ToString().Substring(0, 8)
$collectedAt = (Get-Date).ToUniversalTime().ToString("o")

if (-not $OutputDir) {
    $cloudDrive = Join-Path $env:HOME "clouddrive"
    if (Test-Path $cloudDrive) {
        $OutputDir = Join-Path $cloudDrive "disipate-demo-review/$runId"
    } else {
        $OutputDir = ".\disipate-demo-review"
    }
}
$null = New-Item -ItemType Directory -Force -Path $OutputDir

Write-Host "============================================================"
Write-Host "Disipate Azure Customer Demo Collector"
Write-Host "Run ID:    $runId"
Write-Host "Output:    $OutputDir"
Write-Host "============================================================"

# ---- Generate the salt ----

$saltPath = Join-Path $OutputDir "salt.bin"
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
[System.IO.File]::WriteAllBytes($saltPath, $bytes)
$rng.Dispose()
Write-Host "[setup] salt written to $saltPath (32 bytes; never uploaded)"

# ---- Stage 1: role probe ----

Write-Host ""
Write-Host "----- Stage 1: role probe -----"
$rolesPath = Join-Path $OutputDir "roles.json"
& pwsh -NoProfile -File (Join-Path $collectorsDir "Test-Roles.ps1") -Scope $Scope -RolesPath $rolesPath -DisipateSasUrl $DisipateSasUrl
if ($LASTEXITCODE -ne 0) { throw "Test-Roles.ps1 failed"; exit 1 }

# ---- Stage 2: ARM inventory ----

Write-Host ""
Write-Host "----- Stage 2: ARM inventory -----"
$inventoryDir = Join-Path $OutputDir "azure_inventory"
$null = New-Item -ItemType Directory -Force -Path $inventoryDir
$inventoryPath = Join-Path $inventoryDir "azure_inventory.csv"
& pwsh -NoProfile -File (Join-Path $collectorsDir "Collect-ArmInventory.ps1") -Scope $Scope -OutputDir $inventoryDir -DemoMode -SaltPath $saltPath
if ($LASTEXITCODE -ne 0) { throw "Collect-ArmInventory.ps1 failed"; exit 2 }

# ---- Stage 3: cost ----

Write-Host ""
Write-Host "----- Stage 3: cost -----"
& pwsh -NoProfile -File (Join-Path $collectorsDir "Collect-Cost.ps1") -InventoryPath $inventoryPath -RolesPath $rolesPath -OutputDir $inventoryDir -DemoId $runId -Multiplier 1.0
if ($LASTEXITCODE -ne 0) { throw "Collect-Cost.ps1 failed"; exit 2 }

# ---- Stage 4: security findings ----

Write-Host ""
Write-Host "----- Stage 4: security findings -----"
& pwsh -NoProfile -File (Join-Path $collectorsDir "Collect-Security.ps1") -InventoryPath $inventoryPath -OutputDir $inventoryDir
if ($LASTEXITCODE -ne 0) { throw "Collect-Security.ps1 failed"; exit 2 }

# ---- Stage 5: obfuscation ----

Write-Host ""
Write-Host "----- Stage 5: obfuscation -----"
$multiplier = 1.0  # cost columns already set; this only obfuscates other identifier columns
$inventoryManifestPath = Join-Path $inventoryDir "azure_inventory.obfuscation_manifest.json"
& python3 (Join-Path $scriptsDir "obfuscate.py") $inventoryPath $inventoryPath $saltPath $inventoryManifestPath $multiplier
if ($LASTEXITCODE -ne 0) { throw "obfuscate.py (inventory) failed"; exit 2 }

$findingsCsv = Join-Path $inventoryDir "security_findings.csv"
$findingsManifestPath = Join-Path $inventoryDir "security_findings.obfuscation_manifest.json"
if (Test-Path $findingsCsv) {
    & python3 (Join-Path $scriptsDir "obfuscate.py") $findingsCsv $findingsCsv $saltPath $findingsManifestPath $multiplier
    if ($LASTEXITCODE -ne 0) { throw "obfuscate.py (findings) failed"; exit 2 }
}

$summaryPath = Join-Path $inventoryDir "cost_summary.json"
$securitySummaryPath = Join-Path $inventoryDir "security_summary.json"

# ---- Stage 6: REVIEW.md + inspection gate ----

Write-Host ""
Write-Host "----- Stage 6: review -----"

# Collect the file manifest for REVIEW.md
$filesToUpload = @()
$fileManifest = @()
$totalBytes = 0
foreach ($f in @($inventoryPath, (Join-Path $inventoryDir "azure_metrics.csv"), (Join-Path $inventoryDir "roles.json"), $summaryPath, $securitySummaryPath, $findingsCsv, $inventoryManifestPath, $findingsManifestPath)) {
    if (Test-Path $f) {
        $size = (Get-Item $f).Length
        $totalBytes += $size
        $rows = ""
        if ($f -like "*.csv") {
            try { $rows = " ($(($(Import-Csv $f) | Measure-Object).Count) rows)" } catch {}
        }
        $fileManifest += "| $($f | Split-Path -Leaf) | $($size) bytes$rows |"
    }
}

# Load the cost + security summaries for the capability block.
$costSummary = $null
if (Test-Path $summaryPath) {
    $costSummary = Get-Content -Raw $summaryPath | ConvertFrom-Json
}
$secSummary = $null
if (Test-Path $securitySummaryPath) {
    $secSummary = Get-Content -Raw $securitySummaryPath | ConvertFrom-Json
}
$roles = Get-Content -Raw $rolesPath | ConvertFrom-Json

$capSummary = @()
$capSummary += "- Operator: $($roles.operator.display_name) ($($roles.operator.id))"
$capSummary += "- Tenant: $($roles.tenant_id)"
$capSummary += "- Scope: $($roles.scope)"
$capSummary += "- arm_inventory: $($roles.capabilities.can_read_arm_inventory)"
$capSummary += "- arm_metrics: $($roles.capabilities.can_read_arm_metrics)"
$capSummary += "- cost_management: $($roles.capabilities.can_read_cost_management)"
$capSummary += "- write_blob: $($roles.capabilities.can_write_blob)"

$costBlock = if ($costSummary) {
    @(
        "Strategy: **$($costSummary.cost_strategy)**",
        "Resources inventoried: $($costSummary.resources_total)",
        "Resources with actual cost: $($costSummary.resources_with_actual_cost)",
        "Estimated monthly total: `$$($costSummary.estimated_monthly_cost_total)`"
    ) -join "`n"
} else {
    "(no cost summary produced)"
}

$secBlock = if ($secSummary) {
    @(
        "Total findings: $($secSummary.total_findings)",
        "- high: $($secSummary.by_severity.high)",
        "- medium: $($secSummary.by_severity.medium)",
        "- low: $($secSummary.by_severity.low)",
        "Estimated monthly savings (synthetic): `$$($secSummary.estimated_monthly_savings_total)`"
    ) -join "`n"
} else {
    "(no security summary produced)"
}

$disclaimerBlock = @(
    "All customer identifiers in the uploaded CSVs are replaced with SHA-256 fragments",
    "keyed to a per-run salt (`salt.bin`). The salt stays on this machine. Even",
    "Disipate cannot recover the original identifiers from the uploaded data. If",
    "you lose `salt.bin`, the obfuscation is permanent — there is no recovery path.",
    "",
    "Disipate does not see real resource names, subscription IDs, tenant IDs, tags,",
    "or PII. What Disipate receives is a one-way-hashed view sufficient for sizing",
    "and severity analysis but not for joining against any historical record."
) -join "`n"

$signoff = @(
    "```",
    "approve    upload the artifacts to Disipate",
    "reject     discard artifacts and exit (code 3)",
    "review     re-display this file in the editor",
    "```"
) -join "`n"

# Apply placeholder substitution. Templates use {{name}} form.
$templatePath = Join-Path $templatesDir "REVIEW.md"
$template = Get-Content -Raw $templatePath

$substitutions = @{
    "{{csp_name}}"              = "Disipate"
    "{{run_id}}"                = $runId
    "{{collected_at}}"          = $collectedAt
    "{{scope}}"                 = $roles.scope
    "{{file_manifest}}"         = ($fileManifest -join "`n")
    "{{total_files}}"           = $fileManifest.Count
    "{{total_size_mb}}"         = [math]::Round($totalBytes / 1MB, 2)
    "{{review_dir}}"            = $OutputDir
    "{{capability_summary}}"    = ($capSummary -join "`n")
    "{{cost_strategy_block}}"   = "$costBlock`n`n$secBlock"
    "{{disclaimer_block}}"      = $disclaimerBlock
    "{{signoff}}"               = $signoff
}

$review = $template
foreach ($k in $substitutions.Keys) {
    $review = $review.Replace($k, [string]$substitutions[$k])
}

$reviewMdPath = Join-Path $OutputDir "REVIEW.md"
$review | Out-File -FilePath $reviewMdPath -Encoding utf8
Write-Host "[review] wrote $reviewMdPath"

# ---- Inspection gate ----

if ($skipPrompt) {
    if ($DryRun) {
        Write-Host ""
        Write-Host "============================================================"
        Write-Host "DRY RUN: artifacts are in $OutputDir"
        Write-Host "Inspect $reviewMdPath and the CSVs in $inventoryDir"
        Write-Host "Re-run with -AutoApprove to upload, or -Reject <run-id> to discard."
        Write-Host "============================================================"
        exit 0
    }
    # AutoApprove path: log the bypass in the manifest and proceed.
    Write-Host "[review] AutoApprove: skipping prompt; uploading."
} else {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "Review directory: $OutputDir"
    Write-Host "Files ready for upload: $($fileManifest.Count) ($([math]::Round($totalBytes / 1MB, 2)) MB total)"
    if ($costSummary) {
        Write-Host "Cost strategy: $($costSummary.cost_strategy), est monthly: `$$($costSummary.estimated_monthly_cost_total)`"
    }
    if ($secSummary) {
        Write-Host "Security findings: $($secSummary.total_findings) (savings `$$($secSummary.estimated_monthly_savings_total)`)"
    }
    Write-Host ""
    Write-Host "Type 'review' to open the review file,"
    Write-Host "     'approve' to upload now,"
    Write-Host "     'reject'  to discard and exit."
    Write-Host "============================================================"
    $choice = Read-Host
    switch ($choice.Trim().ToLower()) {
        "approve" { Write-Host "[review] approved; uploading." }
        "reject" {
            Get-ChildItem -Path $OutputDir -Recurse -Filter "salt.bin" | Remove-Item -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $OutputDir -Recurse -Force
            Write-Host "[review] rejected; artifacts discarded."
            exit 3
        }
        "review" {
            try { code $reviewMdPath } catch { Get-Content $reviewMdPath | Out-Host }
            # Re-prompt after review
            Write-Host ""
            $choice = Read-Host "Type 'approve' or 'reject'"
            if ($choice.Trim().ToLower() -ne "approve") {
                Get-ChildItem -Path $OutputDir -Recurse -Filter "salt.bin" | Remove-Item -Force -ErrorAction SilentlyContinue
                Remove-Item -Path $OutputDir -Recurse -Force
                Write-Host "[review] not approved; artifacts discarded."
                exit 3
            }
        }
        default {
            Write-Host "[review] unrecognized input; treating as reject"
            Get-ChildItem -Path $OutputDir -Recurse -Filter "salt.bin" | Remove-Item -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $OutputDir -Recurse -Force
            exit 3
        }
    }
}

# ---- Stage 7: build demo_findings.json ----

Write-Host ""
Write-Host "----- Stage 7: build demo_findings.json -----"
$demoFindingsPath = Join-Path $OutputDir "demo_findings.json"
& python3 (Join-Path $scriptsDir "make_demo_manifest.py") `
    --review-dir $OutputDir `
    --roles $rolesPath `
    --cost-summary $summaryPath `
    --security-summary $securitySummaryPath `
    --demo-id $runId `
    --output $demoFindingsPath
if ($LASTEXITCODE -ne 0) { throw "make_demo_manifest.py failed"; exit 2 }

# ---- Stage 8: upload ----

if ($AutoApprove -or (-not $DryRun)) {
    Write-Host ""
    Write-Host "----- Stage 8: upload -----"
    & pwsh -NoProfile -File (Join-Path $collectorsDir "Push-Blob.ps1") `
        -FilesToUpload @($inventoryPath, (Join-Path $inventoryDir "azure_metrics.csv"), $summaryPath, $securitySummaryPath, $findingsCsv, $inventoryManifestPath, $findingsManifestPath, $demoFindingsPath) `
        -SasUrl $DisipateSasUrl `
        -DemoId $runId
    if ($LASTEXITCODE -ne 0) { throw "Push-Blob.ps1 failed"; exit 2 }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "Done."
Write-Host "Run directory: $OutputDir"
if ($AutoApprove) {
    Write-Host "Upload: completed (auto-approved)."
} elseif ($DryRun) {
    Write-Host "Upload: skipped (dry run)."
} else {
    Write-Host "Upload: completed (approved)."
}
Write-Host "============================================================"
exit 0

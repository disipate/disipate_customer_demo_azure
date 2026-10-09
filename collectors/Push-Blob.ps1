# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Upload demo artifacts to a Disipate-managed Azure Blob container via
    a Disipate-provided SAS URL.

    Auth: SAS URL only. No app registration, no secrets, no managed
    identity. The operator pastes a SAS URL at install time (24h TTL, scoped
    to create+write on a single container). The script PUTs each file
    using Invoke-RestMethod with the SAS appended.

    Retry policy: each PUT gets up to 3 attempts with exponential
    backoff on transient failures (5xx, network errors). 4xx errors
    are NOT retried — they indicate auth/scope failure and won't
    resolve on retry. Partial uploads are recorded in the
    demo_findings.json.partial flag.

.PARAMETER FilesToUpload
    Array of file paths to upload. Each becomes a blob at
    <container>/<demo-id>/<basename>.

.PARAMETER SasUrl
    The Disipate-provided SAS URL. Defaults to $env:DISIPATE_SAS_URL.

.PARAMETER DemoId
    Blob path prefix for this run. Default: caller-supplied.

.EXAMPLE
    .\Push-Blob.ps1 -FilesToUpload @(".\azure_inventory.csv",".\cost_summary.json") -DemoId "abc123"
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$FilesToUpload,

    [string]$SasUrl = $env:DISIPATE_SAS_URL,

    [string]$DemoId = ""
)

$ErrorActionPreference = "Stop"

if (-not $SasUrl) {
    throw "No SAS URL. Set \$env:DISIPATE_SAS_URL or pass -SasUrl."
}

if (-not $DemoId) {
    $DemoId = ([guid]::NewGuid()).ToString().Substring(0, 8)
}

# Parse the SAS URL once. The base URL is everything before the query
# string; the SAS query string is everything after. Each blob is
# <base>/<demo-id>/?<sas>.
$baseUrl = ($SasUrl -split "\?")[0]
$sasQuery = ($SasUrl -split "\?")[1]
if (-not $sasQuery.StartsWith("?")) { $sasQuery = "?" + $sasQuery }

Write-Host "[upload] base: $baseUrl"
Write-Host "[upload] demo_id: $DemoId"
Write-Host "[upload] files: $($FilesToUpload.Count)"

$results = @()
$partial = $false

foreach ($file in $FilesToUpload) {
    if (-not (Test-Path $file)) {
        Write-Warning "[upload] $file not found, skipping"
        $results += [ordered]@{
            file = $file
            status = "skipped"
            error = "file not found"
        }
        continue
    }
    $name = Split-Path -Leaf $file
    $blobUrl = "$baseUrl/$DemoId/$name$sasQuery"
    $size = (Get-Item $file).Length

    Write-Host "[upload] $name ($size bytes) -> $blobUrl"

    $attempts = 0
    $maxAttempts = 3
    $ok = $false
    $lastError = ""

    while ($attempts -lt $maxAttempts -and -not $ok) {
        $attempts++
        try {
            $headers = @{
                "x-ms-blob-type"         = "BlockBlob"
                "x-ms-blob-content-type" = if ($name -like "*.csv") { "text/csv" }
                                           elseif ($name -like "*.json") { "application/json" }
                                           else { "application/octet-stream" }
            }
            Invoke-RestMethod -Uri $blobUrl -Method Put -InFile $file -Headers $headers -TimeoutSec 120 | Out-Null
            Write-Host "[upload]   attempt $attempts: ok"
            $ok = $true
            $results += [ordered]@{
                file = $file
                name = $name
                status = "uploaded"
                size = $size
                attempts = $attempts
            }
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            $lastError = "$($_.Exception.Message) (HTTP $code)"
            if ($code -ge 400 -and $code -lt 500) {
                # 4xx: don't retry. Auth/scope failure won't fix itself.
                Write-Warning "[upload]   attempt $attempts: 4xx, aborting: $lastError"
                $partial = $true
                break
            }
            Write-Warning "[upload]   attempt $attempts: $lastError; retrying"
            Start-Sleep -Seconds ([math]::Pow(2, $attempts))
        }
    }

    if (-not $ok -and -not ($lastError -match "HTTP 4")) {
        Write-Warning "[upload] $name failed after $maxAttempts attempts: $lastError"
        $partial = $true
        $results += [ordered]@{
            file = $file
            name = $name
            status = "failed"
            attempts = $attempts
            error = $lastError
        }
    }
}

# Write the upload log next to the artifacts.
$logPath = Join-Path (Split-Path -Parent (Split-Path -Parent $FilesToUpload[0])) "upload_log.json"
$log = [ordered]@{
    demo_id = $DemoId
    uploaded_at = (Get-Date).ToUniversalTime().ToString("o")
    partial = $partial
    results = $results
}
$log | ConvertTo-Json -Depth 10 | Out-File -FilePath $logPath -Encoding utf8
Write-Host "[upload] log: $logPath"

if ($partial) {
    Write-Warning "[upload] partial upload; downstream consumers should ignore this demo_id."
    exit 2
}

Write-Host "[upload] complete"
exit 0

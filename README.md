<!-- Copyright (c) 2026 Disipate -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Disipate Customer Demo for Azure

A read-only Azure collector that produces a cost + security findings report
from a customer's own subscription, without Disipate ever seeing the
customer's real resource names.

Run it in the customer's Azure Cloud Shell during a demo. It collects the
resource inventory, cost data, and security findings for one resource group,
hashes every identifier with a per-run salt that never leaves the machine,
shows you exactly what would be uploaded, and waits for you to type
`approve` before anything leaves the tenant.

Licensed under the Apache License 2.0 — see [Licensing](#licensing). The
source is meant to be read by your security reviewers.

---

## 60-second version

```
# 1. In Azure Cloud Shell, install the collector
bash <(curl -fsSL https://raw.githubusercontent.com/gatortim/disipate_customer_demo_azure/main/install_cloudshell.sh)

# 2. Paste the SAS URL your Disipate contact gave you
export DISIPATE_SAS_URL="https://account.blob.core.windows.net/container?<sas>"

# 3. Run the demo
Collect-All.ps1

# 4. Read the REVIEW.md the script produces, type 'approve'
```

That's it. The script pauses before uploading anything so you and the
customer can read what would leave the tenant.

## What the script actually does

1. **Probes the signed-in operator's roles.** Lists what you can do in the
   tenant — direct assignments only, group inheritance noted but not
   expanded.
2. **Pulls the resource inventory** for the current resource group via
   Resource Graph. Same data the Azure Portal shows, in CSV form.
3. **Pulls actual cost data** from Cost Management if the role allows,
   otherwise falls back to a synthetic rate-card estimate. The script
   says out loud which path ran.
4. **Detects security findings** — orphaned disks, public IPs with no NIC,
   empty NSGs, internet-facing VMs with no NSG. Six rule types, each
   tagged with severity and a synthetic savings estimate.
5. **Obfuscates everything** with a per-run salt that stays on the
   customer's machine. Even Disipate cannot recover the original resource
   names.
6. **Writes REVIEW.md** and pauses for sign-off.
7. **Uploads** on approval. Rejected runs discard artifacts and shred the
   salt.

## What gets uploaded

On approval, the script uploads these files to the Disipate blob:

- `azure_inventory.csv` — obfuscated resource inventory
- `azure_metrics.csv` — VM CPU / network / disk metrics (P7D average)
- `cost_summary.json` — strategy, totals, savings
- `security_findings.csv` — per-finding detail
- `security_summary.json` — counts by severity
- `azure_inventory.obfuscation_manifest.json` — schema version + salt fingerprint
- `security_findings.obfuscation_manifest.json` — same
- `demo_findings.json` — the summary Disipate ingests

What does NOT get uploaded: the salt, the un-obfuscated inventory,
anything from your session, the customer's tags verbatim, the customer's
actual location strings (regional enum only).

## Privacy guarantees

- **Salt never leaves the tenant.** Lose it and the obfuscation is permanent.
- **All identifiers are SHA-256 fragments** (16 hex chars), not reversible.
- **Cost columns may be scaled** by a clamped random multiplier (0.5–2.0) so
  the distribution stays realistic but the absolute values are not exact.
- **Tags get value-only placeholders** (`tag-0`, `tag-1`, …); keys are
  preserved because they're needed for finding logic.

If the customer asks "can you see our data?" the honest answer is **no, and
we never could**. The obfuscation runs on their machine, before anything
leaves. You can read the transform in `scripts/obfuscate.py`.

## Flag matrix

| Invocation | Stages 1–5 | Inspection gate | Stage 6 (upload) |
|---|---|---|---|
| `Collect-All.ps1` (default) | run | prompt + wait for input | only after approve |
| `Collect-All.ps1 -AutoApprove` | run | skip prompt | run immediately |
| `Collect-All.ps1 -DryRun` | run | skip prompt | never |
| `Collect-All.ps1 -Review <run-id>` | skip | skip prompt | skip |
| `Collect-All.ps1 -Reject <run-id>` | skip | skip prompt | never; shred salt |
| `Collect-All.ps1 -CleanupSalt` | skip | skip prompt | skip; shred every salt |

`-AutoApprove` exists for non-interactive automation. Use it during recorded
demos only if you've already read the review template.

## Exit codes

- `0` — success
- `1` — pre-flight failed (no Az context, modules missing)
- `2` — collector stage failed
- `3` — you rejected the upload
- `4` — non-interactive invocation without an explicit flag. Re-run with
  `-AutoApprove` or `-DryRun`.

## Prerequisites

- Azure Cloud Shell (bash). PowerShell 7+ on macOS works for local
  development, but you'll need `Az.Accounts`, `Az.Resources`, and
  `Az.CostManagement` installed via `Install-Module -Scope CurrentUser`.
- Python 3.9+ on `PATH` — the three analyzer modules are Python and are
  invoked by the PowerShell collectors via `python3`.
- A Disipate-provided SAS URL. Ask your Disipate contact for one; they are
  scoped to a single container, 24h TTL, write-only.
- Reader or higher on the resource group you want to demo. Cost Management
  Reader gets you actual cost data; anything else falls back to synthetic
  estimates.

## Running it

### In Azure Cloud Shell (the supported path)

The one-liner above clones this repo to
`$HOME/clouddrive/disipate-customer-demo-azure` and symlinks the collectors
into `$HOME/bin`, so `Collect-All.ps1` resolves on `PATH`. `$HOME/clouddrive`
is an Azure Files share and survives Cloud Shell session refreshes, so
re-running the installer is safe and idempotent.

Then pin the scope you want to demo against — the script demos one resource
group at a time:

```
Set-AzContext -Subscription <sub-id>
Collect-All.ps1 -Scope subscriptions/<sub-id>/resourceGroups/<rg-name>
```

### Locally (development)

```
git clone https://github.com/gatortim/disipate_customer_demo_azure.git
cd disipate_customer_demo_azure
./install_cloudshell.sh
```

Everything except the Azure calls works off a saved inventory CSV, which is
how the tests exercise the analyzers.

## Tests

The Python modules carry the business logic and are covered by pytest. No
cloud credentials or network access required — the tests are pure:

```
python3 -m pytest tests/ -v
```

The suite has **no third-party dependencies**: pytest is only the runner, and
every test file also executes standalone on the standard library's unittest
module if pytest isn't installed:

```
for f in tests/test_*.py; do python3 "$f"; done
```

The PowerShell collectors handle Azure I/O only (token acquisition, REST
calls, CSV writing) and are not part of the test suite.

## Troubleshooting

**The script says "Non-interactive mode detected."**
You're running it piped or via the Cloud Shell "run as script" button.
Re-run with `-AutoApprove` to upload without prompting, or `-DryRun` to
inspect without uploading.

**Cost Management 403.**
The role allows the call but the RG isn't in scope. The script falls back
to synthetic estimates automatically — check the demo's `cost_strategy`
field.

**Empty inventory.**
The signed-in identity has no ARM access to the current RG. Run
`Get-AzResourceGroup` to see what's visible, or `Set-AzContext
-Subscription <other-sub>` to switch.

**Cloud Shell session expired.**
Cloud Shell containers can be wiped. The salt, the review directory, and
the install all live on the attached Azure Files share, so they survive.
Re-run `Collect-All.ps1` to start a fresh run.

## What it deliberately does NOT do

- **Never touches Billing APIs.** No `Microsoft.Billing/*`, no rate cards,
  no invoices. Demos must not depend on EA enrollment access.
- **Never makes outbound calls outside Azure.** No third-party telemetry.
  No license-check pings.
- **Never stores credentials.** No app registration, no client secret, no
  managed identity. The SAS URL is the only auth material, and it's scoped
  to one container for 24h.
- **Never writes to the customer's subscription.** Read-only. No tags are
  applied, no resources are modified or deleted.

## Architecture

The collector is a thin PowerShell shell around four Python modules:

| Module | What it does |
|---|---|
| `scripts/obfuscate.py` | One-way CSV transform with SHA-256 + salt |
| `scripts/cost_router.py` | Role-driven cost routing (actual vs synthetic) |
| `scripts/security_finder.py` | Six detection rules for orphaned resources |
| `scripts/make_demo_manifest.py` | Builds `demo_findings.json` |

The PowerShell side (`collectors/*.ps1`) handles Azure I/O only:
token acquisition, REST calls, CSV writing. Every piece of testable business
logic lives in Python where the project has a working test environment.

```
.
├── README.md              (this file)
├── LICENSE                Apache License 2.0
├── sample.env             Environment template
├── install_cloudshell.sh  Cloud Shell bootstrap
├── collectors/            PowerShell: Test-Roles, Collect-{ArmInventory,Cost,Security,All}, Push-Blob
├── scripts/               Python: obfuscate, cost_router, security_finder, make_demo_manifest
├── templates/REVIEW.md    The review document template
└── tests/                 pytest tests for the Python modules
```

## After a demo

Always run cleanup:

```
Collect-All.ps1 -CleanupSalt
```

This shreds every `salt.bin` under the review directory tree. Old obfuscated
data in the Disipate blob is unaffected (Disipate never had the salts) but
cleaning up the local copy is good hygiene.

## Scope of this repo

This repository contains the **client-side collector only**. The Disipate
platform itself — ingestion, normalization, analysis, the GraphQL API, the
customer dashboard — is proprietary and lives elsewhere. Nothing in this repo
contacts Disipate infrastructure except the single `Push-Blob` upload to a
SAS-scoped container that you supply and can revoke.

## Licensing

Copyright (c) Disipate.

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify,
and redistribute this code, including commercially, subject to the terms of
that license. Every source file carries an
`SPDX-License-Identifier: Apache-2.0` header.

Two things the license does *not* grant:

- **Trademarks.** Apache-2.0 §6 does not grant rights to the "Disipate" name
  or logo. Please don't imply endorsement of a fork.
- **Warranty.** The license ships this code "AS IS", without warranty of any
  kind. It reads your Azure environment; verify the scope and the review
  document before you approve an upload.

Contributions submitted as pull requests are accepted under Apache-2.0 as
provided in §5 of the license.

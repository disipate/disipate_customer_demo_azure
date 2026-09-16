<!-- SPDX-License-Identifier: Apache-2.0 -->
# {{csp_name}} Demo Review

**Run ID:** `{{run_id}}`
**Collected at:** {{collected_at}}
**Scope:** {{scope}}

> **Read this before approving upload.** This page lists every file that
> would leave your tenant if you approve. All customer identifiers are
> replaced with SHA-256 fragments keyed to a per-run salt. The salt
> stays on this machine; even Disipate cannot recover the original
> identifiers. If anything below looks wrong, type `reject` at the
> prompt and the artifacts will be discarded.

---

## What gets uploaded

{{file_manifest}}

Total: **{{total_files}} files, {{total_size_mb}} MB total.**

## What stays on your machine

- The salt file (`salt.bin`). Lose this and the obfuscation is permanent.
- This review directory: `{{review_dir}}`.
- All PowerShell + Python source code (already in the installer package).

## What was collected

{{capability_summary}}

## Cost strategy

{{cost_strategy_block}}

## Disclaimer

{{disclaimer_block}}

---

Type one of:

- `approve` — upload the artifacts to Disipate.
- `reject`  — discard artifacts and exit.
- `review`  — open this file in the editor (Cloud Shell `code` command).

{{signoff}}

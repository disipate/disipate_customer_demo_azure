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

## What the obfuscation does NOT hide

Read this section carefully. It describes what is still visible in the
uploaded files, so that nothing here surprises you later.

**Tag keys are preserved; only tag values are replaced.** A tag like
`Owner = jane.doe@contoso.com` becomes `Owner = tag-0` — the key stays.
Tag keys are kept because Disipate's finding logic uses them, but keys are
frequently identifying on their own. If you use tag keys that name people,
teams, systems, clients, or projects (for example `Owner`, `Project`,
`ClientName`, `CostCenter` on a per-tenant scheme), **those key names will
be visible in the uploaded inventory**. Reject the upload, or rename those
tags, if that is not acceptable.

**Network security group rule names are preserved.** A rule named
`allow-ssh-from-contractor-j-smith` uploads with that name intact. Rule names
are kept so the exposure findings can tell you *which* rule permits traffic.
If your rule names are descriptive, treat them as disclosed.

**Resource types, SKUs, tiers, kinds, and locations are preserved verbatim.**
These are needed for cost and finding analysis. They describe the *shape* of
your estate, not its identity, but they are not obfuscated.

**Everything outside an allow-list is dropped from resource properties.**
Disipate retains only the property fields its detection rules read (network
interface and NSG wiring, disk attachment state, and NSG rule definitions).
Fields such as `osProfile`, `customData`, `provisioningState`, and rule
descriptions are removed entirely before upload — not hashed, dropped.

**Resource references inside properties are hashed with the same salt** as
the resource ID column, so a reference to a network interface matches that
interface's own row. This is what lets findings remain accurate after
obfuscation. The salt never leaves this machine.

If any of the above is not acceptable for this environment, type `reject`.

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

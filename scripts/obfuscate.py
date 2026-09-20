# SPDX-License-Identifier: Apache-2.0
"""obfuscate.py — privacy-preserving CSV transformer for the Disipate
customer demo collector.

Before any CSV leaves the customer's tenant, every identifier column is replaced
with a deterministic SHA-256 fragment keyed to a per-run salt, and every
cost column is scaled by a clamped random multiplier. A manifest JSON is
written next to the output with the multiplier, the salt's *fingerprint*
(not the salt), and the schema version, so the customer can audit what
transformation was applied without exposing the salt itself.

Design notes:
- Salt is 32 bytes, never uploaded. If lost, identifiers are unrecoverable.
- Multiplier is clamped to [0.5, 2.0] so a bug can't produce negative savings.
- Identifier column list is explicit (allow-list, not deny-list).
- Tags get value-placeholder substitution; keys are preserved verbatim
  (key shape is needed by downstream finding logic; values are not).
  Both `tags` (semicolon form) and `tags_json` (ARM JSON form) are covered —
  the ARM collector emits `tags_json`, so a `tags`-only rule silently leaked
  every tag value.
- `properties_json` is an unbounded bag straight from ARM. It is rebuilt
  through an explicit ALLOW-LIST (`PROPERTIES_ALLOWLIST`): only the keys the
  detection rules actually read survive, everything else is dropped, and ARM
  resource paths inside it are hashed with the *same* transform as
  `resource_id` so cross-row joins (NIC -> NSG, NIC -> public IP) still
  resolve after obfuscation. This matters because ARM nests full
  `/subscriptions/<guid>/...` paths inside `networkProfile`,
  `networkSecurityGroup`, `ipConfigurations`, `ipConfiguration` and
  `managedDisk` — none of which are columns, so no deny-list of column names
  can catch them.
- Resource groups get a `rg-demo-<8 hex>` constant prefix so they look
  real in the output but cannot be tied back to the prospect.
- Location, sku, tier, kind pass through verbatim (needed for findings).
- All stdlib, no deps — runs anywhere Python 3.11+ runs.
"""

import csv
import hashlib
import json
import os
import random
import sys
from typing import Any, Dict, List, Union

OBFUSCATION_SCHEMA_VERSION = "1.1"


# Columns that get the hash transform. Allow-list — anything not listed is
# left alone unless it's a cost column (separate list).
IDENTIFIER_COLUMNS = frozenset(
    {
        "resource_id",
        "resource_name",
        "subscription_id",
        "tenant_id",
        "object_id",
        "user_principal_name",
        "display_name",
        "mail",
        "storage_account_name",
        "key_vault_name",
        "public_ip",
    }
)

# Columns that get the multiplier transform.
COST_COLUMNS = frozenset(
    {
        "cost",
        "quantity",
        "estimated_monthly_savings",
        "estimated_hourly_cost",
        "estimated_monthly_cost",
        "CostInBillingCurrency",
    }
)

MULTIPLIER_MIN = 0.5
MULTIPLIER_MAX = 2.0

# Length of the hashed identifier output, in hex chars. 16 = 8 bytes of
# the SHA-256, which gives enough uniqueness for a single prospect's
# resource set without bloating CSVs.
HASH_HEX_LEN = 16

# --- properties_json handling -------------------------------------------------
#
# `properties_json` is a raw ARM properties bag. It cannot be handled with a
# column deny-list because the identifying values are *nested inside it* as
# substrings: ARM writes full resource paths such as
#   /subscriptions/<guid>/resourceGroups/<rg>/providers/Microsoft.Network/networkInterfaces/<name>
# inside networkProfile.networkInterfaces[].id, networkSecurityGroup.id,
# ipConfigurations[].id, ipConfiguration.id and managedDisk.id.
#
# Two rules keep this both private and useful:
#   1. ALLOW-LIST the keys. Only keys the detection rules read survive;
#      everything else (provisioningState, osProfile, customData, ...) is
#      dropped. This is how the transform fails closed on new ARM fields.
#   2. Hash any string that looks like an ARM resource id, using the SAME
#      hash_identifier transform as the resource_id column, so a hashed
#      reference still equals the hashed resource_id of the row it points at.
#      Without this the NIC -> NSG join would break after obfuscation.
#
# Note the rules read `securityRules` (empty_security_group). To decide
# whether a VM is effectively exposed we need each rule's direction, access,
# priority, ports and protocol — so those subkeys are allow-listed too.
PROPERTIES_ALLOWLIST = frozenset(
    {
        # The ARM path holder. Every nested reference below lives under an
        # `id` key, so omitting `id` would silently drop the join keys.
        "id",
        # orphaned_managed_disk
        "diskState",
        # orphaned_public_ip / VM->NIC and NIC->IP wiring
        "ipConfiguration",
        "ipConfigurations",
        # VM -> NIC
        "networkProfile",
        "networkInterfaces",
        # NIC -> NSG (the association the old rule could not resolve)
        "networkSecurityGroup",
        "networkSecurityGroups",
        "virtualMachine",
        # VM -> disk
        "managedDisk",
        # empty_security_group + NSG rule semantics
        "securityRules",
        "defaultSecurityRules",
    }
)

# Subkeys allow-listed inside NSG rules. These are the fields that decide
# whether a rule permits inbound traffic; ports/protocol are retained so the
# exposure question is answerable. `description` is deliberately excluded
# (free text, may name internal systems).
SECURITY_RULE_ALLOWLIST = frozenset(
    {
        "name",
        "direction",
        "access",
        "priority",
        "protocol",
        "sourceAddressPrefix",
        "sourceAddressPrefixes",
        "destinationAddressPrefix",
        "destinationAddressPrefixes",
        "destinationPortRange",
        "destinationPortRanges",
        "sourcePortRange",
        "sourcePortRanges",
    }
)

# Marker used when a string is unambiguously an ARM resource id.
_ARM_ID_PREFIXES = ("/subscriptions/", "/providers/", "/resourceGroups/")

# Depth cap. ARM properties are shallow in practice; the cap stops a
# pathological payload from turning the transform into a DoS vector.
_MAX_PROPERTY_DEPTH = 8



def hash_identifier(value: str, salt: bytes) -> str:
    """One-way SHA-256 transform. Same input + same salt -> same output.
    Different salts -> different outputs. Output is HASH_HEX_LEN hex chars."""
    if value is None:
        return ""
    h = hashlib.sha256()
    h.update(salt)
    h.update(value.encode("utf-8"))
    return h.hexdigest()[:HASH_HEX_LEN]


def fingerprint_salt(salt: bytes) -> str:
    """SHA-256 of the salt, hex-encoded. Lets us prove two runs used the
    same salt without ever exposing the salt itself."""
    return hashlib.sha256(salt).hexdigest()


def clamp_multiplier(m: float) -> float:
    """Clamp the cost multiplier to [MULTIPLIER_MIN, MULTIPLIER_MAX]. A bug
    that produces e.g. -1.0 would turn a $100 line into -$100, which would
    invert savings findings. Don't allow that."""
    if m < MULTIPLIER_MIN:
        return MULTIPLIER_MIN
    if m > MULTIPLIER_MAX:
        return MULTIPLIER_MAX
    return m


def parse_tags(value: Union[str, Dict[str, str], None]) -> Union[str, Dict[str, str], None]:
    """Replace tag values with `tag-N` placeholders. Preserve keys verbatim.
    Returns the same shape it received (dict in -> dict out, str in -> str out).

    The str case is for the Cost Management CSV format, which serializes
    tags as `key1=value1;key2=value2`. The dict case is for the ARM
    inventory format, which uses proper JSON.
    """
    if value is None or value == "" or value == {}:
        return value

    if isinstance(value, dict):
        return {k: f"tag-{i}" for i, k in enumerate(value.keys())}

    if isinstance(value, str):
        # semicolon-separated "k=v;k=v" form
        if "=" not in value:
            return value  # not actually key=value pairs
        parts = value.split(";")
        out_parts = []
        for i, part in enumerate(parts):
            if "=" in part:
                k, _ = part.split("=", 1)
                out_parts.append(f"{k}=tag-{i}")
            else:
                out_parts.append(part)
        return ";".join(out_parts)

    return value


def _looks_like_arm_id(value: str) -> bool:
    """True when a string is unambiguously an ARM resource id.

    ARM resource ids always begin with `/subscriptions/`, `/providers/` or
    `/resourceGroups/`. The check is prefix-based rather than a full
    parse — a malformed id still leaks, and this transform should fail
    closed on anything id-shaped.
    """
    return value.startswith(_ARM_ID_PREFIXES)


def obfuscate_properties(
    value: Any, salt: bytes, _depth: int = 0
) -> Any:
    """Rebuild a parsed ARM properties bag so it retains only allow-listed
    keys, with every ARM resource id hashed by the same transform used for
    the `resource_id` column.

    Returns a JSON-serialisable structure. Unknown keys are DROPPED — the
    allow-list is the fail-closed mechanism, so a new identifying ARM field
    defaults to excluded rather than leaked.

    Hashing (rather than stripping) the ids is what keeps the cross-row
    rules working after obfuscation: a NIC reference inside `networkProfile`
    hashes to the same value as that NIC row's obfuscated `resource_id`.
    """
    if _depth > _MAX_PROPERTY_DEPTH:
        return None

    if isinstance(value, dict):
        # NSG rules get their own narrower allow-list.
        keys = (
            SECURITY_RULE_ALLOWLIST
            if _is_security_rule(value)
            else PROPERTIES_ALLOWLIST
        )
        out: Dict[str, Any] = {}
        for k, v in value.items():
            if k not in keys:
                continue
            cleaned = obfuscate_properties(v, salt, _depth + 1)
            if cleaned is not None:
                out[k] = cleaned
        return out

    if isinstance(value, list):
        return [
            c for c in (obfuscate_properties(v, salt, _depth + 1) for v in value)
            if c is not None
        ]

    if isinstance(value, str):
        if _looks_like_arm_id(value):
            return hash_identifier(value, salt)
        return value

    return value


def _is_security_rule(node: Dict[str, Any]) -> bool:
    """Heuristic: an NSG rule object carries `direction` and `access`.
    Used to pick the narrower rule allow-list regardless of the key name the
    rule list sits under (securityRules vs securityRules/defaultSecurityRules).
    """
    return "direction" in node and "access" in node


def obfuscate_properties_json(
    raw: Union[str, Dict[str, Any], None], salt: bytes
) -> str:
    """Apply obfuscate_properties to a `properties_json` CSV cell.

    Handles the empty/malformed cases the collector can emit. On any parse
    failure the value collapses to "{}" rather than passing through — a
    malformed bag is exactly the case where we cannot prove it is safe.
    """
    if raw is None or raw == "" or raw == {}:
        return "{}"

    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return "{}"
    else:
        parsed = raw

    if not isinstance(parsed, (dict, list)):
        return "{}"

    cleaned = obfuscate_properties(parsed, salt)
    try:
        return json.dumps(cleaned, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return "{}"


def obfuscate_tags_json(raw: Union[str, Dict[str, Any], None]) -> str:
    """Apply parse_tags to a `tags_json` CSV cell (the ARM JSON form).

    Collect-ArmInventory.ps1 emits `tags_json` as a JSON object, so this must
    parse then substitute. Passing it to the semicolon-string branch would
    no-op (no "=" in a JSON blob) and leak every tag value verbatim — which
    is precisely what happened before this was split out.
    """
    if raw is None or raw == "" or raw == {}:
        return "{}"

    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            # Unparseable tags: drop the values rather than pass them
            # through. Fail closed.
            return "{}"
    else:
        parsed = raw

    if not isinstance(parsed, dict):
        return "{}"

    substituted = parse_tags(parsed)
    try:
        return json.dumps(substituted, sort_keys=True)
    except (TypeError, ValueError):
        return "{}"


def obfuscate_row(row: Dict[str, str], salt: bytes, multiplier: float) -> Dict[str, str]:
    """Apply all per-column transforms to a single CSV row. Returns a new
    dict — does not mutate the input."""
    out: Dict[str, str] = {}
    for col, val in row.items():
        if col == "resource_group":
            # RG gets a constant demo prefix + 8 hex chars of the hash
            # so different RGs stay distinguishable but cannot be tied
            # back to the prospect's actual RG naming convention.
            if val is None or val == "":
                out[col] = ""
            else:
                h = hashlib.sha256()
                h.update(salt)
                h.update(val.encode("utf-8"))
                out[col] = f"rg-demo-{h.hexdigest()[:8]}"
            continue

        # Both tag shapes: `tags` is the Cost Management semicolon form,
        # `tags_json` is what Collect-ArmInventory.ps1 actually emits.
        # Missing tags_json here leaked every tag value verbatim. Note the
        # ARM form is JSON, so it is parsed before substitution; treating it
        # as the semicolon form would pass an unrecognised string straight
        # through (which is exactly how the leak survived).
        if col == "tags_json":
            out[col] = obfuscate_tags_json(val)
            continue

        if col == "tags":
            out[col] = parse_tags(val)  # type: ignore[assignment]
            continue

        # The ARM properties bag: nested resource paths live in here.
        if col == "properties_json":
            out[col] = obfuscate_properties_json(val, salt)
            continue

        if col in IDENTIFIER_COLUMNS:
            if val is None or val == "":
                out[col] = ""
            else:
                out[col] = hash_identifier(str(val), salt)
            continue

        if col in COST_COLUMNS:
            if val is None or val == "":
                out[col] = ""
            else:
                try:
                    out[col] = str(float(val) * multiplier)
                except (ValueError, TypeError):
                    # If the cost cell isn't numeric (e.g. "n/a"), leave it.
                    out[col] = val
            continue

        # Everything else passes through verbatim: location, sku, tier,
        # kind, meter_category, etc. These are needed for finding logic.
        out[col] = val

    return out



def obfuscate_csv(
    input_path: str,
    output_path: str,
    salt_path: str,
    manifest_path: str,
    multiplier: float,
) -> Dict[str, Any]:
    """Read input_path as CSV, write obfuscated rows to output_path, write
    manifest JSON to manifest_path. Returns the manifest dict."""
    with open(salt_path, "rb") as f:
        salt = f.read()
    if len(salt) < 32:
        raise ValueError(f"salt at {salt_path} must be at least 32 bytes")

    clamped = clamp_multiplier(multiplier)

    with open(input_path, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames: List[str] = list(reader.fieldnames or [])
        rows = [obfuscate_row(r, salt, clamped) for r in reader]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    manifest = {
        "schema_version": OBFUSCATION_SCHEMA_VERSION,
        "multiplier": clamped,
        "salt_fingerprint": fingerprint_salt(salt),
        "input_rows": len(rows),
        "identifier_columns": sorted(IDENTIFIER_COLUMNS),
        "cost_columns": sorted(COST_COLUMNS),
        # Disclose what happens inside nested columns, so a reviewing
        # prospect can see these are covered rather than assume they aren't.
        "tag_columns": ["tags", "tags_json"],
        "properties_transform": {
            "columns": ["properties_json"],
            "mode": "allow_list_plus_id_hash",
            "allowlisted_keys": sorted(PROPERTIES_ALLOWLIST),
            "security_rule_allowlisted_keys": sorted(SECURITY_RULE_ALLOWLIST),
            "arm_id_transform": "hash_identifier (same transform as resource_id)",
            "unlisted_keys": "dropped",
        },
    }

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return manifest


def main(argv: List[str]) -> int:
    """CLI entry point. Usage:
    obfuscate.py <input.csv> <output.csv> <salt.bin> <manifest.json> <multiplier>
    """
    if len(argv) != 6:
        sys.stderr.write(
            "usage: obfuscate.py <input.csv> <output.csv> <salt.bin> "
            "<manifest.json> <multiplier>\n"
        )
        return 2
    input_path, output_path, salt_path, manifest_path, mult_str = argv[1:]
    obfuscate_csv(
        input_path=input_path,
        output_path=output_path,
        salt_path=salt_path,
        manifest_path=manifest_path,
        multiplier=float(mult_str),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

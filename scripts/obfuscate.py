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

OBFUSCATION_SCHEMA_VERSION = "1.0"

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

        if col == "tags":
            out[col] = parse_tags(val)  # type: ignore[assignment]
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

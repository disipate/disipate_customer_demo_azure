# SPDX-License-Identifier: Apache-2.0
"""make_demo_manifest.py — build demo_findings.json for the customer
demo collector.

The summary JSON is the only file Disipate ingests on the demo path.
It contains:
  * identifying-free run metadata (demo_id, scope, tenant_fingerprint)
  * capability flags used during the run
  * summary counts and dollar totals
  * artifact URLs (blob URLs of the CSVs, for human reference)

NO real customer data — the inventory CSV next to this manifest is
obfuscated; the manifest itself contains no PII, no resource IDs,
no tags, no location strings.

Inputs (paths to JSON/CSV files written by the rest of the pipeline):
  roles.json                 - Test-Roles.ps1 output
  cost_summary.json          - cost_router.py output
  security_summary.json      - security_finder.py output
  azure_inventory.csv        - obfuscated inventory (for resource counts)
  azure_inventory.obfuscation_manifest.json  - salt fingerprint
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Optional


def _load_json(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def _load_csv_resource_types(path: str) -> List[str]:
    with open(path, newline="") as f:
        return [r.get("resource_type", "") for r in csv.DictReader(f)]


def _tenant_fingerprint(salt_fingerprint: str, tenant_id: str) -> str:
    h = hashlib.sha256()
    h.update(salt_fingerprint.encode("utf-8"))
    h.update(tenant_id.encode("utf-8"))
    return h.hexdigest()[:12]


def build_demo_manifest(
    roles_path: str,
    cost_summary_path: str,
    security_summary_path: str,
    inventory_path: str,
    obfuscation_manifest_path: Optional[str],
    demo_id: str,
    collected_at: str,
    artifact_urls: Dict[str, str],
) -> Dict[str, Any]:
    roles = _load_json(roles_path)
    cost_summary = _load_json(cost_summary_path)
    security_summary = _load_json(security_summary_path)

    resource_types = _load_csv_resource_types(inventory_path)
    type_counts = Counter(t for t in resource_types if t)
    top10 = [{"type": t, "count": c} for t, c in type_counts.most_common(10)]

    obf_applied = False
    obf_schema = None
    salt_fp = ""
    if obfuscation_manifest_path and os.path.exists(obfuscation_manifest_path):
        obf = _load_json(obfuscation_manifest_path)
        obf_applied = True
        obf_schema = obf.get("schema_version")
        salt_fp = obf.get("salt_fingerprint", "")

    caps = roles.get("capabilities", {})
    caps_used = {
        "actual_cost": bool(caps.get("can_read_cost_management", False))
        and cost_summary.get("cost_strategy") == "actual",
        "arm_inventory": bool(caps.get("can_read_arm_inventory", False)),
        "arm_metrics": bool(caps.get("can_read_arm_metrics", False)),
        "security_findings": security_summary.get("total_findings", 0) > 0
        or security_summary.get("total_findings") == 0,
    }

    summary = {
        "resources_total": len(resource_types),
        "resources_by_type_top10": top10,
        "estimated_monthly_cost_total": cost_summary.get("estimated_monthly_cost_total", 0.0),
        "cost_is_synthetic": bool(cost_summary.get("cost_is_synthetic", True)),
        "orphaned_resources_count": security_summary.get("total_findings", 0),
        "estimated_monthly_savings": security_summary.get("estimated_monthly_savings_total", 0.0),
        "security_findings_by_severity": security_summary.get(
            "by_severity", {"high": 0, "medium": 0, "low": 0}
        ),
    }

    return {
        "demo_id": demo_id,
        "collected_at": collected_at,
        "demo_mode": True,
        "obfuscation_applied": obf_applied,
        "obfuscation_schema_version": obf_schema,
        "tenant_fingerprint": _tenant_fingerprint(salt_fp, roles.get("tenant_id", "")),
        "scope": roles.get("scope", ""),
        "capabilities_used": caps_used,
        "summary": summary,
        "artifacts": artifact_urls,
    }


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Build demo_findings.json")
    parser.add_argument("--roles", required=True, help="Path to roles.json")
    parser.add_argument("--cost-summary", required=True, help="Path to cost_summary.json")
    parser.add_argument("--security-summary", required=True, help="Path to security_summary.json")
    parser.add_argument("--inventory", required=True, help="Path to azure_inventory.csv")
    parser.add_argument(
        "--obfuscation-manifest",
        default=None,
        help="Path to azure_inventory.obfuscation_manifest.json (optional)",
    )
    parser.add_argument("--demo-id", required=True)
    parser.add_argument("--collected-at", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--artifact-url",
        action="append",
        default=[],
        help="Artifact URL in key=value form; can be repeated",
    )
    args = parser.parse_args(argv[1:])

    artifact_urls: Dict[str, str] = {}
    for kv in args.artifact_url:
        if "=" in kv:
            k, v = kv.split("=", 1)
            artifact_urls[k.strip()] = v.strip()

    manifest = build_demo_manifest(
        roles_path=args.roles,
        cost_summary_path=args.cost_summary,
        security_summary_path=args.security_summary,
        inventory_path=args.inventory,
        obfuscation_manifest_path=args.obfuscation_manifest,
        demo_id=args.demo_id,
        collected_at=args.collected_at,
        artifact_urls=artifact_urls,
    )

    with open(args.output, "w") as f:
        json.dump(manifest, f, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

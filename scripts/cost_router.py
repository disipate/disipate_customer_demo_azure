# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
"""cost_router.py — the role-driven cost-routing decision logic for the
Disipate customer demo collector.

Pure decision logic. Inputs are dicts/lists; outputs are dicts/lists.
No I/O. This module is called by Collect-Cost.ps1 (PowerShell) after
the PowerShell side has fetched the Cost Management API data (if the
role allows) and dumped it to JSON.

Decision tree:
  if roles.can_read_cost_management AND actual_cost_data is non-empty:
      path = "actual"
      each row: actual_cost if available, else fall back to synthetic
  else:
      path = "synthetic"   # always-available fallback
      each row: rate-card lookup * multiplier

Multipliers apply ONLY to synthetic estimates, never to actual API data.
This keeps demo numbers honest: when the operator has Cost Management
Reader, the actual figures are reported as-is.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

# 730 hours = standard "month" for hourly billing math.
HOURLY_TO_MONTHLY = 730

# Synthetic rate-card table. Covers top 20 Azure resource types by consumption.
# Values are rough order-of-magnitude estimates (hourly unless noted).
# Sources: Azure Pricing Calculator, Microsoft public pricing pages.
# Do NOT use for billing — only for demo estimates.
RATE_CARD: Dict[str, float] = {
    # Compute
    "Microsoft.Compute/virtualMachines": 0.10,
    "Microsoft.Compute/disks": 0.05,
    "Microsoft.Compute/virtualMachines/extensions": 0.00,
    "Microsoft.ContainerService/managedClusters": 0.05,
    "Microsoft.ContainerInstance/containerGroups": 0.02,
    "Microsoft.Web/sites": 0.01,
    "Microsoft.Web/serverFarms": 0.05,
    # Networking
    "Microsoft.Network/publicIPAddresses": 0.01,
    "Microsoft.Network/loadBalancers": 0.03,
    "Microsoft.Network/natGateways": 0.04,
    "Microsoft.Network/networkSecurityGroups": 0.00,
    "Microsoft.Network/applicationGateways": 0.05,
    "Microsoft.Network/frontDoors": 0.05,
    "Microsoft.Network/virtualNetworkGateways": 0.05,
    # Storage
    "Microsoft.Storage/storageAccounts": 0.02,
    # Database
    "Microsoft.Sql/servers": 0.00,
    "Microsoft.Sql/servers/databases": 0.02,
    "Microsoft.DBforMariaDB/servers": 0.02,
    "Microsoft.DBforMySQL/servers": 0.02,
    "Microsoft.DBforPostgreSQL/servers": 0.02,
    "Microsoft.DocumentDB/databaseAccounts": 0.05,  # Cosmos DB
    # Caching
    "Microsoft.Cache/redis": 0.03,
    # Messaging
    "Microsoft.ServiceBus/namespaces": 0.02,
    "Microsoft.EventHub/namespaces": 0.02,
    # Serverless
    "Microsoft.Web/sites/functions": 0.0001,  # per execution
    # API Management
    "Microsoft.ApiManagement/service": 0.05,
    # Security
    "Microsoft.KeyVault/vaults": 0.001,
}

MULT_MIN = 0.5
MULT_MAX = 2.0


def clamp_multiplier(m: float) -> float:
    """Clamp to [MULT_MIN, MULT_MAX]. Defends against bad multiplier seeds
    that would invert savings findings."""
    if m < MULT_MIN:
        return MULT_MIN
    if m > MULT_MAX:
        return MULT_MAX
    return m


def lookup_synthetic_cost(resource_type: str) -> tuple:
    """Return (hourly, monthly) for a resource type from the rate card.
    Unknown types return (0.0, 0.0). Sub-types of types in the card map to
    the parent (e.g. virtualMachines/extensions -> virtualMachines rate)."""
    if resource_type in RATE_CARD:
        hourly = RATE_CARD[resource_type]
        return (hourly, round(hourly * HOURLY_TO_MONTHLY, 2))

    # Try the parent type for sub-types like "X/Y/Z".
    parts = resource_type.split("/")
    for i in range(len(parts) - 1, 0, -1):
        parent = "/".join(parts[:i])
        if parent in RATE_CARD:
            hourly = RATE_CARD[parent]
            return (hourly, round(hourly * HOURLY_TO_MONTHLY, 2))

    return (0.0, 0.0)


def apply_costs(
    inventory_rows: List[Dict[str, Any]],
    roles: Dict[str, Any],
    actual_cost_by_resource: Optional[Dict[str, Dict[str, float]]] = None,
    demo_id: str = "",
    multiplier: float = 1.0,
) -> Dict[str, Any]:
    """The main entry point. Returns:
        {
          "inventory_rows": [...updated rows with cost columns filled...],
          "summary": {
            cost_strategy, resources_with_actual_cost,
            estimated_monthly_cost_total, cost_is_synthetic,
            multiplier_applied, demo_id, ...
          }
        }

    Mutates the input rows in place AND returns them; this is intentional
    so the PowerShell caller can write the rows back out without an extra
    copy step. Callers who need immutability should deep-copy first.
    """
    actual_cost_by_resource = actual_cost_by_resource or {}
    mult = clamp_multiplier(multiplier)

    can_actual = bool(roles.get("capabilities", {}).get("can_read_cost_management", False))
    have_actual_data = bool(actual_cost_by_resource)

    use_actual = can_actual and have_actual_data
    strategy = "actual" if use_actual else "synthetic"

    total = 0.0
    actual_count = 0

    for row in inventory_rows:
        rid = row.get("resource_id", "")
        rtype = row.get("resource_type", "")

        actual_entry = actual_cost_by_resource.get(rid)
        # Actual path: use actual if we have it for this resource,
        # fall back to synthetic for any resource not in the API response.
        if use_actual and actual_entry:
            row["estimated_hourly_cost"] = float(actual_entry.get("estimated_hourly_cost", 0.0))
            row["estimated_monthly_cost"] = float(actual_entry.get("estimated_monthly_cost", 0.0))
            row["cost_is_synthetic"] = "False"
            row["cost_estimation_method"] = "azure_cost_management_api"
            row["actual_cost_available_for_subscription"] = "True"
            actual_count += 1
        else:
            # Synthetic path. Multiplier applies only here.
            hourly, monthly = lookup_synthetic_cost(rtype)
            row["estimated_hourly_cost"] = round(hourly * mult, 6)
            row["estimated_monthly_cost"] = round(monthly * mult, 2)
            row["cost_is_synthetic"] = "True"
            row["cost_estimation_method"] = "synthetic_resource_type_rate"
            row["actual_cost_available_for_subscription"] = "False"

        try:
            total += float(row["estimated_monthly_cost"])
        except (ValueError, TypeError):
            pass

    summary = {
        "demo_id": demo_id,
        "cost_strategy": strategy,
        "can_read_cost_management": can_actual,
        "had_actual_data": have_actual_data,
        "resources_with_actual_cost": actual_count,
        "resources_total": len(inventory_rows),
        "estimated_monthly_cost_total": round(total, 2),
        "cost_is_synthetic": strategy == "synthetic",
        "multiplier_applied": mult,
    }

    return {"inventory_rows": inventory_rows, "summary": summary}


def main(argv: List[str]) -> int:
    """CLI entry point. Collect-Cost.ps1 shells out to this.

    Usage:
      cost_router.py <roles.json> <inventory.csv> <actual_cost.json>
                     <output_inventory.csv> <output_summary.json>
                     <demo_id> <multiplier>

    actual_cost.json may be "{}" if no actual data was fetched (the
    PowerShell side writes a stub in that case so this script never has
    to special-case missing files).
    """
    if len(argv) != 8:
        sys.stderr.write(
            "usage: cost_router.py <roles.json> <inventory.csv> "
            "<actual_cost.json> <output_inventory.csv> <output_summary.json> "
            "<demo_id> <multiplier>\n"
        )
        return 2

    roles_path, inv_path, actual_path, out_inv_path, out_sum_path, demo_id, mult_str = argv[1:]

    with open(roles_path) as f:
        roles = json.load(f)

    import csv

    with open(inv_path, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames: List[str] = list(reader.fieldnames or [])
        rows = [dict(r) for r in reader]

    with open(actual_path) as f:
        actual_raw = json.load(f)
    # actual_raw is either {} (no data) or {resource_id: {hourly, monthly}}
    actual = actual_raw if isinstance(actual_raw, dict) else {}

    result = apply_costs(
        inventory_rows=rows,
        roles=roles,
        actual_cost_by_resource=actual,
        demo_id=demo_id,
        multiplier=float(mult_str),
    )

    with open(out_inv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(result["inventory_rows"])

    with open(out_sum_path, "w") as f:
        json.dump(result["summary"], f, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

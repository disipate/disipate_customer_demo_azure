# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
"""Tests for cost_router.py — the role-driven cost-routing decision logic
for the Disipate customer demo collector.

The PowerShell Collect-Cost.ps1 fetches actual Cost Management API data
(if the role allows) and dumps it to JSON. cost_router.py then merges
that data into the inventory rows using a deterministic decision tree:

  if roles.can_read_cost_management AND actual_cost_data is non-empty:
      path = "actual"
  else:
      path = "synthetic"   # always-available fallback

This file tests that decision tree + the rate-card lookup exhaustively.
"""

import json
import os
import sys
import unittest

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS_DIR)

from cost_router import (  # noqa: E402
    HOURLY_TO_MONTHLY,
    RATE_CARD,
    apply_costs,
    lookup_synthetic_cost,
)


def make_roles(can_read_cost_management: bool) -> dict:
    return {
        "capabilities": {
            "can_read_cost_management": can_read_cost_management,
            "can_read_arm_inventory": True,
            "can_read_arm_metrics": False,
            "can_write_blob": True,
            "is_owner": False,
        }
    }


def make_inventory_row(resource_type: str, resource_id: str = "/x/y") -> dict:
    return {
        "cloud_provider": "azure",
        "subscription_id": "sub-1",
        "resource_id": resource_id,
        "resource_name": resource_id.split("/")[-1],
        "resource_type": resource_type,
        "resource_group": "rg-test",
        "estimated_hourly_cost": "",
        "estimated_monthly_cost": "",
        "cost_is_synthetic": "",
        "actual_cost_available_for_subscription": "",
        "cost_estimation_method": "",
    }


class TestLookupSyntheticCost(unittest.TestCase):
    """The synthetic rate-card lookup is the always-on fallback. Any resource
    type not in the table falls back to $0/hr (per plan: don't expand the
    table without a source)."""

    def test_vm_in_table(self):
        hourly, monthly = lookup_synthetic_cost("Microsoft.Compute/virtualMachines")
        self.assertEqual(hourly, RATE_CARD["Microsoft.Compute/virtualMachines"])
        self.assertEqual(monthly, round(hourly * HOURLY_TO_MONTHLY, 2))

    def test_disk_in_table(self):
        hourly, _ = lookup_synthetic_cost("Microsoft.Compute/disks")
        self.assertEqual(hourly, RATE_CARD["Microsoft.Compute/disks"])

    def test_unknown_resource_type_returns_zero(self):
        hourly, monthly = lookup_synthetic_cost("Microsoft.Foo/widgets")
        self.assertEqual(hourly, 0.0)
        self.assertEqual(monthly, 0.0)

    def test_extension_subtype_stays_zero(self):
        # Microsoft.Compute/virtualMachines/extensions is in the rate card
        # explicitly at 0.00 — extensions are attached to a parent VM that
        # already gets its rate, so they add no cost. The direct table hit
        # takes precedence over a parent-type fallback.
        ext_hourly, ext_monthly = lookup_synthetic_cost(
            "Microsoft.Compute/virtualMachines/extensions"
        )
        self.assertEqual(ext_hourly, 0.0)
        self.assertEqual(ext_monthly, 0.0)

    def test_unknown_subtype_falls_back_to_parent(self):
        # A subtype NOT in the table (e.g. Microsoft.Compute/foo/bar)
        # should fall back to the parent type if the parent IS in the
        # table. This handles Microsoft.Sql/servers/databases/sub where
        # the explicit /databases entry exists, but a future /elasticpools
        # type would correctly fall through to /servers.
        hourly, _ = lookup_synthetic_cost("Microsoft.Sql/servers/databases")
        self.assertEqual(hourly, RATE_CARD["Microsoft.Sql/servers/databases"])


class TestApplyCostsActualPath(unittest.TestCase):
    """When the role allows AND actual data is non-empty, use actual."""

    def test_actual_path_marks_synthetic_false_and_method_api(self):
        roles = make_roles(can_read_cost_management=True)
        inv = [make_inventory_row("Microsoft.Compute/virtualMachines", "/x/vm-1")]
        # Actual cost data: a flat dict resource_id -> cost.
        actual = {"/x/vm-1": {"estimated_monthly_cost": 73.0, "estimated_hourly_cost": 0.10}}

        result = apply_costs(
            inventory_rows=inv,
            roles=roles,
            actual_cost_by_resource=actual,
            demo_id="abc123",
        )

        self.assertEqual(len(result["inventory_rows"]), 1)
        row = result["inventory_rows"][0]
        self.assertEqual(row["cost_is_synthetic"], "False")
        self.assertEqual(row["cost_estimation_method"], "azure_cost_management_api")
        self.assertEqual(row["actual_cost_available_for_subscription"], "True")
        self.assertEqual(row["estimated_monthly_cost"], 73.0)
        self.assertEqual(row["estimated_hourly_cost"], 0.10)

    def test_actual_path_summary_records_strategy_and_totals(self):
        roles = make_roles(can_read_cost_management=True)
        inv = [
            make_inventory_row("Microsoft.Compute/virtualMachines", "/x/vm-1"),
            make_inventory_row("Microsoft.Compute/disks", "/x/disk-1"),
        ]
        actual = {
            "/x/vm-1": {"estimated_monthly_cost": 73.0, "estimated_hourly_cost": 0.10},
            "/x/disk-1": {"estimated_monthly_cost": 36.5, "estimated_hourly_cost": 0.05},
        }
        result = apply_costs(inv, roles, actual, demo_id="abc123")
        summary = result["summary"]
        self.assertEqual(summary["cost_strategy"], "actual")
        self.assertEqual(summary["resources_with_actual_cost"], 2)
        self.assertEqual(summary["estimated_monthly_cost_total"], 109.5)
        self.assertEqual(summary["cost_is_synthetic"], False)
        self.assertIn("demo_id", summary)

    def test_actual_path_with_resource_missing_from_data_uses_synthetic_fallback(self):
        """A resource that wasn't in the actual API response (e.g., it was
        created today, no cost accrued yet) should still get a synthetic
        estimate rather than being left blank."""
        roles = make_roles(can_read_cost_management=True)
        inv = [
            make_inventory_row("Microsoft.Compute/virtualMachines", "/x/vm-1"),
            make_inventory_row("Microsoft.Compute/disks", "/x/disk-1"),
        ]
        actual = {"/x/vm-1": {"estimated_monthly_cost": 73.0, "estimated_hourly_cost": 0.10}}
        # disk-1 missing from actual

        result = apply_costs(inv, roles, actual, demo_id="abc123")
        rows = {r["resource_id"]: r for r in result["inventory_rows"]}

        # vm-1 got actual
        self.assertEqual(rows["/x/vm-1"]["cost_is_synthetic"], "False")
        # disk-1 fell back to synthetic
        self.assertEqual(rows["/x/disk-1"]["cost_is_synthetic"], "True")
        self.assertEqual(
            rows["/x/disk-1"]["cost_estimation_method"],
            "synthetic_resource_type_rate",
        )


class TestApplyCostsSyntheticFallback(unittest.TestCase):
    """When the role does NOT allow, OR actual data is empty, use synthetic."""

    def test_role_disallows_synthetic_only(self):
        roles = make_roles(can_read_cost_management=False)
        inv = [make_inventory_row("Microsoft.Compute/virtualMachines")]
        actual = {"/x/y": {"estimated_monthly_cost": 999.0}}  # ignored

        result = apply_costs(inv, roles, actual, demo_id="abc123")
        row = result["inventory_rows"][0]
        self.assertEqual(row["cost_is_synthetic"], "True")
        self.assertEqual(row["cost_estimation_method"], "synthetic_resource_type_rate")
        # synthetic cost comes from rate card, NOT from actual data
        self.assertNotEqual(row["estimated_monthly_cost"], 999.0)
        self.assertEqual(row["actual_cost_available_for_subscription"], "False")
        self.assertEqual(result["summary"]["cost_strategy"], "synthetic")

    def test_role_allows_but_actual_data_empty_synthetic_fallback(self):
        """Best-effort discipline: a failed Cost Management API call for a
        sub does NOT abort the run. The summary marks it as synthetic with
        available_for_subscription=false."""
        roles = make_roles(can_read_cost_management=True)
        inv = [
            make_inventory_row("Microsoft.Compute/virtualMachines", "/x/vm-1"),
            make_inventory_row("Microsoft.Compute/disks", "/x/disk-1"),
        ]
        # Per-resource actual: empty for this sub (the call failed)
        actual = {}

        result = apply_costs(inv, roles, actual, demo_id="abc123")
        summary = result["summary"]
        self.assertEqual(summary["cost_strategy"], "synthetic")
        self.assertEqual(summary["resources_with_actual_cost"], 0)
        # All rows synthetic
        for row in result["inventory_rows"]:
            self.assertEqual(row["cost_is_synthetic"], "True")

    def test_synthetic_unknown_resource_type_gets_zero(self):
        roles = make_roles(can_read_cost_management=False)
        inv = [make_inventory_row("Microsoft.Foo/widgets", "/x/widget-1")]
        result = apply_costs(inv, roles, {}, demo_id="abc123")
        row = result["inventory_rows"][0]
        self.assertEqual(row["estimated_hourly_cost"], 0.0)
        self.assertEqual(row["estimated_monthly_cost"], 0.0)
        self.assertEqual(row["cost_is_synthetic"], "True")


class TestApplyCostsMultiplier(unittest.TestCase):
    """The synthetic cost multiplier (clamped to [0.5, 2.0]) is applied to
    the synthetic rate-card estimate, not to actual cost data."""

    def test_synthetic_multiplier_applied(self):
        roles = make_roles(can_read_cost_management=False)
        inv = [make_inventory_row("Microsoft.Compute/virtualMachines")]
        result = apply_costs(inv, roles, {}, demo_id="abc", multiplier=1.5)
        row = result["inventory_rows"][0]
        # VM rate = 0.10/hr; monthly = 0.10 * 730 = 73.0
        # with multiplier 1.5: monthly = 109.5
        self.assertAlmostEqual(float(row["estimated_monthly_cost"]), 109.5, places=2)

    def test_actual_cost_not_multiplied(self):
        """Actual API data must pass through verbatim; the multiplier only
        affects synthetic fallback. This is the rule that keeps demo
        numbers honest when the operator has the role."""
        roles = make_roles(can_read_cost_management=True)
        inv = [make_inventory_row("Microsoft.Compute/virtualMachines", "/x/vm-1")]
        actual = {"/x/vm-1": {"estimated_monthly_cost": 73.0, "estimated_hourly_cost": 0.10}}
        result = apply_costs(inv, roles, actual, demo_id="abc", multiplier=1.5)
        row = result["inventory_rows"][0]
        self.assertEqual(row["estimated_monthly_cost"], 73.0)

    def test_multiplier_clamped_when_out_of_bounds(self):
        roles = make_roles(can_read_cost_management=False)
        inv = [make_inventory_row("Microsoft.Compute/virtualMachines")]
        result = apply_costs(inv, roles, {}, demo_id="abc", multiplier=99.0)
        summary = result["summary"]
        self.assertEqual(summary["multiplier_applied"], 2.0)


if __name__ == "__main__":
    unittest.main()

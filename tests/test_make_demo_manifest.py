# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
"""Tests for make_demo_manifest.py — the demo-findings summary builder.

The customer demo collector produces a demo_findings.json file at
the end of each run. This is the file Disipate ingests to return
savings/security estimates to the customer without ever seeing the
prospect's real environment.

Shape (per plan §10):
  demo_id, collected_at, demo_mode, obfuscation_applied,
  obfuscation_schema_version, tenant_fingerprint, scope,
  capabilities_used {actual_cost, arm_inventory, arm_metrics,
  security_findings}, summary {resources_total,
  resources_by_type_top10, estimated_monthly_cost_total,
  cost_is_synthetic, orphaned_resources_count,
  estimated_monthly_savings, security_findings_by_severity},
  artifacts {<name>: <url>}
"""

import csv
import json
import os
import sys
import tempfile
import unittest

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS_DIR)

from make_demo_manifest import build_demo_manifest  # noqa: E402


def write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


class TestBuildDemoManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.roles_path = os.path.join(self.tmp.name, "roles.json")
        self.cost_path = os.path.join(self.tmp.name, "cost_summary.json")
        self.sec_path = os.path.join(self.tmp.name, "security_summary.json")
        self.inv_path = os.path.join(self.tmp.name, "azure_inventory.csv")
        self.obf_manifest_path = os.path.join(
            self.tmp.name, "azure_inventory.obfuscation_manifest.json"
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _write_roles(self, **overrides):
        roles = {
            "tenant_id": "tenant-abc",
            "scope": "subscriptions/sub-1/resourceGroups/rg-demo",
            "capabilities": {
                "can_read_arm_inventory": True,
                "can_read_arm_metrics": False,
                "can_read_cost_management": True,
                "can_write_blob": True,
                "is_owner": False,
            },
        }
        roles["capabilities"].update(overrides.get("capabilities", {}))
        for k, v in overrides.items():
            if k != "capabilities":
                roles[k] = v
        write_json(self.roles_path, roles)

    def _write_cost_summary(self, **overrides):
        s = {
            "demo_id": "demo-1",
            "cost_strategy": "actual",
            "resources_total": 50,
            "resources_with_actual_cost": 30,
            "estimated_monthly_cost_total": 1234.56,
            "cost_is_synthetic": False,
        }
        s.update(overrides)
        write_json(self.cost_path, s)

    def _write_security_summary(self, **overrides):
        s = {
            "total_findings": 14,
            "by_severity": {"high": 3, "medium": 7, "low": 4},
            "estimated_monthly_savings_total": 387.20,
        }
        s.update(overrides)
        write_json(self.sec_path, s)

    def _write_inventory(self, types):
        rows = []
        for i, t in enumerate(types):
            rows.append(
                {
                    "cloud_provider": "azure",
                    "resource_id": f"/x/{t}/{i}",
                    "resource_type": t,
                    "resource_name": f"{t}-{i}",
                    "estimated_monthly_cost": 10.0,
                }
            )
        write_csv(self.inv_path, rows)

    def _write_obfuscation_manifest(self):
        write_json(
            self.obf_manifest_path,
            {
                "schema_version": "1.0",
                "multiplier": 1.0,
                "salt_fingerprint": "a" * 64,
            },
        )

    def _build(self, **kwargs):
        return build_demo_manifest(
            roles_path=self.roles_path,
            cost_summary_path=self.cost_path,
            security_summary_path=self.sec_path,
            inventory_path=self.inv_path,
            obfuscation_manifest_path=(
                self.obf_manifest_path if os.path.exists(self.obf_manifest_path) else None
            ),
            demo_id=kwargs.get("demo_id", "demo-1"),
            collected_at=kwargs.get("collected_at", "2026-08-24T16:00:00Z"),
            artifact_urls=kwargs.get("artifact_urls", {}),
        )

    def test_top_level_fields(self):
        self._write_roles()
        self._write_cost_summary()
        self._write_security_summary()
        self._write_inventory(["Microsoft.Compute/virtualMachines"])
        self._write_obfuscation_manifest()

        m = self._build()
        self.assertEqual(m["demo_id"], "demo-1")
        self.assertEqual(m["collected_at"], "2026-08-24T16:00:00Z")
        self.assertTrue(m["demo_mode"])
        self.assertTrue(m["obfuscation_applied"])
        self.assertEqual(m["obfuscation_schema_version"], "1.0")
        # tenant_fingerprint = sha256(salt_fingerprint + tenant_id)[:12]
        self.assertEqual(len(m["tenant_fingerprint"]), 12)
        self.assertEqual(m["scope"], "subscriptions/sub-1/resourceGroups/rg-demo")

    def test_capabilities_used_mirrors_roles(self):
        self._write_roles(
            capabilities={
                "can_read_arm_metrics": True,
                "can_read_cost_management": False,
            }
        )
        self._write_cost_summary()
        self._write_security_summary()
        self._write_inventory(["X"])
        m = self._build()
        caps = m["capabilities_used"]
        self.assertTrue(caps["arm_inventory"])
        self.assertTrue(caps["arm_metrics"])
        self.assertFalse(caps["actual_cost"])
        self.assertTrue(caps["security_findings"])

    def test_summary_resources_total_and_by_type_top10(self):
        self._write_roles()
        self._write_cost_summary()
        self._write_security_summary()
        # 7 VMs, 5 disks, 2 NSGs = 14 rows
        types = (
            ["Microsoft.Compute/virtualMachines"] * 7
            + ["Microsoft.Compute/disks"] * 5
            + ["Microsoft.Network/networkSecurityGroups"] * 2
        )
        self._write_inventory(types)
        m = self._build()
        self.assertEqual(m["summary"]["resources_total"], 14)
        by_type = m["summary"]["resources_by_type_top10"]
        # Top entry should be VMs (7), then disks (5), then NSGs (2)
        self.assertEqual(by_type[0]["type"], "Microsoft.Compute/virtualMachines")
        self.assertEqual(by_type[0]["count"], 7)
        self.assertEqual(by_type[1]["type"], "Microsoft.Compute/disks")
        self.assertEqual(by_type[1]["count"], 5)

    def test_summary_cost_total_and_synthetic_flag(self):
        self._write_roles()
        self._write_cost_summary(estimated_monthly_cost_total=5000.0, cost_is_synthetic=False)
        self._write_security_summary()
        self._write_inventory(["X"])
        m = self._build()
        self.assertEqual(m["summary"]["estimated_monthly_cost_total"], 5000.0)
        self.assertFalse(m["summary"]["cost_is_synthetic"])

    def test_summary_synthetic_path_marks_cost_is_synthetic_true(self):
        self._write_roles()
        self._write_cost_summary(cost_strategy="synthetic", cost_is_synthetic=True)
        self._write_security_summary()
        self._write_inventory(["X"])
        m = self._build()
        self.assertTrue(m["summary"]["cost_is_synthetic"])

    def test_summary_security_findings_by_severity(self):
        self._write_roles()
        self._write_cost_summary()
        self._write_security_summary(
            by_severity={"high": 5, "medium": 10, "low": 2},
            estimated_monthly_savings_total=999.99,
        )
        self._write_inventory(["X"])
        m = self._build()
        sev = m["summary"]["security_findings_by_severity"]
        self.assertEqual(sev["high"], 5)
        self.assertEqual(sev["medium"], 10)
        self.assertEqual(sev["low"], 2)
        self.assertEqual(m["summary"]["estimated_monthly_savings"], 999.99)

    def test_orphaned_resources_count_uses_security_total_findings(self):
        self._write_roles()
        self._write_cost_summary()
        self._write_security_summary(total_findings=42)
        self._write_inventory(["X"])
        m = self._build()
        self.assertEqual(m["summary"]["orphaned_resources_count"], 42)

    def test_artifacts_section_uses_provided_urls(self):
        self._write_roles()
        self._write_cost_summary()
        self._write_security_summary()
        self._write_inventory(["X"])
        urls = {
            "azure_inventory_csv": "https://blob.example/demo1/azure_inventory.csv",
            "cost_summary_json": "https://blob.example/demo1/cost_summary.json",
        }
        m = self._build(artifact_urls=urls)
        self.assertEqual(m["artifacts"]["azure_inventory_csv"], urls["azure_inventory_csv"])

    def test_tenant_fingerprint_is_deterministic_for_same_inputs(self):
        self._write_roles()
        self._write_cost_summary()
        self._write_security_summary()
        self._write_inventory(["X"])
        self._write_obfuscation_manifest()
        a = self._build()
        b = self._build()
        self.assertEqual(a["tenant_fingerprint"], b["tenant_fingerprint"])

    def test_obfuscation_applied_false_when_no_manifest(self):
        self._write_roles()
        self._write_cost_summary()
        self._write_security_summary()
        self._write_inventory(["X"])
        # no obfuscation manifest written
        m = self._build()
        self.assertFalse(m["obfuscation_applied"])
        self.assertIsNone(m["obfuscation_schema_version"])


if __name__ == "__main__":
    unittest.main()

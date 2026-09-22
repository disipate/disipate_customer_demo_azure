# Copyright (c) 2026 Disipate
# SPDX-License-Identifier: Apache-2.0
"""Tests for obfuscate.py — the privacy-preserving CSV transformer used by
the Disipate customer demo collector before any data leaves the customer's
tenant.

Follows the project's unittest pattern: tests live under
tests/ and the script under test lives under
scripts/. We add the scripts dir to sys.path explicitly
since this folder is not a Python package.
"""

import csv
import hashlib
import json
import os
import sys
import tempfile
import unittest
from typing import Dict

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS_DIR)

from obfuscate import (  # noqa: E402
    OBFUSCATION_SCHEMA_VERSION,
    clamp_multiplier,
    fingerprint_salt,
    hash_identifier,
    obfuscate_csv,
    obfuscate_properties,
    obfuscate_properties_json,
    parse_tags,
)

# A realistic full ARM path, as Collect-ArmInventory.ps1 emits inside
# properties_json. The guid and the names are the identifying parts.
ARM_ID = (
    "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/"
    "rg-prod-web/providers/Microsoft.Network/networkInterfaces/nic-web-prod-01"
)
SECRET_GUID = "11111111-2222-3333-4444-555555555555"
SECRET_RG = "rg-prod-web"
SECRET_NAME = "nic-web-prod-01"


class TestHashIdentifier(unittest.TestCase):
    """hash_identifier is the core one-way transform. Same input + same salt
    must always produce same output. Different salts must produce different
    output for the same input. Output length must be fixed (16 hex chars)."""

    def test_same_input_same_salt_is_deterministic(self):
        salt = b"\x00" * 32
        a = hash_identifier("vm-prod-web-01", salt)
        b = hash_identifier("vm-prod-web-01", salt)
        self.assertEqual(a, b)

    def test_same_input_different_salts_differ(self):
        salt_a = b"\x00" * 32
        salt_b = b"\x01" * 32
        self.assertNotEqual(
            hash_identifier("vm-prod-web-01", salt_a),
            hash_identifier("vm-prod-web-01", salt_b),
        )

    def test_output_is_sixteen_hex_chars(self):
        out = hash_identifier("anything", b"\x00" * 32)
        self.assertEqual(len(out), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in out))

    def test_different_inputs_with_same_salt_differ(self):
        salt = b"\x00" * 32
        self.assertNotEqual(
            hash_identifier("vm-a", salt),
            hash_identifier("vm-b", salt),
        )


class TestFingerprintSalt(unittest.TestCase):
    """The manifest gets a salt *fingerprint* so the customer can tell whether
    two runs used the same salt without ever exposing the salt itself."""

    def test_fingerprint_is_sha256_hex_64_chars(self):
        fp = fingerprint_salt(b"\x00" * 32)
        self.assertEqual(len(fp), 64)
        self.assertEqual(fp, hashlib.sha256(b"\x00" * 32).hexdigest())

    def test_different_salts_produce_different_fingerprints(self):
        a = fingerprint_salt(b"\x00" * 32)
        b = fingerprint_salt(b"\x01" * 32)
        self.assertNotEqual(a, b)


class TestClampMultiplier(unittest.TestCase):
    """The cost multiplier is clamped so a bug can't produce negative
    savings findings."""

    def test_in_bounds_unchanged(self):
        self.assertEqual(clamp_multiplier(1.0), 1.0)
        self.assertEqual(clamp_multiplier(0.85), 0.85)

    def test_above_max_clamped_to_max(self):
        self.assertEqual(clamp_multiplier(5.0), 2.0)
        self.assertEqual(clamp_multiplier(2.5), 2.0)

    def test_below_min_clamped_to_min(self):
        self.assertEqual(clamp_multiplier(0.1), 0.5)
        self.assertEqual(clamp_multiplier(-1.0), 0.5)


class TestParseTags(unittest.TestCase):
    """Tags come in as either JSON ({"Env":"prod","Owner":"tim"}) or a
    semicolon-separated string ("Env=prod;Owner=tim"). The obfuscator
    preserves keys, replaces values with tag-N placeholders, and returns
    the same shape it received."""

    def test_json_dict_in_json_dict_out(self):
        tags = {"Environment": "Production", "Owner": "Platform"}
        out = parse_tags(tags)
        self.assertIsInstance(out, dict)
        self.assertIn("Environment", out)
        self.assertIn("Owner", out)
        # values are placeholders, not original
        for v in out.values():
            self.assertRegex(v, r"^tag-\d+$")
        # keys preserved verbatim
        self.assertNotIn("Production", out.values())
        self.assertNotIn("Platform", out.values())

    def test_semicolon_string_in_string_out(self):
        tags = "Environment=Production;Owner=Platform"
        out = parse_tags(tags)
        self.assertIsInstance(out, str)
        # keys preserved
        self.assertIn("Environment=", out)
        self.assertIn("Owner=", out)
        # values are placeholders
        self.assertNotIn("Production", out)
        self.assertNotIn("Platform", out)

    def test_empty_tags_handled(self):
        self.assertEqual(parse_tags(""), "")
        self.assertEqual(parse_tags({}), {})


class TestObfuscateProperties(unittest.TestCase):
    """properties_json is a raw ARM bag and carries full resource paths
    nested inside it, so no column-level deny-list can cover it. These tests
    pin the two guarantees: unlisted keys are dropped, and ARM ids are hashed
    with the same transform as the resource_id column."""

    def setUp(self):
        self.salt = b"\x42" * 32

    def test_arm_id_inside_nested_bag_is_hashed(self):
        props = {"networkProfile": {"networkInterfaces": [{"id": ARM_ID}]}}
        out = obfuscate_properties(props, self.salt)
        blob = json.dumps(out)
        for secret in (SECRET_GUID, SECRET_RG, SECRET_NAME):
            self.assertNotIn(secret, blob)
        # and the id is replaced by a hash, not deleted
        self.assertEqual(
            out["networkProfile"]["networkInterfaces"][0]["id"],
            hash_identifier(ARM_ID, self.salt),
        )

    def test_hashed_nested_id_matches_hashed_resource_id_column(self):
        """The NIC -> NSG join must still resolve after obfuscation, so a
        nested reference and the row's resource_id must hash identically."""
        out = obfuscate_properties({"ipConfiguration": {"id": ARM_ID}}, self.salt)
        self.assertEqual(out["ipConfiguration"]["id"], hash_identifier(ARM_ID, self.salt))

    def test_unlisted_keys_are_dropped(self):
        props = {
            "osProfile": {"adminUsername": "azureuser", "customData": "SECRET"},
            "provisioningState": "Succeeded",
            "diskState": "Unattached",
        }
        out = obfuscate_properties(props, self.salt)
        self.assertEqual(out, {"diskState": "Unattached"})

    def test_security_rule_keeps_decision_fields_drops_description(self):
        props = {
            "securityRules": [
                {
                    "name": "allow-ssh-internet",
                    "direction": "Inbound",
                    "access": "Allow",
                    "priority": 100,
                    "protocol": "Tcp",
                    "destinationPortRange": "22",
                    "description": "opened for contractor j.smith",
                }
            ]
        }
        out = obfuscate_properties(props, self.salt)
        rule = out["securityRules"][0]
        # decision fields retained so the exposure question stays answerable
        self.assertEqual(rule["direction"], "Inbound")
        self.assertEqual(rule["access"], "Allow")
        self.assertEqual(rule["destinationPortRange"], "22")
        # free text dropped
        self.assertNotIn("description", rule)
        self.assertNotIn("j.smith", json.dumps(out))

    def test_non_id_strings_pass_through(self):
        # values are only preserved when their KEY is allow-listed.
        props = {"diskState": "Unattached", "managedDisk": {"id": ARM_ID}}
        out = obfuscate_properties(props, self.salt)
        self.assertEqual(out["diskState"], "Unattached")
        self.assertEqual(out["managedDisk"]["id"], hash_identifier(ARM_ID, self.salt))
        # a non-id string under an allow-listed key is preserved as-is
        self.assertEqual(obfuscate_properties({"diskState": "Attached"}, self.salt),
                         {"diskState": "Attached"})

    def test_empty_bag_is_empty_object(self):
        self.assertEqual(obfuscate_properties({}, self.salt), {})
        self.assertEqual(obfuscate_properties_json("", self.salt), "{}")
        self.assertEqual(obfuscate_properties_json(None, self.salt), "{}")

    def test_malformed_json_fails_closed(self):
        """A bag we cannot parse is exactly the case where we cannot prove
        it is safe, so it collapses to {} rather than passing through."""
        self.assertEqual(obfuscate_properties_json("{not json", self.salt), "{}")
        self.assertEqual(obfuscate_properties_json('"just a string"', self.salt), "{}")

    def test_depth_cap_terminates(self):
        """A pathological nesting depth must not blow the stack; deeper
        levels are dropped."""
        node: Dict[str, object] = {"diskState": "Unattached"}
        for _ in range(30):
            node = {"managedDisk": node}
        out = obfuscate_properties(node, self.salt)
        # survives without raising, and the deep leaf is gone
        self.assertNotIn("Unattached", json.dumps(out))

    def test_output_is_valid_json(self):
        props = {"networkProfile": {"networkInterfaces": [{"id": ARM_ID}]}}
        s = obfuscate_properties_json(json.dumps(props), self.salt)
        self.assertIsInstance(json.loads(s), dict)


class TestObfuscateCsv(unittest.TestCase):
    """End-to-end: given an input CSV and a salt path, obfuscate_csv writes
    an output CSV with identifier columns hashed, cost columns scaled by
    the clamped multiplier, and a manifest JSON next to it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.input_path = os.path.join(self.tmp.name, "in.csv")
        self.output_path = os.path.join(self.tmp.name, "out.csv")
        self.salt_path = os.path.join(self.tmp.name, "salt.bin")
        self.manifest_path = os.path.join(self.tmp.name, "manifest.json")
        with open(self.salt_path, "wb") as f:
            f.write(b"\x42" * 32)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_input(self, rows):
        with open(self.input_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    def _read_output(self):
        with open(self.output_path, newline="") as f:
            return list(csv.DictReader(f))

    def test_identifier_columns_replaced_cost_columns_scaled_others_unchanged(self):
        rows = [
            {
                "resource_id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-1",
                "resource_name": "vm-1",
                "subscription_id": "sub-1",
                "resource_group": "rg-prod",
                "location": "eastus",
                "cost": "100.00",
                "quantity": "10",
                "sku": "Standard_D2s_v3",
            }
        ]
        self._write_input(rows)

        manifest = obfuscate_csv(
            input_path=self.input_path,
            output_path=self.output_path,
            salt_path=self.salt_path,
            manifest_path=self.manifest_path,
            multiplier=1.5,
        )

        out_rows = self._read_output()
        self.assertEqual(len(out_rows), 1)
        row = out_rows[0]

        # identifier columns replaced (no longer contain original values)
        self.assertNotIn("vm-1", row["resource_name"])
        self.assertNotIn("sub-1", row["subscription_id"])
        self.assertNotIn("rg-prod", row["resource_group"])
        # resource_id is the most sensitive; fully gone
        self.assertNotIn("Microsoft.Compute", row["resource_id"])
        # non-identifier columns preserved
        self.assertEqual(row["location"], "eastus")
        self.assertEqual(row["sku"], "Standard_D2s_v3")
        # cost scaled by multiplier
        self.assertEqual(float(row["cost"]), 150.0)
        self.assertEqual(float(row["quantity"]), 15.0)

    def test_tags_json_and_properties_json_are_both_obfuscated(self):
        """Regression: the ARM collector emits `tags_json` and
        `properties_json`, neither of which the original column-level rules
        covered — so tag values and nested ARM resource paths left the tenant
        verbatim. Assert end-to-end that both are now transformed."""
        rows = [
            {
                "resource_id": ARM_ID,
                "resource_name": "vm-1",
                "subscription_id": "sub-1",
                "resource_group": "rg-prod",
                "tags_json": json.dumps({"Owner": "jane.doe@contoso.com", "CostCenter": "CC-4417"}),
                "properties_json": json.dumps(
                    {"networkProfile": {"networkInterfaces": [{"id": ARM_ID}]}}
                ),
                "location": "eastus",
                "cost": "1.0",
                "quantity": "1",
                "sku": "x",
            }
        ]
        self._write_input(rows)
        obfuscate_csv(
            self.input_path,
            self.output_path,
            self.salt_path,
            self.manifest_path,
            multiplier=1.0,
        )
        row = self._read_output()[0]
        blob = json.dumps(row)

        # no real tag values survive
        self.assertNotIn("jane.doe@contoso.com", blob)
        self.assertNotIn("CC-4417", blob)
        # no real ARM identifiers survive anywhere in the row
        self.assertNotIn(SECRET_GUID, blob)
        self.assertNotIn(SECRET_RG, blob)
        self.assertNotIn(SECRET_NAME, blob)
        # tag keys are still present (finding logic needs the key shape)
        self.assertIn("Owner", row["tags_json"])

    def test_manifest_discloses_nested_transforms(self):
        rows = [
            {
                "resource_id": "x",
                "resource_name": "x",
                "subscription_id": "x",
                "resource_group": "rg",
                "tags_json": "{}",
                "properties_json": "{}",
                "location": "eastus",
                "cost": "1.0",
                "quantity": "1",
                "sku": "x",
            }
        ]
        self._write_input(rows)
        obfuscate_csv(
            self.input_path,
            self.output_path,
            self.salt_path,
            self.manifest_path,
            multiplier=1.0,
        )
        with open(self.manifest_path) as f:
            manifest = json.load(f)
        self.assertIn("tags_json", manifest["tag_columns"])
        self.assertEqual(manifest["properties_transform"]["columns"], ["properties_json"])
        # still no salt in the manifest
        self.assertNotIn("salt", manifest)

    def test_resource_group_gets_demo_prefix(self):
        rows = [
            {
                "resource_id": "x",
                "resource_name": "x",
                "subscription_id": "x",
                "resource_group": "rg-prod-web",
                "location": "eastus",
                "cost": "0",
                "quantity": "0",
                "sku": "x",
            }
        ]
        self._write_input(rows)
        obfuscate_csv(
            self.input_path,
            self.output_path,
            self.salt_path,
            self.manifest_path,
            multiplier=1.0,
        )
        out = self._read_output()
        self.assertTrue(out[0]["resource_group"].startswith("rg-demo-"))

    def test_manifest_has_fingerprint_not_salt_and_schema_version(self):
        rows = [
            {
                "resource_id": "x",
                "resource_name": "x",
                "subscription_id": "x",
                "resource_group": "rg",
                "location": "eastus",
                "cost": "1.0",
                "quantity": "1",
                "sku": "x",
            }
        ]
        self._write_input(rows)
        obfuscate_csv(
            self.input_path,
            self.output_path,
            self.salt_path,
            self.manifest_path,
            multiplier=0.9,
        )
        with open(self.manifest_path) as f:
            manifest = json.load(f)
        self.assertEqual(manifest["schema_version"], OBFUSCATION_SCHEMA_VERSION)
        self.assertEqual(manifest["multiplier"], 0.9)
        self.assertIn("salt_fingerprint", manifest)
        self.assertNotIn("salt", manifest)
        self.assertEqual(len(manifest["salt_fingerprint"]), 64)

    def test_multiplier_clamped_in_manifest(self):
        rows = [
            {
                "resource_id": "x",
                "resource_name": "x",
                "subscription_id": "x",
                "resource_group": "rg",
                "location": "eastus",
                "cost": "1.0",
                "quantity": "1",
                "sku": "x",
            }
        ]
        self._write_input(rows)
        obfuscate_csv(
            self.input_path,
            self.output_path,
            self.salt_path,
            self.manifest_path,
            multiplier=99.0,  # out of bounds, should clamp
        )
        with open(self.manifest_path) as f:
            manifest = json.load(f)
        self.assertEqual(manifest["multiplier"], 2.0)


if __name__ == "__main__":
    unittest.main()

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

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS_DIR)

from obfuscate import (  # noqa: E402
    OBFUSCATION_SCHEMA_VERSION,
    clamp_multiplier,
    fingerprint_salt,
    hash_identifier,
    obfuscate_csv,
    parse_tags,
)


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

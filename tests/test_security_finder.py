# SPDX-License-Identifier: Apache-2.0
"""Tests for security_finder.py — the security findings detector for the
Disipate customer demo collector.

Six detection rules cover the resource types where customers find the most
waste AND the most unmonitored attack surface:

  orphaned_managed_disk        - disk with no parent VM
  orphaned_public_ip           - public IP not attached to any NIC
  orphaned_load_balancer       - LB with no backend pool members
  orphaned_nat_gateway         - NAT with no route table reference
  empty_security_group         - NSG with zero rules
  public_ip_on_unprotected_vm  - VM with public IP and no NSG

The detector is pure logic over the inventory CSV. No Azure calls. Per-
row severity is hardcoded per the rule (not learned); cost is the rate-
card estimate, flagged cost_is_synthetic=true.
"""

import os
import sys
import unittest

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS_DIR)

from security_finder import (  # noqa: E402
    detect_findings,
    summarize,
)


def row(rt, rid, **extra):
    base = {
        "resource_id": rid,
        "resource_name": rid.split("/")[-1],
        "resource_type": rt,
        "subscription_id": "sub-1",
        "resource_group": "rg",
        "location": "eastus",
        "tags_json": "{}",
        "properties_json": "{}",
    }
    base.update(extra)
    return base


class TestOrphanedDisk(unittest.TestCase):
    def test_unattached_disk_finding_emitted(self):
        inv = [row("Microsoft.Compute/disks", "/d1", properties_json='{"diskState": "Unattached"}')]
        findings = detect_findings(inv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "orphaned_managed_disk")
        self.assertEqual(findings[0]["severity"], "medium")

    def test_attached_disk_no_finding(self):
        inv = [row("Microsoft.Compute/disks", "/d1", properties_json='{"diskState": "Attached"}')]
        findings = detect_findings(inv)
        self.assertEqual(findings, [])


class TestOrphanedPublicIp(unittest.TestCase):
    def test_unassociated_public_ip_finding(self):
        inv = [
            row(
                "Microsoft.Network/publicIPAddresses",
                "/ip1",
                properties_json='{"ipConfiguration": null}',
            )
        ]
        findings = detect_findings(inv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "orphaned_public_ip")
        self.assertEqual(findings[0]["severity"], "medium")

    def test_associated_public_ip_no_finding(self):
        inv = [
            row(
                "Microsoft.Network/publicIPAddresses",
                "/ip1",
                properties_json='{"ipConfiguration": {"id": "/nic1"}}',
            )
        ]
        self.assertEqual(detect_findings(inv), [])


class TestOrphanedLoadBalancer(unittest.TestCase):
    def test_lb_with_no_backend_members(self):
        inv = [
            row(
                "Microsoft.Network/loadBalancers",
                "/lb1",
                properties_json='{"backendAddressPools": []}',
            )
        ]
        findings = detect_findings(inv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "orphaned_load_balancer")

    def test_lb_with_backend_members_no_finding(self):
        inv = [
            row(
                "Microsoft.Network/loadBalancers",
                "/lb1",
                properties_json='{"backendAddressPools": [{"id": "/be1"}]}',
            )
        ]
        self.assertEqual(detect_findings(inv), [])


class TestOrphanedNatGateway(unittest.TestCase):
    def test_nat_with_no_route_table(self):
        inv = [
            row(
                "Microsoft.Network/natGateways",
                "/nat1",
                properties_json='{"subnets": []}',
            )
        ]
        findings = detect_findings(inv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "orphaned_nat_gateway")

    def test_nat_with_subnets_no_finding(self):
        inv = [
            row(
                "Microsoft.Network/natGateways",
                "/nat1",
                properties_json='{"subnets": [{"id": "/sub1"}]}',
            )
        ]
        self.assertEqual(detect_findings(inv), [])


class TestEmptySecurityGroup(unittest.TestCase):
    def test_nsg_with_no_rules(self):
        inv = [
            row(
                "Microsoft.Network/networkSecurityGroups",
                "/nsg1",
                properties_json='{"securityRules": []}',
            )
        ]
        findings = detect_findings(inv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "empty_security_group")
        self.assertEqual(findings[0]["severity"], "high")  # empty NSG = no protection

    def test_nsg_with_default_rules_no_finding(self):
        # Default NSGs ship with 6 built-in rules. Don't flag those.
        inv = [
            row(
                "Microsoft.Network/networkSecurityGroups",
                "/nsg1",
                properties_json='{"securityRules": [{}]}',  # at least one explicit rule
            )
        ]
        self.assertEqual(detect_findings(inv), [])


class TestPublicIpOnUnprotectedVm(unittest.TestCase):
    """A VM with a public IP and no NSG is internet-reachable with no
    firewall. This is the highest-severity finding.

    The NIC -> NSG association is resolved from `networkSecurityGroup.id` on
    the NIC, which is why the fixtures below include a NIC row. Before that
    fix the rule approximated "has NSG" with "an NSG exists somewhere".
    """

    def test_vm_with_public_ip_no_nsg_high_severity(self):
        inv = [
            row(
                "Microsoft.Compute/virtualMachines",
                "/vm1",
                properties_json='{"networkProfile": {"networkInterfaces": [{"id": "/nic1"}]}}',
            ),
            row(
                "Microsoft.Network/networkInterfaces",
                "/nic1",
                properties_json='{"ipConfigurations": [{"id": "/ipcfg1"}]}',
            ),
            row(
                "Microsoft.Network/publicIPAddresses",
                "/ip1",
                properties_json='{"ipConfiguration": {"id": "/nic1"}}',
            ),
        ]
        findings = detect_findings(inv)
        ids = [f["finding_type"] for f in findings]
        self.assertIn("public_ip_on_unprotected_vm", ids)
        finding = next(f for f in findings if f["finding_type"] == "public_ip_on_unprotected_vm")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["resource_id"], "/vm1")
        # no NSG anywhere -> the strong claim is warranted
        self.assertIn("no network security group", finding["description"])

    def test_unrelated_nsg_does_not_suppress_the_rule(self):
        """The old implementation returned nothing whenever ANY NSG with rules
        existed anywhere in the inventory — so one NSG on a dev box silenced
        the rule for every VM in the subscription. This is the regression."""
        inv = [
            row(
                "Microsoft.Compute/virtualMachines",
                "/vm1",
                properties_json='{"networkProfile": {"networkInterfaces": [{"id": "/nic1"}]}}',
            ),
            row(
                "Microsoft.Network/networkInterfaces",
                "/nic1",
                properties_json='{}',  # NO networkSecurityGroup -> unfiltered
            ),
            row(
                "Microsoft.Network/publicIPAddresses",
                "/ip1",
                properties_json='{"ipConfiguration": {"id": "/nic1"}}',
            ),
            # An NSG that exists but is attached to something else entirely.
            row(
                "Microsoft.Network/networkSecurityGroups",
                "/nsg-unrelated",
                properties_json='{"securityRules": [{"direction": "Inbound", "access": "Allow"}]}',
            ),
        ]
        findings = detect_findings(inv)
        ids = [f["finding_type"] for f in findings]
        self.assertIn("public_ip_on_unprotected_vm", ids)

    def test_vm_whose_nic_has_nsg_with_custom_rules_no_finding(self):
        inv = [
            row(
                "Microsoft.Compute/virtualMachines",
                "/vm1",
                properties_json='{"networkProfile": {"networkInterfaces": [{"id": "/nic1"}]}}',
            ),
            row(
                "Microsoft.Network/networkInterfaces",
                "/nic1",
                properties_json='{"networkSecurityGroup": {"id": "/nsg1"}}',
            ),
            row(
                "Microsoft.Network/publicIPAddresses",
                "/ip1",
                properties_json='{"ipConfiguration": {"id": "/nic1"}}',
            ),
            row(
                "Microsoft.Network/networkSecurityGroups",
                "/nsg1",
                properties_json='{"securityRules": [{"direction": "Inbound", "access": "Deny"}]}',
            ),
        ]
        findings = detect_findings(inv)
        ids = [f["finding_type"] for f in findings]
        self.assertNotIn("public_ip_on_unprotected_vm", ids)

    def test_vm_whose_nic_has_empty_nsg_is_protected(self):
        """Azure adds DenyAllInbound (65500, 0.0.0.0/0) to every NSG, so an
        NSG with no CUSTOM rules still denies internet inbound. The old logic
        treated an empty NSG as evidence of exposure and a VM with no NSG at
        all as equally bad — exactly backwards."""
        inv = [
            row(
                "Microsoft.Compute/virtualMachines",
                "/vm1",
                properties_json='{"networkProfile": {"networkInterfaces": [{"id": "/nic1"}]}}',
            ),
            row(
                "Microsoft.Network/networkInterfaces",
                "/nic1",
                properties_json='{"networkSecurityGroup": {"id": "/nsg1"}}',
            ),
            row(
                "Microsoft.Network/publicIPAddresses",
                "/ip1",
                properties_json='{"ipConfiguration": {"id": "/nic1"}}',
            ),
            row(
                "Microsoft.Network/networkSecurityGroups",
                "/nsg1",
                properties_json='{"securityRules": []}',  # defaults still apply
            ),
        ]
        findings = detect_findings(inv)
        ids = [f["finding_type"] for f in findings]
        # not flagged as unprotected ...
        self.assertNotIn("public_ip_on_unprotected_vm", ids)
        # ... but still surfaced as a governance gap
        self.assertIn("empty_security_group", ids)

    def test_nsg_referenced_but_absent_from_inventory_does_not_overclaim(self):
        """If the NIC references an NSG we never collected, we cannot read its
        rules. Report, but do not claim there is no filtering."""
        inv = [
            row(
                "Microsoft.Compute/virtualMachines",
                "/vm1",
                properties_json='{"networkProfile": {"networkInterfaces": [{"id": "/nic1"}]}}',
            ),
            row(
                "Microsoft.Network/networkInterfaces",
                "/nic1",
                properties_json='{"networkSecurityGroup": {"id": "/nsg-not-collected"}}',
            ),
            row(
                "Microsoft.Network/publicIPAddresses",
                "/ip1",
                properties_json='{"ipConfiguration": {"id": "/nic1"}}',
            ),
        ]
        findings = detect_findings(inv)
        finding = next(
            f for f in findings if f["finding_type"] == "public_ip_on_unprotected_vm"
        )
        self.assertIn("could not be read", finding["description"])
        self.assertNotIn("no network security group", finding["description"])

    def test_vm_without_public_ip_not_flagged(self):
        inv = [
            row(
                "Microsoft.Compute/virtualMachines",
                "/vm1",
                properties_json='{"networkProfile": {"networkInterfaces": [{"id": "/nic1"}]}}',
            ),
            row(
                "Microsoft.Network/networkInterfaces",
                "/nic1",
                properties_json='{}',
            ),
        ]
        findings = detect_findings(inv)
        ids = [f["finding_type"] for f in findings]
        self.assertNotIn("public_ip_on_unprotected_vm", ids)


class TestSummarize(unittest.TestCase):
    def test_summary_groups_by_severity_and_type(self):
        findings = [
            {
                "finding_type": "orphaned_managed_disk",
                "severity": "medium",
                "estimated_monthly_savings": 36.5,
                "resource_id": "/d1",
            },
            {
                "finding_type": "orphaned_managed_disk",
                "severity": "medium",
                "estimated_monthly_savings": 36.5,
                "resource_id": "/d2",
            },
            {
                "finding_type": "empty_security_group",
                "severity": "high",
                "estimated_monthly_savings": 0.0,
                "resource_id": "/nsg1",
            },
            {
                "finding_type": "public_ip_on_unprotected_vm",
                "severity": "high",
                "estimated_monthly_savings": 73.0,
                "resource_id": "/vm1",
            },
        ]
        summary = summarize(findings)
        self.assertEqual(summary["total_findings"], 4)
        self.assertEqual(summary["by_severity"]["medium"], 2)
        self.assertEqual(summary["by_severity"]["high"], 2)
        self.assertEqual(summary["by_severity"]["low"], 0)
        self.assertEqual(summary["estimated_monthly_savings_total"], 146.0)
        self.assertEqual(summary["by_finding_type"]["orphaned_managed_disk"], 2)
        self.assertEqual(summary["by_finding_type"]["empty_security_group"], 1)


if __name__ == "__main__":
    unittest.main()

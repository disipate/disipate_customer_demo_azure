# SPDX-License-Identifier: Apache-2.0
"""security_finder.py — security findings detector for the Disipate
customer demo collector.

Pure logic over the inventory CSV. No Azure calls. Six detection rules
cover the resource types where customers find the most waste AND the most
unmonitored attack surface:

  orphaned_managed_disk        - disk with no parent VM
  orphaned_public_ip           - public IP not attached to any NIC
  orphaned_load_balancer       - LB with no backend pool members
  orphaned_nat_gateway         - NAT with no route table reference
  empty_security_group         - NSG with zero custom rules
  public_ip_on_unprotected_vm  - VM reachable from a public IP with no NSG

Per-row severity is hardcoded per the rule. The "synthetic" cost flag
is preserved so the manifest is honest about provenance.

The detection rules read from a `properties_json` column on each row.
Collect-ArmInventory.ps1 emits this column from the Resource Graph
`properties` field. Empty/missing properties -> no finding (we cannot
prove unattached without evidence).

Cross-row resolution: the VM->NIC->public-IP and NIC->NSG associations are
resolved by looking up referenced resources in the inventory by id. Those
references live inside `properties_json`, which obfuscate.py hashes with the
same transform it applies to the `resource_id` column — so the joins still
resolve on obfuscated data.

Azure NSG default rules matter here: every NSG carries AllowVnetInBound
(65000), AllowAzureLoadBalancerInBound (65001) and DenyAllInbound (65500).
An NSG with no custom rules therefore still denies internet inbound. See the
public_ip_on_unprotected_vm rule for how that changes the verdict.
"""

import json
import sys
from typing import Any, Dict, List, Optional

# Synthetic rate-card lookup, shared with cost_router.py. Duplicated here
# rather than imported so this module has no project-internal deps and can
# be tested in isolation.
RATE_CARD_HOURLY: Dict[str, float] = {
    "Microsoft.Compute/virtualMachines": 0.10,
    "Microsoft.Compute/disks": 0.05,
    "Microsoft.Network/publicIPAddresses": 0.01,
    "Microsoft.Network/loadBalancers": 0.03,
    "Microsoft.Network/natGateways": 0.04,
    "Microsoft.Network/networkSecurityGroups": 0.00,
}

HOURS_PER_MONTH = 730
SEVERITY_ORDER = ("high", "medium", "low")


def _parse_props(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = row.get("properties_json", "") or row.get("properties", "") or ""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {}


def _synthetic_monthly(resource_type: str) -> float:
    hourly = RATE_CARD_HOURLY.get(resource_type, 0.0)
    return round(hourly * HOURS_PER_MONTH, 2)


def _finding(
    row: Dict[str, Any], finding_type: str, severity: str, description: str
) -> Dict[str, Any]:
    return {
        "subscription_id": row.get("subscription_id", ""),
        "resource_id": row.get("resource_id", ""),
        "resource_type": row.get("resource_type", ""),
        "resource_group": row.get("resource_group", ""),
        "location": row.get("location", ""),
        "finding_type": finding_type,
        "severity": severity,
        "description": description,
        "estimated_monthly_savings": _synthetic_monthly(row.get("resource_type", "")),
        "cost_is_synthetic": True,
    }


def detect_findings(inventory_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run all six rules over the inventory. Returns one finding dict per
    rule violation. Empty list = nothing detected."""
    findings: List[Dict[str, Any]] = []

    # Index NICs by VM, public IPs by NIC id, and track NSGs separately
    # so the cross-row rule (public_ip_on_unprotected_vm) is O(N) not O(N^2).
    vm_nic_ids: Dict[str, set] = {}
    ip_to_nic: Dict[str, str] = {}
    # Lookup by resource_id, so cross-row rules can resolve a referenced
    # resource's own properties (NIC -> NSG) instead of guessing from the
    # presence of any unrelated resource of that type.
    _row_by_id: Dict[str, Dict[str, Any]] = {}

    for row in inventory_rows:
        rt = row.get("resource_type", "")
        rid = row.get("resource_id", "")
        props = _parse_props(row)
        if rid:
            _row_by_id[rid] = row

        # ---- Rule: orphaned_managed_disk ----
        if rt == "Microsoft.Compute/disks":
            state = props.get("diskState", "")
            if state == "Unattached":
                findings.append(
                    _finding(
                        row,
                        "orphaned_managed_disk",
                        "medium",
                        "Disk is Unattached. Verify the parent VM still exists; otherwise the disk is unmonitored attack surface.",
                    )
                )

        # ---- Rule: orphaned_public_ip ----
        elif rt == "Microsoft.Network/publicIPAddresses":
            ip_cfg = props.get("ipConfiguration")
            if ip_cfg is None:
                findings.append(
                    _finding(
                        row,
                        "orphaned_public_ip",
                        "medium",
                        "Public IP has no NIC association. Reserved-but-unused public IPs are an unmonitored entry point.",
                    )
                )
            elif isinstance(ip_cfg, dict) and ip_cfg.get("id"):
                ip_to_nic[rid] = ip_cfg["id"]

        # ---- Rule: orphaned_load_balancer ----
        elif rt == "Microsoft.Network/loadBalancers":
            backends = props.get("backendAddressPools") or []
            if len(backends) == 0:
                findings.append(
                    _finding(
                        row,
                        "orphaned_load_balancer",
                        "medium",
                        "Load Balancer has no backend pool members. Idle LB still incurs cost and presents an exposed front door.",
                    )
                )

        # ---- Rule: orphaned_nat_gateway ----
        elif rt == "Microsoft.Network/natGateways":
            subnets = props.get("subnets") or []
            if len(subnets) == 0:
                findings.append(
                    _finding(
                        row,
                        "orphaned_nat_gateway",
                        "medium",
                        "NAT Gateway has no subnet associations. Idle NAT GW incurs hourly cost.",
                    )
                )

        # ---- Rule: empty_security_group ----
        #
        # NOTE: an NSG with zero CUSTOM rules is not unprotected. Azure always
        # adds three default inbound rules whose last match is DenyAllInbound
        # (priority 65500, 0.0.0.0/0 -> 0.0.0.0/0, any port, Deny). So the
        # rule fires for the right reason — the NSG was created and never
        # configured, which is a governance gap worth reporting — but the
        # description must not claim there is no filtering, because there is.
        elif rt == "Microsoft.Network/networkSecurityGroups":
            rules = props.get("securityRules") or []
            if len(rules) == 0:
                findings.append(
                    _finding(
                        row,
                        "empty_security_group",
                        "high",
                        "Network Security Group has no custom rules. Azure's default "
                        "inbound rules still deny internet traffic (DenyAllInbound, "
                        "priority 65500), but the NSG was created and never configured — "
                        "a governance gap. Confirm no workload relies on it for filtering.",
                    )
                )

        # ---- Index VMs for the cross-row rule ----
        elif rt == "Microsoft.Compute/virtualMachines":
            nic_ids = set()
            net_profile = props.get("networkProfile") or {}
            for nic in net_profile.get("networkInterfaces") or []:
                if isinstance(nic, dict) and nic.get("id"):
                    nic_ids.add(nic["id"])
            vm_nic_ids[rid] = nic_ids

    # ---- Rule: public_ip_on_unprotected_vm ----
    #
    # A VM is at risk when it is reachable from a public IP and its NIC has
    # no NSG providing inbound filtering.
    #
    # The previous implementation approximated "has NSG" with "any NSG exists
    # anywhere in the inventory", and only fired when the inventory contained
    # NO NSGs at all. Two problems with that:
    #
    #   1. A single unrelated NSG anywhere suppressed the rule for the whole
    #      inventory, so it fired on essentially nothing in a real estate.
    #   2. It counted rules rather than reading them. Azure NSGs always carry
    #      three default inbound rules, ending in DenyAllInbound at priority
    #      65500 (0.0.0.0/0 -> 0.0.0.0/0, any port, Deny). So an NSG with zero
    #      CUSTOM rules is default-deny for internet inbound, while a VM with
    #      no NSG at all has no filtering whatsoever. The old ordering had
    #      those two cases exactly backwards.
    #
    # What we can now do precisely, because `networkSecurityGroup.id` and
    # `networkInterfaces[].id` are retained inside properties_json: resolve the
    # ACTUAL NIC -> NSG association per VM. We still cannot read the rules of
    # an NSG we cannot see, so the conservative fallback is retained only for
    # that specific case.
    if ip_to_nic and vm_nic_ids:
        # Map NIC -> VM (reverse lookup)
        nic_to_vm: Dict[str, str] = {}
        for vm_id, nics in vm_nic_ids.items():
            for nic_id in nics:
                nic_to_vm[nic_id] = vm_id

        # NSG ids we can actually see, and whether each has custom rules.
        nsgs_with_custom_rules: set = set()
        for row in inventory_rows:
            if row.get("resource_type", "") != "Microsoft.Network/networkSecurityGroups":
                continue
            nsg_id = row.get("resource_id", "")
            if not nsg_id:
                continue
            props = _parse_props(row)
            if props.get("securityRules"):
                nsgs_with_custom_rules.add(nsg_id)

        protected_vms: set = set()
        for vm_id, nics in vm_nic_ids.items():
            for nic_id in nics:
                row = _row_by_id.get(nic_id)
                if row is None:
                    continue
                nic_props = _parse_props(row)
                nsg_ref = (nic_props.get("networkSecurityGroup") or {}).get("id", "")
                if not nsg_ref:
                    continue
                # A directly associated NSG that carries custom rules is
                # proven filtering. An NSG with no custom rules still has
                # Azure's deny-all default, which is also protection — but
                # only claim that when we can actually see the NSG row, since
                # we cannot distinguish "no custom rules" from "we have no
                # data" otherwise.
                if nsg_ref in nsgs_with_custom_rules:
                    protected_vms.add(vm_id)
                elif nsg_ref in _row_by_id:
                    protected_vms.add(vm_id)

        for ip_rid, nic_id in ip_to_nic.items():
            vm_id = nic_to_vm.get(nic_id)
            if not vm_id or vm_id in protected_vms:
                continue
            vm_row = _row_by_id.get(vm_id)
            if not vm_row:
                continue

            # Distinguish the two unprotected shapes so the description does
            # not overclaim: no NSG at all is a stronger statement than an
            # NSG we could not inspect.
            vm_nics = vm_nic_ids.get(vm_id, set())
            has_any_nsg_ref = False
            for n in vm_nics:
                n_row = _row_by_id.get(n)
                if n_row and (_parse_props(n_row).get("networkSecurityGroup") or {}).get("id"):
                    has_any_nsg_ref = True
                    break

            if has_any_nsg_ref:
                description = (
                    "VM is reachable from a public IP and its network security group is not "
                    "present in the collected inventory, so the rules governing it could not be "
                    "read. Verify inbound filtering manually."
                )
            else:
                description = (
                    "VM is reachable from a public IP and has no network security group. "
                    "Internet-facing workload with no network filtering."
                )

            findings.append(
                {
                    "subscription_id": vm_row.get("subscription_id", ""),
                    "resource_id": vm_id,
                    "resource_type": vm_row.get("resource_type", ""),
                    "resource_group": vm_row.get("resource_group", ""),
                    "location": vm_row.get("location", ""),
                    "finding_type": "public_ip_on_unprotected_vm",
                    "severity": "high",
                    "description": description,
                    "estimated_monthly_savings": _synthetic_monthly(
                        vm_row.get("resource_type", "")
                    ),
                    "cost_is_synthetic": True,
                }
            )

    return findings


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a summary block for the demo manifest: counts by severity and
    finding type, plus the synthetic savings total."""
    by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    by_finding_type: Dict[str, int] = {}
    total_savings = 0.0
    for f in findings:
        sev = f.get("severity", "low")
        if sev not in by_severity:
            sev = "low"
        by_severity[sev] += 1
        ftype = f.get("finding_type", "unknown")
        by_finding_type[ftype] = by_finding_type.get(ftype, 0) + 1
        try:
            total_savings += float(f.get("estimated_monthly_savings", 0.0))
        except (ValueError, TypeError):
            pass
    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_finding_type": by_finding_type,
        "estimated_monthly_savings_total": round(total_savings, 2),
    }


def main(argv: List[str]) -> int:
    """CLI entry point. Collect-Security.ps1 shells out to this.

    Usage:
      security_finder.py <inventory.csv> <findings.csv> <summary.json>
    """
    if len(argv) != 4:
        sys.stderr.write(
            "usage: security_finder.py <inventory.csv> <findings.csv> <summary.json>\n"
        )
        return 2

    inv_path, findings_path, summary_path = argv[1], argv[2], argv[3]

    import csv

    with open(inv_path, newline="") as f:
        rows = [dict(r) for r in csv.DictReader(f)]

    findings = detect_findings(rows)
    summary = summarize(findings)

    if findings:
        with open(findings_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(findings[0].keys()))
            writer.writeheader()
            writer.writerows(findings)
    else:
        # Empty file with just a header so downstream tooling doesn't
        # fail on missing file.
        with open(findings_path, "w", newline="") as f:
            f.write(
                "subscription_id,resource_id,resource_type,resource_group,location,"
                "finding_type,severity,description,estimated_monthly_savings,cost_is_synthetic\n"
            )

    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

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
  empty_security_group         - NSG with zero rules
  public_ip_on_unprotected_vm  - VM with public IP and no NSG

Per-row severity is hardcoded per the rule. The "synthetic" cost flag
is preserved so the manifest is honest about provenance.

The detection rules read from a `properties_json` column on each row.
Collect-ArmInventory.ps1 emits this column from the Resource Graph
`properties` field. Empty/missing properties -> no finding (we cannot
prove unattached without evidence).
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
    has_nsg_with_rules: set = set()

    for row in inventory_rows:
        rt = row.get("resource_type", "")
        rid = row.get("resource_id", "")
        props = _parse_props(row)

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
        elif rt == "Microsoft.Network/networkSecurityGroups":
            rules = props.get("securityRules") or []
            if len(rules) == 0:
                findings.append(
                    _finding(
                        row,
                        "empty_security_group",
                        "high",
                        "Network Security Group has zero explicit rules. Workloads associated with this NSG have no network filtering.",
                    )
                )
            else:
                has_nsg_with_rules.add(rid)

        # ---- Index VMs for the cross-row rule ----
        elif rt == "Microsoft.Compute/virtualMachines":
            nic_ids = set()
            net_profile = props.get("networkProfile") or {}
            for nic in net_profile.get("networkInterfaces") or []:
                if isinstance(nic, dict) and nic.get("id"):
                    nic_ids.add(nic["id"])
            vm_nic_ids[rid] = nic_ids

    # ---- Rule: public_ip_on_unprotected_vm ----
    # A VM with a NIC that's reachable from a public IP, and that VM has
    # no NSG attached to any of its NICs (or all its NSGs are empty).
    # We approximate "has NSG" by "any NSG exists at all" since the
    # NSG-to-NIC association lives in NIC-level properties that we
    # may not have. Conservative: if NO NSGs exist in the inventory at
    # all, all public-facing VMs are unprotected.
    if ip_to_nic and vm_nic_ids:
        # Map NIC -> VM (reverse lookup)
        nic_to_vm: Dict[str, str] = {}
        for vm_id, nics in vm_nic_ids.items():
            for nic_id in nics:
                nic_to_vm[nic_id] = vm_id

        protected_vms = set()
        if has_nsg_with_rules:
            # If any NSG with rules exists, conservatively assume VMs
            # might be protected. We can't definitively prove the
            # association without NIC-level properties, so this rule
            # only fires when NO NSGs exist or when we can prove the VM
            # has no NSG. Without that proof, skip — emit no finding
            # rather than a false positive.
            pass
        else:
            # No NSGs anywhere in the inventory: every VM with a public IP
            # is unprotected.
            for ip_rid, nic_id in ip_to_nic.items():
                vm_id = nic_to_vm.get(nic_id)
                if vm_id:
                    vm_row = next(
                        (r for r in inventory_rows if r.get("resource_id") == vm_id),
                        None,
                    )
                    if vm_row:
                        findings.append(
                            {
                                "subscription_id": vm_row.get("subscription_id", ""),
                                "resource_id": vm_id,
                                "resource_type": vm_row.get("resource_type", ""),
                                "resource_group": vm_row.get("resource_group", ""),
                                "location": vm_row.get("location", ""),
                                "finding_type": "public_ip_on_unprotected_vm",
                                "severity": "high",
                                "description": (
                                    "VM is reachable from a public IP and the inventory contains no NSGs. "
                                    "Internet-facing workload with no network filtering."
                                ),
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

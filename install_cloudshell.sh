#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
#
# install_cloudshell.sh — one-shot bootstrap for the Disipate customer demo
# collector. Meant to be run via:
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/gatortim/disipate_customer_demo_azure/main/install_cloudshell.sh)
#
# Idempotent: safe to re-run after every Cloud Shell session refresh.
#
# What it does:
#   1. Clones this repo into $HOME/clouddrive/disipate-customer-demo-azure
#   2. Symlinks the collector scripts into $HOME/bin
#   3. Pre-installs the Az PowerShell modules needed by the collectors
#   4. Prints next-step instructions
#
# Environment overrides:
#   DISIPATE_REPO_URL     Override the source repo
#                         (default: gatortim/disipate_customer_demo_azure on GitHub)
#   DISIPATE_BRANCH       Branch to clone (default: main)

set -euo pipefail

REPO_URL="${DISIPATE_REPO_URL:-https://github.com/gatortim/disipate_customer_demo_azure.git}"
BRANCH="${DISIPATE_BRANCH:-main}"
CLOUDDRIVE="${HOME}/clouddrive"
INSTALL_ROOT="${CLOUDDRIVE}/disipate-customer-demo-azure"
BIN_DIR="${HOME}/bin"

echo "[install] repo:   $REPO_URL"
echo "[install] branch: $BRANCH"
echo "[install] target: $INSTALL_ROOT"

mkdir -p "$CLOUDDRIVE" "$BIN_DIR"

# ---- 1. Clone ----

if [ ! -d "$INSTALL_ROOT" ]; then
    echo "[install] cloning..."
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_ROOT"
else
    echo "[install] existing install at $INSTALL_ROOT; updating..."
    git -C "$INSTALL_ROOT" fetch --depth 1 origin "$BRANCH"
    git -C "$INSTALL_ROOT" reset --hard "origin/$BRANCH"
fi

# ---- 2. Symlink scripts ----

for script in Collect-All.ps1 Collect-ArmInventory.ps1 Collect-Cost.ps1 Collect-Security.ps1 Test-Roles.ps1 Push-Blob.ps1; do
    ln -sf "$INSTALL_ROOT/collectors/$script" "$BIN_DIR/$script"
done
echo "[install] scripts linked into $BIN_DIR"

# ---- 3. PowerShell modules ----

# Check pwsh is available. Cloud Shell has it; macOS dev boxes may not.
if ! command -v pwsh >/dev/null 2>&1; then
    echo "[install] WARNING: pwsh not found. Install PowerShell 7+ and re-run, or this step will fail at first run."
fi

if command -v pwsh >/dev/null 2>&1; then
    echo "[install] installing Az PowerShell modules (current user scope)..."
    pwsh -NoProfile -Command '
        $ErrorActionPreference = "Stop"
        $modules = @("Az.Accounts", "Az.Resources", "Az.CostManagement")
        foreach ($m in $modules) {
            if (-not (Get-Module -ListAvailable -Name $m)) {
                Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber
            }
        }
    ' || echo "[install] module install failed; run from Cloud Shell instead"
fi

# ---- 4. Next steps ----

cat <<EOF

[install] done.

Next steps:

  1. Open Azure Cloud Shell (https://shell.azure.com).
  2. Paste the SAS URL from your Disipate contact:
       export DISIPATE_SAS_URL="https://account.blob.core.windows.net/container?<sas>"
  3. Pick the resource group you want to demo against:
       Set-AzContext -Subscription <sub-id>
       Set-AzContext -Subscription <sub-id> -Tenant <tenant-id>
  4. Run the demo:
       Collect-All.ps1

The collector will pause for your review before any data leaves your tenant.
Type 'approve' to upload, 'reject' to discard, 'review' to re-read.

To uninstall:
  rm -rf $INSTALL_ROOT
  rm $BIN_DIR/Collect-*.ps1 $BIN_DIR/Test-Roles.ps1 $BIN_DIR/Push-Blob.ps1

EOF

#!/usr/bin/env bash
# ReconForge :: setup.sh
# Install every tool ReconForge can use, without running a scan.
#   bash setup.sh            # install everything missing
#   bash setup.sh --check    # only report what is / isn't installed
set -o pipefail

RF_SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
RF_OVERWRITE=false
RF_DEBUG=false
RF_LOG_FILE=""

source "$RF_SCRIPT_DIR/lib/core.sh"
source "$RF_SCRIPT_DIR/lib/install.sh"

case ":$PATH:" in *":$HOME/go/bin:"*) ;; *) export PATH="$PATH:$HOME/go/bin" ;; esac

if [[ "${1:-}" == "--check" ]]; then
    log_section "ReconForge dependency status"
    miss=0
    for t in "${RF_REQUIRED_TOOLS[@]}"; do
        if have "$t"; then log_ok "  $t"; else log_err "  $t (required)"; miss=$((miss+1)); fi
    done
    for t in "${!RF_TOOL_SPEC[@]}"; do
        [[ " ${RF_REQUIRED_TOOLS[*]} " == *" $t "* ]] && continue
        if have "$t"; then log_ok "  $t"; else log_warn "  $t (missing)"; fi
    done
    echo
    log_info "install everything with: bash setup.sh"
    exit 0
fi

log_section "ReconForge setup"
if ! have go; then
    log_warn "Go toolchain not found. ProjectDiscovery/Go tools cannot be installed."
    log_info "Install it first (Kali: sudo apt install -y golang), then re-run."
fi
if ! command -v apt-get >/dev/null 2>&1; then
    log_warn "apt-get not found; only Go-based tools will be installed."
fi

install_missing_tools

log_section "Setup complete"
log_info "Run a scan with:  ./reconforge.sh -d example.com"

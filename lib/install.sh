#!/usr/bin/env bash
# ReconForge :: install.sh
# Auto-installs missing tools. Tuned for Kali/Debian (apt + `go install`).
# Sourced by reconforge.sh. Only runs when --install / RF_AUTO_INSTALL=true.
#
# Every entry is best-effort: a failed install logs a warning and the scan
# continues with the remaining tools. Nothing here runs unless asked.

RF_INSTALLED=()
RF_INSTALL_FAILED=()

# tool -> "method|package"
declare -A RF_TOOL_SPEC=(
    # --- apt (Debian/Kali) ---
    [jq]="apt|jq"
    [curl]="apt|curl"
    [nmap]="apt|nmap"
    [gobuster]="apt|gobuster"
    [dirsearch]="apt|dirsearch"
    [nikto]="apt|nikto"
    [whatweb]="apt|whatweb"
    [git]="apt|git"
    [wget]="apt|wget"
    [unzip]="apt|unzip"
    [cargo]="apt|cargo"
    # --- go install ---
    [subfinder]="go|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [amass]="go|github.com/owasp-amass/amass/v4/...@master"
    [httpx]="go|github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [dnsx]="go|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    [naabu]="go|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    [nuclei]="go|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [ffuf]="go|github.com/ffuf/ffuf/v2@latest"
    [katana]="go|github.com/projectdiscovery/katana/cmd/katana@latest"
    [gau]="go|github.com/lc/gau/v2/cmd/gau@latest"
    [waybackurls]="go|github.com/tomnomnom/waybackurls@latest"
    [gospider]="go|github.com/jaeles-project/gospider@latest"
    [hakrawler]="go|github.com/hakluke/hakrawler@latest"
    [gf]="go|github.com/tomnomnom/gf@latest"
    [qsreplace]="go|github.com/tomnomnom/qsreplace@latest"
    [anew]="go|github.com/tomnomnom/anew@latest"
    [subjack]="go|github.com/haccer/subjack@latest"
    [assetfinder]="go|github.com/tomnomnom/assetfinder@latest"
    [dalfox]="go|github.com/hahwul/dalfox/v2@latest"
    [gowitness]="go|github.com/sensepost/gowitness@latest"
    [gitleaks]="go|github.com/gitleaks/gitleaks/v8@latest"
    [alterx]="go|github.com/projectdiscovery/alterx/cmd/alterx@latest"
    [trufflehog]="go-git|https://github.com/trufflesecurity/trufflehog"
    # x8 is a Rust tool; requires cargo (skipped gracefully if absent).
    [x8]="cargo|https://github.com/Sh1Yo/x8"
    # --- pip (python) ---
    [arjun]="pip|arjun"
    [uro]="pip|uro"
    [dnsgen]="pip|dnsgen"
    [wafw00f]="pip|wafw00f"
)

# True when we can escalate for apt (root, or passwordless sudo).
_can_apt() {
    [[ "$(id -u)" -eq 0 ]] && return 0
    command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null
}
_apt() {
    if [[ "$(id -u)" -eq 0 ]]; then apt-get "$@"; else sudo apt-get "$@"; fi
}

_install_go() {
    local tool="$1" pkg="$2"
    if ! have go; then
        log_warn "cannot install $tool: Go toolchain not found (install golang)."
        return 1
    fi
    log_info "go install $pkg ..."
    if go install "$pkg" >/dev/null 2>&1; then
        return 0
    fi
    # Retry verbosely once so the failure reason reaches the debug log.
    log_debug "$(go install "$pkg" 2>&1 | tail -5)"
    return 1
}

_install_go_git() {
    # Some tools (e.g. trufflehog) ship a go.mod with `replace` directives, so
    # `go install <module>@latest` is refused. Clone the repo and build in-tree.
    local tool="$1" repo="$2"
    if ! have go; then
        log_warn "cannot install $tool: Go toolchain not found (install golang)."
        return 1
    fi
    log_info "go install $repo (from source) ..."
    local tmp; tmp=$(mktemp -d)
    if git clone -q --depth 1 "$repo" "$tmp/src" >/dev/null 2>&1 && \
       (cd "$tmp/src" && go install) >/dev/null 2>&1; then
        rm -rf "$tmp"
        return 0
    fi
    log_debug "$(cd "$tmp/src" 2>/dev/null && go install 2>&1 | tail -5)"
    rm -rf "$tmp"
    return 1
}

_install_apt() {
    local tool="$1" pkg="$2"
    if ! command -v apt-get >/dev/null 2>&1; then
        log_warn "cannot install $tool: apt-get unavailable."
        return 1
    fi
    if ! _can_apt; then
        log_warn "cannot install $tool: need root or passwordless sudo for apt."
        return 1
    fi
    log_info "apt-get install $pkg ..."
    _apt update -qq >/dev/null 2>&1 || true
    _apt install -y "$pkg" >/dev/null 2>&1
}

_install_pip() {
    local tool="$1" pkg="$2"
    # Kali/Debian are PEP-668 "externally managed"; prefer pipx for CLI tools,
    # then fall back to pip with --break-system-packages, then plain pip.
    if command -v pipx >/dev/null 2>&1; then
        log_info "pipx install $pkg ..."
        pipx install "$pkg" >/dev/null 2>&1 && return 0
    fi
    local pip=""
    for c in pip3 pip; do command -v "$c" >/dev/null 2>&1 && { pip="$c"; break; }; done
    [[ -z "$pip" ]] && { log_warn "cannot install $tool: pip not found."; return 1; }
    log_info "pip install $pkg ..."
    "$pip" install --quiet --break-system-packages "$pkg" >/dev/null 2>&1 && return 0
    "$pip" install --quiet --user "$pkg" >/dev/null 2>&1
}

_install_cargo() {
    local tool="$1" repo="$2"
    if ! command -v cargo >/dev/null 2>&1; then
        log_warn "cannot install $tool: Rust/cargo not found (install rustc+cargo via apt)."
        return 1
    fi
    log_info "cargo install --git $repo ..."
    timeout 600 cargo install --quiet --git "$repo" >/dev/null 2>&1
}

install_tool() {
    local tool="$1"
    local spec="${RF_TOOL_SPEC[$tool]:-}"
    if [[ -z "$spec" ]]; then
        log_debug "no installer registered for '$tool'."
        return 1
    fi
    local method="${spec%%|*}" pkg="${spec#*|}"
    case "$method" in
        go)     _install_go     "$tool" "$pkg" ;;
        go-git) _install_go_git "$tool" "$pkg" ;;
        apt)   _install_apt   "$tool" "$pkg" ;;
        pip)   _install_pip   "$tool" "$pkg" ;;
        cargo) _install_cargo "$tool" "$pkg" ;;
        *)     log_warn "unknown install method '$method' for $tool"; return 1 ;;
    esac
}

# Post-install assets that are not standalone binaries.
install_assets() {
    # nuclei templates
    if have nuclei; then
        log_info "updating nuclei templates..."
        nuclei -update-templates -silent >/dev/null 2>&1 || \
            log_warn "nuclei template update failed (will use bundled templates)."
    fi
    # gf patterns
    if have gf && [[ ! -d "$HOME/.gf" || -z "$(ls -A "$HOME/.gf" 2>/dev/null)" ]]; then
        log_info "provisioning gf patterns..."
        local tmp; tmp=$(mktemp -d)
        git clone -q --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$tmp/p" 2>/dev/null || true
        git clone -q --depth 1 https://github.com/tomnomnom/gf "$tmp/g" 2>/dev/null || true
        mkdir -p "$HOME/.gf"
        cp "$tmp"/p/*.json "$HOME/.gf/" 2>/dev/null || true
        cp "$tmp"/g/examples/*.json "$HOME/.gf/" 2>/dev/null || true
        rm -rf "$tmp"
    fi
    # subjack fingerprints (cache into the repo for future runs)
    if [[ ! -f "$RF_SCRIPT_DIR/patterns/subjack-fingerprints.json" ]]; then
        local fp
        fp=$(find "$HOME/go/pkg/mod/github.com/haccer" -name fingerprints.json 2>/dev/null | head -1)
        if [[ -n "$fp" ]]; then
            cp "$fp" "$RF_SCRIPT_DIR/patterns/subjack-fingerprints.json" 2>/dev/null || true
        fi
    fi
}

# Install every tool in the registry that is currently missing.
install_missing_tools() {
    log_section "TOOL SETUP"
    case ":$PATH:" in *":$HOME/go/bin:"*) ;; *) export PATH="$PATH:$HOME/go/bin" ;; esac
    case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) export PATH="$PATH:$HOME/.cargo/bin" ;; esac

    local tool
    for tool in "${!RF_TOOL_SPEC[@]}"; do
        if have "$tool"; then
            continue
        fi
        if install_tool "$tool" && have "$tool"; then
            log_ok "installed $tool"
            RF_INSTALLED+=("$tool")
        else
            log_warn "could not install $tool (continuing without it)"
            RF_INSTALL_FAILED+=("$tool")
        fi
    done

    install_assets

    if ((${#RF_INSTALLED[@]})); then
        log_ok "installed: ${RF_INSTALLED[*]}"
    fi
    if ((${#RF_INSTALL_FAILED[@]})); then
        log_warn "still missing: ${RF_INSTALL_FAILED[*]}"
    fi
    hash -r 2>/dev/null || true
}

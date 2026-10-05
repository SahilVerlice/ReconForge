#!/usr/bin/env bash
# ===========================================================================
#  ReconForge - resource-conscious reconnaissance orchestrator
#  A hardened, feature-extended reimplementation inspired by BugBountyScanner.
#
#  For authorized security testing only. You are responsible for having
#  permission to test every target you point this at.
# ===========================================================================
set -o pipefail

RF_VERSION="2.0.0"
RF_SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

# --- defaults --------------------------------------------------------------
RF_TOOLSDIR="/opt"
RF_OUTDIR="$PWD"
RF_OVERWRITE=false
RF_MODE="standard"          # quick | standard | deep
RF_ONLY=""
RF_SKIP=""
RF_DRY_RUN=false
RF_DEBUG=false
RF_INSTALL=false
RF_NO_INSTALL=false
RF_ACTIVE=false
RF_THREADS=40
RF_PAR=40
RF_QUIET=false
RF_ASCII="${RF_ASCII:-0}"
RF_DOMAINS=()
RF_NOTIFY_ENABLED=false
RF_LOG_FILE=""
RF_STATE_DIR=""

source "$RF_SCRIPT_DIR/lib/core.sh"
source "$RF_SCRIPT_DIR/lib/install.sh"
source "$RF_SCRIPT_DIR/lib/scan.sh"
source "$RF_SCRIPT_DIR/lib/report.sh"

usage() {
    cat <<EOF
${C_BOLD}${C_NEON}ReconForge v${RF_VERSION}${C_RESET} ${C_DIM}—${C_RESET} automated reconnaissance for authorized testing

${C_BOLD}USAGE${C_RESET}
  $0 [options] -d <domain> [-d <domain> ...]

${C_BOLD}OPTIONS${C_RESET}
  -d, --domain <d>        Target domain (repeatable). Prompts if omitted.
  -o, --output <dir>      Parent output dir (default: current dir).
  -t, --toolsdir <dir>    Tools directory for wordlists/fingerprints (default: /opt).
  -m, --mode <mode>       quick | standard | deep        (default: standard)
      --only <list>       Comma-separated phases to run exclusively.
      --skip <list>       Comma-separated phases to skip.
      --threads <n>       Parallelism for httpx/ad-hoc checks   (default: 40)
  -w, --overwrite         Re-run every step, ignoring checkpoints.
  -n, --dry-run           Show what would run, do not execute scans.
      --install           Auto-install missing tools, then scan (no prompt).
      --no-install        Never install tools, even if some are missing.
      --active            Enable intrusive phases (xss/dalfox). Off by default.
  -q, --quiet             Minimal output (log file still gets everything).
      --ascii             ASCII-only UI (no box-drawing / braille glyphs).
      --no-notify         Disable Telegram notifications.
      --no-color          Disable colored output (also honors NO_COLOR).
      --debug             Verbose debug logging.
  -h, --help              This help.
  -V, --version           Print version.

${C_BOLD}PHASES${C_RESET}
  subdomains resolve live screenshots takeover urls crawl gf nuclei ffuf checks
  ports secrets waf params permute xss cors headers cloud dedupe

  Intrusive phases (xss) require --active. Use --only to force any phase.

${C_BOLD}EXAMPLES${C_RESET}
  $0 -d example.com
  $0 -d example.com -m deep --threads 80 -o ~/recon
  $0 -d example.com --only subdomains,live,nuclei
  $0 -d example.com --skip ports,secrets

Credentials: put telegram_api_key / telegram_chat_id in a .env next to this
script to enable notifications. See README for full documentation.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing (robust while-loop; does not mis-consume values like the
# original's `for arg in "$@"` loop did).
# ---------------------------------------------------------------------------
parse_args() {
    while (($#)); do
        case "$1" in
            -d|--domain)    [[ -z "${2:-}" ]] && { log_err "--domain needs a value"; exit 1; }
                            RF_DOMAINS+=("$2"); shift 2 ;;
            -o|--output)    RF_OUTDIR="${2:?--output needs a value}"; shift 2 ;;
            -t|--toolsdir)  RF_TOOLSDIR="${2:?--toolsdir needs a value}"; shift 2 ;;
            -m|--mode)      RF_MODE="${2:?--mode needs a value}"; shift 2 ;;
            --only)         RF_ONLY="${2:?--only needs a value}"; shift 2 ;;
            --skip)         RF_SKIP="${2:?--skip needs a value}"; shift 2 ;;
            --threads)      RF_THREADS="${2:?--threads needs a value}"; RF_PAR="$RF_THREADS"; shift 2 ;;
            -w|--overwrite|--force) RF_OVERWRITE=true; shift ;;
            -n|--dry-run)   RF_DRY_RUN=true; shift ;;
            --install)      RF_INSTALL=true; shift ;;
            --no-install)   RF_NO_INSTALL=true; shift ;;
            --active)       RF_ACTIVE=true; shift ;;
            -q|--quiet)     RF_QUIET=true; shift ;;
            --ascii)        RF_ASCII=1; shift ;;
            --no-notify)    RF_NOTIFY_ENABLED=false; RF_NOTIFY_LOCKED=true; shift ;;
            --no-color)     C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""
                            C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""; shift ;;
            --debug)        RF_DEBUG=true; shift ;;
            -h|--help)      usage; exit 0 ;;
            -V|--version)   echo "ReconForge $RF_VERSION"; exit 0 ;;
            --)             shift; break ;;
            *)              log_err "Unknown option: $1"; echo; usage; exit 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Phase registry + selection
# ---------------------------------------------------------------------------
RF_ALL_PHASES=(subdomains resolve live screenshots takeover urls crawl gf nuclei ffuf checks ports secrets
               waf params permute xss cors headers cloud dedupe)
RF_QUICK_PHASES=(subdomains resolve live takeover)
# `xss` (dalfox) is intrusive and only runs in deep mode when --active is given.
RF_DEEP_PHASES=(subdomains resolve live screenshots takeover urls crawl gf nuclei ffuf checks ports secrets
                waf params permute cors headers cloud dedupe)

phase_fn() {
    case "$1" in
        subdomains)  echo phase_subdomains ;;
        resolve)     echo phase_resolve ;;
        live)        echo phase_live ;;
        screenshots) echo phase_screenshots ;;
        takeover)    echo phase_takeover ;;
        urls)        echo phase_urls ;;
        crawl)       echo phase_crawl ;;
        gf)          echo phase_gf ;;
        nuclei)      echo phase_nuclei ;;
        ffuf)        echo phase_ffuf ;;
        checks)      echo phase_checks ;;
        ports)       echo phase_ports ;;
        secrets)     echo phase_secrets ;;
        waf)         echo phase_waf ;;
        params)      echo phase_params ;;
        permute)     echo phase_permute ;;
        xss)         echo phase_xss ;;
        cors)        echo phase_cors ;;
        headers)     echo phase_headers ;;
        cloud)       echo phase_cloud ;;
        dedupe)      echo phase_dedupe ;;
        *)           echo "" ;;
    esac
}

phase_label() {
    case "$1" in
        subdomains)  echo "Subdomain enumeration" ;;
        resolve)     echo "DNS resolution" ;;
        live)        echo "HTTP probing" ;;
        screenshots) echo "Screenshots" ;;
        takeover)    echo "Subdomain takeover check" ;;
        urls)        echo "Historical URL discovery" ;;
        crawl)       echo "Web crawling" ;;
        gf)          echo "gf pattern tagging" ;;
        nuclei)      echo "Vulnerability scan (nuclei)" ;;
        ffuf)        echo "Content discovery (ffuf)" ;;
        checks)      echo "Active parameter checks" ;;
        ports)       echo "Port scanning" ;;
        secrets)     echo "Secret scanning" ;;
        waf)         echo "WAF detection" ;;
        params)      echo "Hidden parameter discovery" ;;
        permute)     echo "Subdomain permutation" ;;
        xss)         echo "XSS scanning (dalfox)" ;;
        cors)        echo "CORS misconfiguration check" ;;
        headers)     echo "Security header audit" ;;
        cloud)       echo "Cloud storage / dangling check" ;;
        dedupe)      echo "URL deduplication (uro)" ;;
        *)           echo "$1" ;;
    esac
}

selected_phases() {
    local -a base
    case "$RF_MODE" in
        quick) base=("${RF_QUICK_PHASES[@]}") ;;
        deep)  base=("${RF_DEEP_PHASES[@]}") ;;
        *)     base=(subdomains resolve live screenshots takeover urls crawl gf nuclei) ;;
    esac
    local -a result=()
    local p

    if [[ -n "$RF_ONLY" ]]; then
        IFS=',' read -ra want <<< "$RF_ONLY"
        for p in "${want[@]}"; do
            p="$(echo "$p" | xargs)"
            [[ -z "$p" ]] && continue
            [[ -z "$(phase_fn "$p")" ]] && { log_err "unknown phase in --only: $p"; exit 1; }
            result+=("$p")
        done
    else
        result=("${base[@]}")
    fi

    if [[ -n "$RF_SKIP" ]]; then
        IFS=',' read -ra drop <<< "$RF_SKIP"
        local -a kept=()
        for p in "${result[@]}"; do
            local skipit=false d
            for d in "${drop[@]}"; do
                d="$(echo "$d" | xargs)"
                [[ "$p" == "$d" ]] && skipit=true
            done
            $skipit || kept+=("$p")
        done
        result=("${kept[@]}")
    fi

    # Intrusive phases require --active unless explicitly requested via --only.
    local -a gated=()
    for p in "${result[@]}"; do
        if [[ "$p" == "xss" && "$RF_ACTIVE" != true && -z "$RF_ONLY" ]]; then
            log_warn "skipping intrusive phase 'xss' (enable with --active)."
            continue
        fi
        gated+=("$p")
    done
    result=("${gated[@]}")
    printf '%s\n' "${result[@]}"
}

# ---------------------------------------------------------------------------
# Per-domain driver
# ---------------------------------------------------------------------------
run_domain() {
    local dom="$1"
    local dom_dir="$RF_OUTDIR/$dom"
    mkdir -p "$dom_dir"
    RF_DOMAIN_DIR="$dom_dir"

    local -a phases
    mapfile -t phases < <(selected_phases)
    ui_begin_domain "$dom" "${#phases[@]}"

    log_section "TARGET :: $dom" "phases ${#phases[@]} · mode $RF_MODE · threads $RF_THREADS"
    notify "Starting reconnaissance on $dom"
    cd "$dom_dir" || { log_err "cannot enter $dom_dir"; return 1; }

    state_init "$RF_STATE_DIR/$dom.state"
    log_debug "phases: ${phases[*]}"

    local p fn label
    for p in "${phases[@]}"; do
        fn=$(phase_fn "$p")
        label=$(phase_label "$p")
        if [[ "$RF_DRY_RUN" == true ]]; then
            RF_UI_INDEX=$((RF_UI_INDEX+1))
            ui_phase "$RF_UI_INDEX" "$RF_UI_TOTAL" skip "$label (dry-run)"
            continue
        fi
        # Guard file per phase (used to confirm output); empty when N/A.
        local guard=""
        case "$p" in
            subdomains)  guard="domains-${dom}.txt" ;;
            resolve)     guard="ip-addresses-${dom}.txt" ;;
            live)        guard="livedomains-${dom}.txt" ;;
            urls)        guard="WayBack-${dom}.txt" ;;
            crawl)       guard="crawl-${dom}.txt" ;;
            *)           guard="" ;;
        esac
        step "$p" "$label" "$guard" "$fn" "$dom" || true
    done

    # Reports (always regenerated; they are cheap and reflect current state).
    if [[ "$RF_DRY_RUN" != true ]]; then
        ui_phase "$RF_UI_TOTAL" "$RF_UI_TOTAL" run "Building reports"
        local djson="reconforge-${dom}.json"
        build_domain_json "$dom" "$dom_dir" > "$djson"
        build_markdown "$dom" "$dom_dir" "$djson" "report-${dom}.md"
        build_html "$dom" "$dom_dir" "$djson" "report-${dom}.html"
        ui_phase "$RF_UI_TOTAL" "$RF_UI_TOTAL" ok "Reports ready" \
            "report-${dom}.html · report-${dom}.md · ${djson}"
    fi

    cd "$RF_OUTDIR" || true
    notify "Reconnaissance on $dom finished."
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    [[ "$RF_QUIET" != true ]] && banner "$RF_VERSION"

    # .env (next to script, then cwd)
    for envf in "$RF_SCRIPT_DIR/.env" "$PWD/.env"; do
        if [[ -f "$envf" ]]; then
            set -a; . "$envf"; set +a
            log_debug "loaded env from $envf"
        fi
    done
    [[ -n "${toolsDir:-}" && "$RF_TOOLSDIR" == "/opt" ]] && RF_TOOLSDIR="$toolsDir"

    # Ensure Go-, cargo- and pipx-installed tools are on PATH.
    case ":$PATH:" in *":$HOME/go/bin:"*) ;; *) export PATH="$PATH:$HOME/go/bin" ;; esac
    case ":$PATH:" in *":$HOME/.cargo/bin:"*) ;; *) export PATH="$PATH:$HOME/.cargo/bin" ;; esac
    case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$PATH:$HOME/.local/bin" ;; esac

    # Notifications
    if [[ "${RF_NOTIFY_LOCKED:-false}" != true && -n "${telegram_api_key:-}" && -n "${telegram_chat_id:-}" ]]; then
        RF_NOTIFY_ENABLED=true
    fi

    # Domains
    if ((${#RF_DOMAINS[@]} == 0)); then
        read -r -p "[?] Target domain(s), comma-separated: " resp
        IFS=', ' read -ra RF_DOMAINS <<< "$resp"
    fi
    local -a clean=()
    local d
    for d in "${RF_DOMAINS[@]}"; do
        d="$(echo "$d" | xargs)"
        [[ -z "$d" ]] && continue
        if valid_domain "$d"; then clean+=("$d"); else log_err "invalid domain, skipping: $d"; fi
    done
    ((${#clean[@]})) || { log_err "no valid domains supplied."; exit 1; }
    RF_DOMAINS=("${clean[@]}")

    # Output dir
    if [[ ! -d "$RF_OUTDIR" ]]; then
        if [[ "$RF_DRY_RUN" == true ]]; then
            log_info "[dry-run] would create output dir $RF_OUTDIR"
        else
            mkdir -p "$RF_OUTDIR" || { log_err "cannot create $RF_OUTDIR"; exit 1; }
        fi
    fi
    RF_OUTDIR="$(cd "$RF_OUTDIR" && pwd)"
    RF_STATE_DIR="$RF_OUTDIR/.reconforge-state"
    RF_SNAP_DIR="$RF_OUTDIR/.reconforge-snapshots"

    log_section "MISSION" "ReconForge v$RF_VERSION"
    ui_kv "mode"    "$RF_MODE" "$C_NEON"
    ui_kv "threads" "$RF_THREADS"
    ui_kv "targets" "${RF_DOMAINS[*]}" "$C_WHITE"
    ui_kv "output"  "$RF_OUTDIR"
    ui_kv "toolsdir" "$RF_TOOLSDIR"
    [[ "$RF_NOTIFY_ENABLED" == true ]] && ui_kv "notify" "enabled" "$C_NEON" || ui_kv "notify" "disabled" "$C_STEEL"

    # --- Missing-tool detection & optional auto-install -------------------
    local -a missing=()
    local t
    for t in "${RF_REQUIRED_TOOLS[@]}" "${RF_OPTIONAL_TOOLS[@]}"; do
        have "$t" || missing+=("$t")
    done

    if ((${#missing[@]})) && [[ "$RF_NO_INSTALL" != true ]]; then
        log_warn "missing tools: ${missing[*]}"
        local do_install=false
        if [[ "$RF_INSTALL" == true ]]; then
            do_install=true
        elif [[ "$RF_DRY_RUN" != true && -t 0 ]]; then
            read -r -p "[?] Install the missing tools now? [Y/n] " ans
            [[ -z "$ans" || "$ans" =~ ^[Yy] ]] && do_install=true
        fi
        if [[ "$do_install" == true ]]; then
            install_missing_tools
        else
            log_info "skipping install; phases using missing tools will be skipped."
        fi
    fi

    check_dependencies
    have nuclei || log_warn "nuclei missing - vulnerability phase will be skipped."

    if [[ "$RF_DRY_RUN" != true ]]; then
        mkdir -p "$RF_STATE_DIR" "$RF_SNAP_DIR"
        RF_LOG_FILE="$RF_OUTDIR/reconforge-$(date +'%Y%m%d-%H%M%S').log"
        : > "$RF_LOG_FILE"
        log_info "logging to $RF_LOG_FILE"
    fi

    local start; start=$(date +%s)
    for d in "${RF_DOMAINS[@]}"; do
        run_domain "$d" || log_err "domain $d encountered errors."
    done
    local end; end=$(date +%s)

    # Run summary ---------------------------------------------------------
    local dur=$(( end - start ))
    log_section "MISSION COMPLETE" "elapsed $(ui_hms "$dur")"
    ui_kv "phases run"     "$RF_STATS_STEPS_RUN" "$C_NEON"
    ui_kv "phases skipped" "$RF_STATS_STEPS_SKIP" "$C_STEEL"
    ui_kv "phases failed"  "$RF_STATS_STEPS_FAIL" "$([[ $RF_STATS_STEPS_FAIL -gt 0 ]] && echo "$C_RED" || echo "$C_STEEL")"
    ui_kv "findings"       "$RF_STATS_FINDINGS" "$C_PINK"
    ui_kv "errors"         "$RF_STATS_ERRORS" "$([[ $RF_STATS_ERRORS -gt 0 ]] && echo "$C_AMBER" || echo "$C_STEEL")"
    echo
    for d in "${RF_DOMAINS[@]}"; do
        local j="$RF_OUTDIR/$d/reconforge-${d}.json"
        if [[ -s "$j" ]]; then
            printf '   %s▸ %s%s  %slive=%s subs=%s nuclei=%s crit=%s high=%s%s\n' \
                "$C_NEON" "$d" "$C_RESET" \
                "$C_STEEL" \
                "$(jq -r '.counts.live_endpoints' "$j")" \
                "$(jq -r '.counts.subdomains' "$j")" \
                "$(jq -r '.counts.nuclei_findings' "$j")" \
                "$(jq -r '.counts.nuclei_critical' "$j")" \
                "$(jq -r '.counts.nuclei_high' "$j")" \
                "$C_RESET"
            printf '     %sreport → %s%s\n' "$C_STEEL" "$RF_OUTDIR/$d/report-${d}.html" "$C_RESET"
        fi
    done
    notify "Recon finished for ${#RF_DOMAINS[@]} domain(s). Findings: $RF_STATS_FINDINGS."
    echo
    log_ok "Mission complete."
}

main "$@"

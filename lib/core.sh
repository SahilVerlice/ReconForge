#!/usr/bin/env bash
# ReconForge :: core.sh
# Terminal UI engine, logging, notifications, state/checkpoint, dependency and
# wordlist handling. Sourced by reconforge.sh. No side effects at source time.

# ---------------------------------------------------------------------------
# Theme + glyphs. Colors auto-disable when not a TTY, NO_COLOR is set, or
# --no-color is passed. RF_ASCII=1 forces a plain-ASCII UI (no box-drawing).
# ---------------------------------------------------------------------------
RF_ASCII="${RF_ASCII:-0}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_BLUE=$'\033[34m'; C_MAGENTA=$'\033[35m'; C_CYAN=$'\033[36m'; C_WHITE=$'\033[97m'
    # neon palette (256-color terminals); degrades gracefully elsewhere
    C_NEON=$'\033[38;5;46m'      # matrix green
    C_PINK=$'\033[38;5;201m'     # hot magenta
    C_AMBER=$'\033[38;5;214m'
    C_VIOLET=$'\033[38;5;135m'
    C_STEEL=$'\033[38;5;244m'
    C_RF_COLOR=1
else
    C_RESET=""; C_DIM=""; C_BOLD=""
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_WHITE=""
    C_NEON=""; C_PINK=""; C_AMBER=""; C_VIOLET=""; C_STEEL=""
    C_RF_COLOR=0
fi

if [[ "$RF_ASCII" == 1 ]]; then
    G_TL='+'; G_TR='+'; G_BL='+'; G_BR='+'; G_H='-'; G_V='|'
    G_BAR='#'; G_BAR_E='.'; G_SPIN=('|' '/' '-' '\')
    G_DOT='o'; G_SKULL='x'; G_ARROW='->'
else
    G_TL='╭'; G_TR='╮'; G_BL='╰'; G_BR='╯'; G_H='─'; G_V='│'
    G_BAR='█'; G_BAR_E='░'; G_SPIN=('⣋' '⣙' '⣸' '⣼' '⣴' '⣦' '⣧' '⣇')
    G_DOT='●'; G_SKULL='☠'; G_ARROW='→'
fi

# ---------------------------------------------------------------------------
# Global counters + run metadata used by the summary / status bar.
# ---------------------------------------------------------------------------
RF_STATS_FINDINGS=0
RF_STATS_ERRORS=0
RF_STATS_STEPS_RUN=0
RF_STATS_STEPS_SKIP=0
RF_STATS_STEPS_FAIL=0

RF_UI_TOTAL=0          # total phases for the current domain
RF_UI_INDEX=0          # phases completed so far
RF_UI_T0=0             # domain start epoch
RF_UI_CUR="idle"       # current phase id
RF_UI_PHASE_T0=0       # current phase start epoch
RF_UI_PHASE_OK=0       # phases that finished without error
RF_UI_PHASE_FAIL=0
RF_UI_DOMAIN=""

_ts() { date +'%d/%m/%y %H:%M:%S'; }

# Render an escape-y string (e.g. '╭') into real glyphs. When the terminal
# cannot render unicode we are already in ASCII mode, so this is safe.
_gl() { printf '%b' "$1"; }

# Strip ANSI SGR escape sequences from a stream (tool output often leaks color
# into files even with --silent, which corrupts downstream greps/reports).
strip_ansi() { sed -r 's/\x1b\[[0-9;]*[mK]//g'; }

# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------
RF_UI_COLS="${COLUMNS:-0}"
_ui_cols() {
    local c="$RF_UI_COLS"
    (( c > 0 )) || c=$(tput cols 2>/dev/null || echo 100)
    (( c < 60 )) && c=60
    (( c > 120 )) && c=120
    echo "$c"
}

# Repeat a glyph N times.
_rep() { local n="$1" ch="$2" s=""; local i; for ((i=0;i<n;i++)); do s+="$ch"; done; printf '%s' "$s"; }

# rule [color]  -> full-width horizontal rule
rule() {
    local col="${1:-$C_STEEL}" c; c=$(_ui_cols)
    printf '%s%s%s\n' "$col" "$(_rep "$((c-1))" "$(_gl "$G_H")")" "$C_RESET"
}

# ---------------------------------------------------------------------------
# Banner (neon block logo + tagline). Printed once at start.
# ---------------------------------------------------------------------------
banner() {
    local ver="$1"
    local n="$C_NEON" d="$C_DIM" p="$C_PINK" r="$C_RESET"
    local c; c=$(_ui_cols)
    [[ "$C_RF_COLOR" == 1 ]] || { n=""; d=""; p=""; r=""; }
    if [[ "$RF_ASCII" == 1 ]]; then
        cat <<EOF

${n}  ____                 _____
${n} |  _ \ ___  ___ ___   |  ___|__  _ __ __ _  ___
${p} | |_) / _ \/ __/ _ \  | |_ / _ \| '__/ _\` |/ _ \\
${p} |  _ <  __/ (_| (_) | |  _| (_) | | | (_| |  __/
${n} |_| \_\___|\___\___/  |_|  \___/|_|  \__, |\___|
${n}                                      |___/
${d}  recon orchestrator - v${ver} - authorized testing only${r}

EOF
        return 0
    fi
    cat <<EOF

${n}   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗${r}
${n}   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝${r}
${p}   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗${r}
${p}   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝${r}
${n}   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗${r}
${n}   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝${r}
${d}   recon orchestrator · v${ver} · ${C_STEEL}authorized testing only${d} · ${C_STEEL}${c}col${r}

EOF
}

# ---------------------------------------------------------------------------
# Logging. All output funnels through _rf_emit so the log file and terminal
# stay in sync. Timestamps are dim so the level tag and message pop.
# ---------------------------------------------------------------------------
_rf_emit() {
    local level="$1" color="$2" tag="$3"; shift 3
    local line="$*"
    local plain="$(_ts) [$tag] $line"
    if [[ -n "${RF_LOG_FILE:-}" ]]; then
        printf '%s\n' "$plain" >> "$RF_LOG_FILE"
    fi
    if [[ -t 1 ]]; then
        printf '%s%s%s %s[%s]%s %s%s\n' \
            "$C_STEEL" "$(_ts)" "$C_RESET" "$color" "$tag" "$C_RESET" "$line" "$C_RESET"
    elif [[ -z "${RF_LOG_FILE:-}" ]]; then
        printf '%s\n' "$plain"
    fi
}

log_info()  { _rf_emit info  "$C_CYAN"    '*'  "$@"; }
log_ok()    { _rf_emit ok    "$C_NEON"    '+'  "$@"; }
log_warn()  { _rf_emit warn  "$C_AMBER"   '!'  "$@"; }
log_err()   { _rf_emit error "$C_RED"     'x'  "$@"; RF_STATS_ERRORS=$((RF_STATS_ERRORS+1)); }
log_debug() { [[ "${RF_DEBUG:-false}" == true ]] && _rf_emit debug "$C_DIM" 'D' "$@" || true; }
log_find()  { _rf_emit find  "$C_PINK"    '>>' "$@"; RF_STATS_FINDINGS=$((RF_STATS_FINDINGS+1)); }
log_hit()   { _rf_emit hit   "$C_PINK$C_BOLD" '!!' "$@"; RF_STATS_FINDINGS=$((RF_STATS_FINDINGS+1)); }

# section <title> [subtitle]
log_section() {
    local title="$1" sub="${2:-}"
    local c; c=$(_ui_cols)
    local tl tr bl br h
    tl=$(_gl "$G_TL"); tr=$(_gl "$G_TR"); h=$(_gl "$G_H")
    bl=$(_gl "$G_BL"); br=$(_gl "$G_BR")
    printf '\n%s%s%s%s%s\n' "$C_VIOLET" "$tl" "$(_rep "$((c-2))" "$h")" "$tr" "$C_RESET"
    if [[ -n "$sub" ]]; then
        printf '%s%s%s  %s%s%s%s\n' "$C_VIOLET" "$(_gl "$G_V")" "$C_RESET" \
            "$C_BOLD$C_WHITE" "$title" "$C_RESET" ""
        printf '%s%s%s  %s%s%s\n' "$C_VIOLET" "$(_gl "$G_V")" "$C_RESET" "$C_DIM" "$sub" "$C_RESET"
    else
        printf '%s%s%s  %s%s%s\n' "$C_VIOLET" "$(_gl "$G_V")" "$C_RESET" "$C_BOLD$C_WHITE" "$title" "$C_RESET"
    fi
    printf '%s%s%s%s%s\n' "$C_VIOLET" "$bl" "$(_rep "$((c-2))" "$h")" "$br" "$C_RESET"
}

# ---------------------------------------------------------------------------
# Phase progress bar:  [████████░░░░░░░░]  7/21  live
# ---------------------------------------------------------------------------
ui_bar() {
    local done="$1" total="$2" width="${3:-24}" i s="" bar=""
    (( total > 0 )) || total=1
    local fill=$(( done * width / total ))
    for ((i=0;i<fill;i++)); do s+="$(_gl "$G_BAR")"; done
    for ((i=fill;i<width;i++)); do s+="$(_gl "$G_BAR_E")"; done
    printf '%s%s%s' "$C_NEON" "$s" "$C_RESET"
}

# ui_phase <n> <total> <state> <label> [detail]
# state: run | ok | skip | fail | hit
ui_phase() {
    local n="$1" total="$2" state="$3" label="$4" detail="${5:-}"
    local col tag
    case "$state" in
        run)  col="$C_CYAN";   tag="RUN " ;;
        ok)   col="$C_NEON";   tag="OK  " ;;
        skip) col="$C_STEEL";  tag="SKIP" ;;
        fail) col="$C_RED";    tag="FAIL" ;;
        hit)  col="$C_PINK";   tag="HIT " ;;
        *)    col="$C_DIM";    tag="?   " ;;
    esac
    local mark; mark=$(_gl "$G_DOT")
    [[ "$state" == fail ]] && mark=$(_gl "$G_SKULL")
    printf '  %s%s%s %s%s%s %s%s%s  %s%s%s\n' \
        "$col" "$mark" "$C_RESET" \
        "$C_STEEL" "$(printf '%2d/%d' "$n" "$total")" "$C_RESET" \
        "$col" "$tag" "$C_RESET" \
        "$C_BOLD$C_WHITE" "$label" "$C_RESET"
    [[ -n "$detail" ]] && printf '        %s%s%s\n' "$C_DIM" "$detail" "$C_RESET"
    return 0
}

# ui_kv <key> <value> [color]
ui_kv() {
    printf '   %s%-22s%s %s%s%s\n' "$C_STEEL" "$1" "$C_RESET" "${3:-$C_WHITE}" "$2" "$C_RESET"
}

# ---------------------------------------------------------------------------
# Live status / elapsed helpers
# ---------------------------------------------------------------------------
ui_begin_domain() {
    RF_UI_DOMAIN="$1"; RF_UI_TOTAL="$2"; RF_UI_INDEX=0
    RF_UI_PHASE_OK=0; RF_UI_PHASE_FAIL=0; RF_UI_T0=$(date +%s)
}
ui_elapsed() { local now; now=$(date +%s); printf '%dm%02ds' $(( (now-RF_UI_T0)/60 )) $(( (now-RF_UI_T0)%60 )); }

# Human duration from seconds.
ui_hms() {
    local s="$1"
    printf '%dm%02ds' $(( s/60 )) $(( s%60 ))
}

# ---------------------------------------------------------------------------
# Notifications (Telegram / Slack / Discord / generic webhook). Optional,
# hardened: markdown fully escaped, failures never abort the scan.
# ---------------------------------------------------------------------------
RF_LAST_NOTIFIED=0
RF_NOTIFY_ENABLED=false

_post_webhook() {
    local url="$1" kind="$2" text="$3"
    [[ -z "$url" ]] && return 0
    local payload
    case "$kind" in
        slack)   payload=$(jq -n --arg t "$text" '{text:$t}') ;;
        discord) payload=$(jq -n --arg t "$text" '{content:$t}') ;;
        *)       payload=$(jq -n --arg t "$text" '{text:$t}') ;;
    esac
    curl -s --max-time 15 -X POST -H 'Content-Type: application/json' \
        -d "$payload" "$url" >/dev/null 2>&1 \
        || log_debug "$kind webhook failed (non-fatal)."
}

notify() {
    [[ "$RF_NOTIFY_ENABLED" == true ]] || return 0
    local text="$1"
    local now; now=$(date +%s)
    if (( now - RF_LAST_NOTIFIED < 1 )); then sleep 1; fi

    local prefix="ReconForge"
    [[ -n "${DOMAIN:-}" ]] && prefix="ReconForge [$DOMAIN]"
    local plain="$prefix: $text"

    if [[ -n "${telegram_api_key:-}" && -n "${telegram_chat_id:-}" ]]; then
        local esc; esc=$(printf '%s' "*$prefix* $text" | sed -E 's/([_*\[\]()~`>#+\-=|{}.!\\])/\\\1/g')
        curl -s --max-time 15 -X POST \
            "https://api.telegram.org/bot${telegram_api_key}/sendMessage" \
            --data-urlencode "chat_id=${telegram_chat_id}" \
            --data-urlencode "text=${esc}" \
            --data-urlencode "parse_mode=MarkdownV2" >/dev/null 2>&1 \
            || log_debug "Telegram notification failed (non-fatal)."
    fi

    _post_webhook "${slack_webhook_url:-}"   slack   "$plain"
    _post_webhook "${discord_webhook_url:-}" discord "$plain"
    _post_webhook "${generic_webhook_url:-}" generic "$plain"

    RF_LAST_NOTIFIED=$(date +%s)
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
RF_REQUIRED_TOOLS=(curl jq)
RF_OPTIONAL_TOOLS=(subfinder amass httpx dnsx naabu nuclei ffuf katana gau
                   waybackurls gospider hakrawler gf qsreplace anew subjack
                   nmap gobuster dalfox gowitness assetfinder uncover
                   arjun uro dnsgen alterx x8 wafw00f subjs paramspider
                   interactsh-client asnmap trufflehog gitleaks)

have() { command -v "$1" >/dev/null 2>&1; }

check_dependencies() {
    local missing_req=() missing_opt=()
    local t
    for t in "${RF_REQUIRED_TOOLS[@]}"; do have "$t" || missing_req+=("$t"); done
    for t in "${RF_OPTIONAL_TOOLS[@]}"; do have "$t" || missing_opt+=("$t"); done

    if ((${#missing_req[@]})); then
        log_err "Missing REQUIRED tools: ${missing_req[*]}"
        log_err "Install them and re-run (see README)."
        exit 2
    fi
    if ((${#missing_opt[@]})); then
        log_warn "missing optional tools: ${missing_opt[*]}"
        RF_MISSING_OPTIONAL=("${missing_opt[@]}")
    fi
    log_ok "dependencies ok ($((${#RF_OPTIONAL_TOOLS[@]} - ${#missing_opt[@]}))/${#RF_OPTIONAL_TOOLS[@]} optional present)."
}

# ---------------------------------------------------------------------------
# Wordlist resolution (never depends on a brittle $toolsDir path)
# ---------------------------------------------------------------------------
RF_WORDLIST_DIR=""
resolve_wordlist() {
    local candidates=(
        "${RF_WORDLIST_DIR}/tempfiles.txt"
        "$RF_SCRIPT_DIR/wordlists/tempfiles.txt"
        "/usr/share/seclists/Discovery/Web-Content/tempfiles.txt"
        "/usr/share/wordlists/seclists/Discovery/Web-Content/tempfiles.txt"
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
        "/usr/share/wordlists/dirb/common.txt"
    )
    local c
    for c in "${candidates[@]}"; do
        [[ -f "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

# ---------------------------------------------------------------------------
# State / checkpointing (per-domain resume)
# ---------------------------------------------------------------------------
RF_STATE_FILE=""
state_init() {
    RF_STATE_FILE="$1"
    mkdir -p "$(dirname "$RF_STATE_FILE")" 2>/dev/null || true
    [[ -f "$RF_STATE_FILE" ]] || : > "$RF_STATE_FILE" 2>/dev/null || true
}
state_done()  { grep -qxF "$1" "$RF_STATE_FILE" 2>/dev/null; }
state_mark()  { state_done "$1" || printf '%s\n' "$1" >> "$RF_STATE_FILE"; }

# step <id> <human label> <guard-file> <command...>
# Skips when the step is already recorded complete (unless --overwrite/--force).
# Marks complete only when the command exits 0 AND produces its guard file.
step() {
    local id="$1" label="$2" guard="$3"; shift 3

    RF_UI_INDEX=$((RF_UI_INDEX+1))
    local n="$RF_UI_INDEX" total="$RF_UI_TOTAL"
    RF_UI_CUR="$id"

    if [[ "$RF_OVERWRITE" != true ]] && state_done "$id"; then
        ui_phase "$n" "$total" skip "$label"
        RF_STATS_STEPS_SKIP=$((RF_STATS_STEPS_SKIP+1))
        RF_UI_PHASE_OK=$((RF_UI_PHASE_OK+1))
        return 0
    fi

    ui_phase "$n" "$total" run "$label"
    RF_UI_PHASE_T0=$(date +%s)
    notify "▶ $label"
    if "$@"; then
        if [[ -n "$guard" && ! -e "$guard" ]]; then
            log_warn "$label finished but expected output '$guard' is missing."
            RF_STATS_STEPS_FAIL=$((RF_STATS_STEPS_FAIL+1))
            RF_UI_PHASE_FAIL=$((RF_UI_PHASE_FAIL+1))
            return 1
        fi
        state_mark "$id"
        RF_STATS_STEPS_RUN=$((RF_STATS_STEPS_RUN+1))
        RF_UI_PHASE_OK=$((RF_UI_PHASE_OK+1))
        local dt=$(( $(date +%s) - RF_UI_PHASE_T0 ))
        printf '        %s%s %s in %s%s\n' "$C_STEEL" "$(_gl "$G_ARROW")" \
            "$label" "$(ui_hms "$dt")" "$C_RESET"
        return 0
    else
        log_err "$label failed (continuing)."
        RF_STATS_STEPS_FAIL=$((RF_STATS_STEPS_FAIL+1))
        RF_UI_PHASE_FAIL=$((RF_UI_PHASE_FAIL+1))
        return 1
    fi
}

# count_lines <file> -> 0 when file is missing
count_lines() { [[ -s "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }
file_count()  { [[ -d "$1" ]] && find "$1" -type f | wc -l | tr -d ' ' || echo 0; }

# ---------------------------------------------------------------------------
# Hardening helpers
# ---------------------------------------------------------------------------
safe_name() {
    printf '%s' "$1" | sed -E 's#^[a-z]+://##; s#[/:?&=]+#_#g; s#_+$##'
}

valid_domain() {
    [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

# ---------------------------------------------------------------------------
# Change detection / diffing (hunt what is *new*)
# ---------------------------------------------------------------------------
snapshot_save() {
    # NOTE: declare on separate lines - bash expands all RHS expressions before
    # assigning any of the locals, so `newf="${file}.new"` on the same `local`
    # line would see an empty $file.
    local file="$1"
    local snap="$2"
    local newf="${file}.new"
    [[ -s "$file" ]] || return 0
    if [[ -s "$snap" ]]; then
        comm -13 <(sort -u "$snap") <(sort -u "$file") > "$newf" 2>/dev/null || : > "$newf"
        if [[ -s "$newf" ]]; then
            log_hit "$(count_lines "$newf") NEW item(s) since last scan -> $newf"
            notify "🆕 $(count_lines "$newf") new item(s) found ($(basename "$file"))"
        else
            rm -f "$newf"
        fi
    fi
    sort -u "$file" > "$snap.tmp" && mv "$snap.tmp" "$snap"
}

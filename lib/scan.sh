#!/usr/bin/env bash
# ReconForge :: scan.sh
# All reconnaissance phases. Sourced by reconforge.sh.
#
# Design rules:
#   * Every external tool is wrapped in `timeout` — a hung tool must never make
#     the run look dead. A phase that exceeds its budget is killed and logged.
#   * Every phase is idempotent, writes deterministic filenames, and is wrapped
#     by `step` for checkpointing + error isolation.
#   * Long phases print progress so the terminal stays alive.

RF_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36"
RF_PAR="${RF_PAR:-40}"          # parallelism for ad-hoc HTTP checks
RF_HTTP_TO="${RF_HTTP_TO:-12}"  # per-request timeout
RF_DOMAIN_DIR=""                # set per-domain by the driver
RF_SNAP_DIR=""                  # snapshot dir for change detection
RF_MISSING_OPTIONAL=()

# need <tool> [phase] -> 0 if present, 1 (+debug) otherwise
need() {
    if have "$1"; then return 0; fi
    log_debug "optional tool '$1' not found; skipping ${2:-phase}"
    return 1
}

# run a command under a wall-clock cap; log (once) when it is killed.
# rf_timeout <seconds> <label> <cmd...>
rf_timeout() {
    local secs="$1" label="$2"; shift 2
    local rc
    timeout --signal=TERM --kill-after=10 "$secs" "$@"
    rc=$?
    if (( rc == 124 )); then
        log_warn "$label exceeded ${secs}s budget — killed (results so far kept)."
    fi
    return $rc
}

# compact progress line for long per-host loops
ui_progress() { # <done> <total> <label>
    local d="$1" t="$2" lbl="$3"
    (( t > 0 )) || return 0
    printf '      %s%s%s %s%s%s %s%s/%s%s  %s%s%s\n' \
        "$C_VIOLET" "$(_gl "$G_ARROW")" "$C_RESET" \
        "$(ui_bar "$d" "$t" 16)" "$C_RESET" \
        "$C_BOLD" "$d" "$t" "$C_RESET" \
        "$C_STEEL" "$lbl" "$C_RESET"
}

# ---------------------------------------------------------------------------
# Phase: subdomain enumeration
# ---------------------------------------------------------------------------
phase_subdomains() {
    local dom="$1" out="domains-${dom}.txt"
    local tmp; tmp=$(mktemp -d)
    local ran=false

    if need subfinder "subdomain enumeration"; then
        log_info "subfinder (passive, all sources)..."
        rf_timeout 300 "subfinder" subfinder -silent -all -d "$dom" -o "$tmp/subfinder.txt" 2>/dev/null || true
        ran=true
    fi
    if need amass "subdomain enumeration"; then
        log_info "amass (passive)..."
        rf_timeout 600 "amass" amass enum --passive -d "$dom" -o "$tmp/amass.txt" >/dev/null 2>&1 || true
        ran=true
    fi
    if need assetfinder "subdomain enumeration"; then
        log_info "assetfinder..."
        rf_timeout 120 "assetfinder" assetfinder --subs-only "$dom" > "$tmp/assetfinder.txt" 2>/dev/null || true
        ran=true
    fi

    if [[ "$ran" != true ]]; then
        log_warn "no subdomain enumerator available; using apex domain only."
        printf '%s\n' "$dom" > "$out"
    else
        cat "$tmp"/*.txt 2>/dev/null | sed '/^[[:space:]]*$/d' | sort -u > "$out"
    fi
    printf '%s\n' "$dom" >> "$out"
    sort -u -o "$out" "$out"
    rm -rf "$tmp"
    log_ok "subdomains: $(count_lines "$out") unique host(s)."
    if [[ -n "$RF_SNAP_DIR" ]]; then snapshot_save "$out" "$RF_SNAP_DIR/domains-${dom}.snap"; fi
}

# ---------------------------------------------------------------------------
# Phase: DNS resolution -> IP addresses
# ---------------------------------------------------------------------------
phase_resolve() {
    local dom="$1" hosts="domains-${dom}.txt" out="ip-addresses-${dom}.txt"

    if need dnsx "DNS resolution"; then
        rf_timeout 300 "dnsx" dnsx -silent -nc -l "$hosts" -a -resp -o "dnsx-${dom}.txt" >/dev/null 2>&1 || true
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "dnsx-${dom}.txt" 2>/dev/null \
            | sort -u > "$out" || true
    fi
    if [[ ! -s "$out" ]]; then
        log_warn "dnsx produced no data; falling back to getent."
        while read -r h; do
            [[ -z "$h" ]] && continue
            getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}'
        done < "$hosts" | sort -u > "$out"
    fi
    log_ok "resolved $(count_lines "$out") unique IP address(es)."
}

# ---------------------------------------------------------------------------
# Phase: HTTP probing -> live endpoints + tech/CDN fingerprint (JSON kept)
# ---------------------------------------------------------------------------
phase_live() {
    local dom="$1" hosts="domains-${dom}.txt" json="httpx-${dom}.json"
    local live="livedomains-${dom}.txt"

    if [[ ! -s "$hosts" ]]; then
        log_warn "no hosts to probe; creating empty live list."
        : > "$live"; return 0
    fi
    need httpx "HTTP probing" || { : > "$live"; return 0; }

    log_info "probing $(count_lines "$hosts") host(s) across common web ports..."
    rf_timeout 600 "httpx" httpx -silent -l "$hosts" \
        -ports 80,443,8080,8443,8000,8888,3000,5000,9000 \
        -status-code -title -tech-detect -cdn -cname -follow-redirects \
        -threads "$RF_THREADS" -timeout 10 -retries 2 \
        -json -o "$json" >/dev/null 2>&1 || true

    jq -r 'select(.failed == false) | .url' "$json" 2>/dev/null \
        | sed '/^[[:space:]]*$/d' | sort -u > "$live"

    log_ok "live endpoints: $(count_lines "$live")."
    if [[ -n "$RF_SNAP_DIR" ]]; then snapshot_save "$live" "$RF_SNAP_DIR/live-${dom}.snap"; fi
    if [[ -s "$json" ]]; then
        jq -r 'select(.tech != null) | "\(.url) [\(.tech|join(", "))]"' "$json" 2>/dev/null \
            | sort -u > "tech-${dom}.txt" || true
        jq -r 'select(.cdn_name != null) | "\(.host) -> \(.cdn_name) (\(.cdn_type // "?"))"' "$json" 2>/dev/null \
            | sort -u > "cdn-${dom}.txt" || true
        jq -r 'select(.webserver != null) | "\(.url) -> \(.webserver)"' "$json" 2>/dev/null \
            | sort -u > "servers-${dom}.txt" || true
        if [[ -s "tech-${dom}.txt" ]]; then
            log_find "$(count_lines "tech-${dom}.txt") technology fingerprint(s) -> tech-${dom}.txt"
        fi
        if [[ -s "cdn-${dom}.txt" ]]; then
            log_info "$(count_lines "cdn-${dom}.txt") host(s) behind a CDN -> cdn-${dom}.txt"
        fi
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Phase: screenshots
# ---------------------------------------------------------------------------
phase_screenshots() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || { log_warn "no live endpoints; skipping screenshots."; return 0; }

    if need httpx "screenshots"; then
        mkdir -p screenshots
        log_info "capturing screenshots with headless browser ($(count_lines "$live") targets)..."
        # Headless Chrome refuses to run as root without --no-sandbox.
        rf_timeout 900 "httpx screenshots" httpx -silent -l "$live" -ss -system-chrome -ho "--no-sandbox" \
            -srd screenshots -screenshot-timeout 20 -threads 10 -timeout 15 \
            >/dev/null 2>&1 || true
    elif need gowitness "screenshots"; then
        mkdir -p screenshots
        rf_timeout 900 "gowitness" gowitness scan file -f "$live" --screenshot-path screenshots >/dev/null 2>&1 || true
    fi
    log_ok "screenshots: $(file_count screenshots) file(s)."
}

# ---------------------------------------------------------------------------
# Phase: subdomain takeover
# ---------------------------------------------------------------------------
phase_takeover() {
    local dom="$1" hosts="domains-${dom}.txt"
    need subjack "subdomain takeover" || return 0

    local fp=""
    for c in "$RF_TOOLSDIR/subjack/fingerprints.json" \
             "$RF_SCRIPT_DIR/patterns/subjack-fingerprints.json" \
             "/usr/share/subjack/fingerprints.json" \
             "$HOME/go/src/github.com/haccer/subjack/fingerprints.json"; do
        [[ -f "$c" ]] && { fp="$c"; break; }
    done
    if [[ -z "$fp" ]]; then
        fp=$(find "$HOME/go/pkg/mod/github.com/haccer" -name fingerprints.json 2>/dev/null | head -1)
    fi
    if [[ -z "$fp" ]] && need git "subdomain takeover"; then
        local tmp; tmp=$(mktemp -d)
        if git clone -q --depth 1 https://github.com/haccer/subjack "$tmp/sj" 2>/dev/null; then
            fp="$tmp/sj/fingerprints.json"
            [[ -f "$fp" ]] && cp "$fp" "$RF_SCRIPT_DIR/patterns/subjack-fingerprints.json" 2>/dev/null || true
        fi
    fi
    if [[ -z "$fp" || ! -f "$fp" ]]; then
        log_warn "subjack fingerprints.json not found; skipping takeover check."
        return 0
    fi
    rf_timeout 300 "subjack" subjack -w "$hosts" -t 100 -c "$fp" -a -o "subjack-${dom}.txt" >/dev/null 2>&1 || true
    if [[ -s "subjack-${dom}.txt" ]] && grep -qiE 'vulnerable|takeover' "subjack-${dom}.txt"; then
        log_hit "potential subdomain takeover(s) -> subjack-${dom}.txt"
    else
        log_info "no subdomain takeover candidates."
    fi
}

# ---------------------------------------------------------------------------
# Phase: port scanning (naabu -> nmap)
# ---------------------------------------------------------------------------
phase_ports() {
    local dom="$1" ips="ip-addresses-${dom}.txt"
    [[ -s "$ips" ]] || { log_warn "no IPs; skipping port scan."; return 0; }

    local ports=""
    if need naabu "port scanning"; then
        log_info "naabu top-1000 TCP on $(count_lines "$ips") IP(s)..."
        rf_timeout 600 "naabu" naabu -silent -l "$ips" -top-ports 1000 -rate 2000 -c 50 \
            -o "naabu-${dom}.txt" >/dev/null 2>&1 || true
        cut -d: -f2 "naabu-${dom}.txt" 2>/dev/null | sort -un > "openports-${dom}.txt" || true
        ports=$(paste -sd, "openports-${dom}.txt" 2>/dev/null || true)
        log_ok "open TCP ports: ${ports:-none} -> openports-${dom}.txt"
    fi

    need nmap "port scanning" || return 0
    mkdir -p nmap
    if [[ -n "$ports" ]]; then
        log_info "nmap service/version scan on discovered ports..."
        rf_timeout 900 "nmap" nmap -T4 -sV --open -Pn -p "$ports" -iL "$ips" \
            -oA "nmap/nmap-${dom}" >/dev/null 2>&1 || true
    else
        log_info "nmap top-1000 scan (no naabu results)..."
        rf_timeout 900 "nmap" nmap -T4 -sV --open -Pn --top-ports 1000 -iL "$ips" \
            -oA "nmap/nmap-${dom}" >/dev/null 2>&1 || true
    fi
    log_ok "nmap results -> nmap/nmap-${dom}.*"
}

# ---------------------------------------------------------------------------
# Phase: historical URLs (gau + waybackurls)
# This is the phase that used to hang the whole run — both tools are now capped.
# ---------------------------------------------------------------------------
phase_urls() {
    local dom="$1" out="WayBack-${dom}.txt"
    local tmp; tmp=$(mktemp -d)
    local got=false

    if need gau "historical URLs"; then
        log_info "gau (historical URLs)..."
        rf_timeout 240 "gau" gau --threads 10 --subs --o "$tmp/gau.txt" "$dom" >/dev/null 2>&1 || \
            rf_timeout 120 "gau (fallback)" gau --subs "$dom" > "$tmp/gau.txt" 2>/dev/null || true
        got=true
    fi
    if need waybackurls "historical URLs"; then
        log_info "waybackurls..."
        rf_timeout 180 "waybackurls" waybackurls "$dom" > "$tmp/wayback.txt" 2>/dev/null || true
        got=true
    fi

    if [[ "$got" == true ]]; then
        cat "$tmp"/*.txt 2>/dev/null \
            | grep -a '?' \
            | qsreplace -a 2>/dev/null \
            | sort -u > "$out" || true
    fi
    rm -rf "$tmp"
    [[ -f "$out" ]] || : > "$out"
    log_ok "historical parameterized URLs: $(count_lines "$out") -> $out"
}

# ---------------------------------------------------------------------------
# Phase: crawling (katana + gospider)
# ---------------------------------------------------------------------------
phase_crawl() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || { log_warn "no live endpoints; skipping crawl."; return 0; }

    local tmp; tmp=$(mktemp -d)
    if need katana "crawling"; then
        log_info "katana crawl (JS-aware, depth 3)..."
        rf_timeout 600 "katana" katana -silent -list "$live" -d 3 -jc -kf all -ef woff,css,png,svg,jpg,jpeg,gif,ico \
            -c 20 -p 10 -o "$tmp/katana.txt" >/dev/null 2>&1 || true
    fi
    if need gospider "crawling"; then
        log_info "gospider crawl..."
        rf_timeout 400 "gospider" gospider -S "$live" -t 5 -c 10 -d 3 -m 3 --no-redirect \
            --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,svg \
            -o "$tmp/gospider" >/dev/null 2>&1 || true
    fi

    cat "$tmp"/*.txt "$tmp"/gospider/* 2>/dev/null \
        | grep -aoE 'https?://[^ "]+' \
        | grep -a "$dom" \
        | qsreplace -a 2>/dev/null \
        | sort -u > "crawl-${dom}.txt" || true
    rm -rf "$tmp"
    [[ -f "crawl-${dom}.txt" ]] || : > "crawl-${dom}.txt"

    cat "crawl-${dom}.txt" "WayBack-${dom}.txt" 2>/dev/null \
        | sort -u > "paths-${dom}.txt"
    log_ok "crawled endpoints: $(count_lines "crawl-${dom}.txt"); combined paths: $(count_lines "paths-${dom}.txt")."
}

# ---------------------------------------------------------------------------
# Phase: gf pattern tagging
# ---------------------------------------------------------------------------
ensure_gf_patterns() {
    [[ -d "$HOME/.gf" && -n "$(ls -A "$HOME/.gf" 2>/dev/null)" ]] && return 0
    need git "gf patterns" || return 1
    log_info "provisioning gf patterns..."
    local tmp; tmp=$(mktemp -d)
    if git clone -q --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$tmp/p" 2>/dev/null; then
        mkdir -p "$HOME/.gf"
        cp "$tmp"/p/*.json "$HOME/.gf/" 2>/dev/null || true
    fi
    if git clone -q --depth 1 https://github.com/tomnomnom/gf "$tmp/g" 2>/dev/null; then
        mkdir -p "$HOME/.gf"
        cp "$tmp"/g/examples/*.json "$HOME/.gf/" 2>/dev/null || true
    fi
    rm -rf "$tmp"
    [[ -n "$(ls -A "$HOME/.gf" 2>/dev/null)" ]]
}

phase_gf() {
    local dom="$1" paths="paths-${dom}.txt"
    [[ -s "$paths" ]] || { log_warn "no paths; skipping gf."; return 0; }
    need gf "gf tagging" || return 0
    ensure_gf_patterns || { log_warn "gf patterns unavailable; skipping gf."; return 0; }

    mkdir -p check-manually
    local total=0 p
    for p in ssrf xss redirect rce idor sqli lfi ssti debug_logic interestingparams \
             s3-buckets urls takeovers; do
        if gf "$p" < "$paths" > "check-manually/${p}.txt" 2>/dev/null; then
            local n; n=$(count_lines "check-manually/${p}.txt")
            total=$((total+n))
            (( n > 0 )) && printf '      %s%-18s%s %s%s%s\n' "$C_VIOLET" "$p" "$C_RESET" "$C_BOLD" "$n" "$C_RESET"
        fi
    done
    log_find "$total tagged endpoint(s) across gf patterns -> check-manually/"
}

# ---------------------------------------------------------------------------
# Phase: content discovery (ffuf) — with live progress
# ---------------------------------------------------------------------------
phase_ffuf() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || { log_warn "no live endpoints; skipping ffuf."; return 0; }
    need ffuf "content discovery" || return 0

    local wl; wl=$(resolve_wordlist) || {
        log_warn "tempfiles wordlist not found; skipping ffuf."; return 0; }

    mkdir -p ffuf
    local total; total=$(count_lines "$live")
    local i=0 dname filename
    while IFS= read -r dname; do
        [[ -z "$dname" ]] && continue
        i=$((i+1))
        filename=$(safe_name "$dname")
        ui_progress "$i" "$total" "ffuf ${dname}"
        rf_timeout 180 "ffuf ${dname}" ffuf -s -ac -w "$wl" -u "${dname%/}/FUZZ" \
            -mc 200-299,301,302,307,401,403 -maxtime 150 -t 50 \
            -o "ffuf/ffuf-${filename}.csv" -of csv >/dev/null 2>&1 || true
    done < "$live"

    find ffuf -type f -size -1c -delete 2>/dev/null || true
    local hits
    hits=$(find ffuf -type f -name '*.csv' -exec wc -l {} + 2>/dev/null \
            | sed '$d' | awk '{s += $1-1} END{print s+0}')
    if (( hits > 0 )); then
        log_find "$hits temporary/interesting file(s) found -> ffuf/"
    else
        log_info "no temporary files identified."
        rmdir ffuf 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Phase: nuclei vulnerability scan
# ---------------------------------------------------------------------------
phase_nuclei() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || { log_warn "no live endpoints; skipping nuclei."; return 0; }
    need nuclei "vulnerability scan" || return 0

    log_info "nuclei: $(count_lines "$live") target(s), severity low..critical, non-intrusive..."
    rf_timeout 1800 "nuclei" nuclei -silent -l "$live" -c 100 -rl 150 \
        -severity low,medium,high,critical -etags intrusive \
        -o "nuclei-${dom}.txt" >/dev/null 2>&1 || true

    if [[ -s "nuclei-${dom}.txt" ]]; then
        local crit high med low
        crit=$(grep -ci '\[critical\]' "nuclei-${dom}.txt" || true)
        high=$(grep -ci '\[high\]'     "nuclei-${dom}.txt" || true)
        med=$(grep -ci  '\[medium\]'   "nuclei-${dom}.txt" || true)
        low=$(grep -ci  '\[low\]'      "nuclei-${dom}.txt" || true)
        printf '      %scritical=%s high=%s medium=%s low=%s%s\n' \
            "$C_STEEL" "$crit" "$high" "$med" "$low" "$C_RESET"
        (( crit > 0 || high > 0 )) \
            && log_hit "nuclei: $(count_lines "nuclei-${dom}.txt") finding(s) [critical=$crit high=$high]" \
            || log_find "nuclei: $(count_lines "nuclei-${dom}.txt") finding(s) [medium=$med low=$low]"
        if [[ -n "$RF_SNAP_DIR" ]]; then snapshot_save "nuclei-${dom}.txt" "$RF_SNAP_DIR/nuclei-${dom}.snap"; fi
    else
        log_info "nuclei: no findings."
    fi
}

# ---------------------------------------------------------------------------
# Phase: active parameter checks (SSTI / LFI / open redirect)
# ---------------------------------------------------------------------------
_check_marker() {
    local list="$1" payload="$2" marker="$3" out="$4" label="$5"
    [[ -s "$list" ]] || { : > "$out"; return 0; }
    : > "$out"
    export RF_MARKER="$marker" RF_UA
    qsreplace "$payload" < "$list" 2>/dev/null | sort -u \
        | xargs -r -P "$RF_PAR" -I{} bash -c '
            body=$(curl -s --max-time 20 -A "$RF_UA" "{}" 2>/dev/null) || exit 0
            case "$body" in *"$RF_MARKER"*) printf "%s\n" "{}" ;; esac
          ' >> "$out" 2>/dev/null || true
    sort -u -o "$out" "$out"
    local n; n=$(count_lines "$out")
    (( n > 0 )) && log_hit "$label: $n candidate(s) -> $out"
    return 0
}

_check_redirect() {
    local list="$1" out="$2"
    [[ -s "$list" ]] || { : > "$out"; return 0; }
    : > "$out"
    local canary="https://reconforge-canary.invalid/$(date +%s)"
    export RF_CANARY="$canary" RF_UA
    qsreplace "$canary" < "$list" 2>/dev/null | sort -u \
        | xargs -r -P "$RF_PAR" -I{} bash -c '
            hdr=$(curl -s --max-time 15 -o /dev/null -D - -A "$RF_UA" "{}" 2>/dev/null) || exit 0
            case "$hdr" in *[Ll]ocation:*"$RF_CANARY"*) printf "%s\n" "{}" ;; esac
          ' >> "$out" 2>/dev/null || true
    sort -u -o "$out" "$out"
    local n; n=$(count_lines "$out")
    (( n > 0 )) && log_hit "open redirect: $n candidate(s) -> $out"
    return 0
}

phase_checks() {
    local dom="$1"
    log_info "active parameter checks (SSTI / LFI / open redirect)..."
    _check_marker "check-manually/ssti.txt"  "ReconForge{{1337*1337}}" "ReconForge1787569" \
        "potential-ssti.txt" "SSTI"
    _check_marker "check-manually/lfi.txt"   "/etc/passwd"              "root:x:0:0"        \
        "potential-lfi.txt"  "LFI"
    _check_redirect "check-manually/redirect.txt" "potential-or.txt"
}

# ---------------------------------------------------------------------------
# Phase: secrets in JS
# ---------------------------------------------------------------------------
phase_secrets() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || return 0
    if need gitleaks "secret scanning"; then
        mkdir -p js
        log_info "fetching JS assets and scanning for secrets..."
        while IFS= read -r u; do
            [[ "$u" == *.js ]] || continue
            rf_timeout 20 "curl $u" curl -s --max-time 15 -A "$RF_UA" "$u" \
                -o "js/$(safe_name "$u").js" 2>/dev/null || true
        done < "$live"
        if [[ -n "$(ls -A js 2>/dev/null)" ]]; then
            rf_timeout 120 "gitleaks" gitleaks detect --no-banner -s js \
                --report-path "secrets-${dom}.json" >/dev/null 2>&1 || true
            [[ -s "secrets-${dom}.json" ]] && log_hit "possible secret(s) in JS -> secrets-${dom}.json"
        fi
    fi
    if need trufflehog "secret scanning"; then
        rf_timeout 300 "trufflehog" trufflehog filesystem --no-update --only-verified . >/dev/null 2>&1 || true
    fi
}

# ---------------------------------------------------------------------------
# Phase: WAF detection (parallel)
# ---------------------------------------------------------------------------
phase_waf() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || { log_warn "no live endpoints; skipping WAF detection."; return 0; }
    need wafw00f "WAF detection" || return 0
    log_info "fingerprinting WAFs on $(count_lines "$live") host(s)..."
    : > "waf-${dom}.txt"
    export RF_UA
    xargs -r -P 10 -I{} bash -c '
        r=$(timeout 30 wafw00f -a "{}" 2>/dev/null | sed -r "s/\x1b\[[0-9;]*[mK]//g" | grep -iE "is behind|No WAF" | head -1)
        [ -n "$r" ] && printf "%s : %s\n" "{}" "$r"
    ' < "$live" >> "waf-${dom}.txt" 2>/dev/null || true
    if grep -qi 'behind' "waf-${dom}.txt" 2>/dev/null; then
        log_hit "WAF detected -> waf-${dom}.txt"
        grep -i 'behind' "waf-${dom}.txt" | head -5 | sed "s/^/      /"
    else
        log_info "no WAF detected on live hosts."
    fi
}

# ---------------------------------------------------------------------------
# Phase: hidden parameter discovery (arjun)
# ---------------------------------------------------------------------------
phase_params() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || { log_warn "no live endpoints; skipping parameter discovery."; return 0; }
    need arjun "parameter discovery" || return 0

    mkdir -p params
    local u i=0 total; total=$(count_lines "$live"); (( total > 10 )) && total=10
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        i=$((i+1)); (( i > 10 )) && break
        ui_progress "$i" "$total" "arjun ${u}"
        rf_timeout 150 "arjun ${u}" arjun -u "$u" -oT "params/arjun-$(safe_name "$u").txt" \
            -t 10 --stable --timeout 8 >/dev/null 2>&1 || true
    done < "$live"

    local found=0 f
    for f in params/*.txt; do [[ -s "$f" ]] && found=$((found+1)); done
    if (( found > 0 )); then
        cat params/*.txt 2>/dev/null | grep -oE '\b[a-zA-Z0-9_]{2,30}\b' | sort -u > "params-${dom}.txt" || true
        log_find "hidden parameters discovered ($(count_lines "params-${dom}.txt")) -> params-${dom}.txt"
    else
        log_info "no hidden parameters discovered."
        rmdir params 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Phase: XSS scanning (dalfox, optional active)
# ---------------------------------------------------------------------------
phase_xss() {
    local dom="$1"
    need dalfox "XSS scanning" || return 0
    local input="check-manually/xss.txt"
    [[ -s "$input" ]] || input="paths-${dom}.txt"
    [[ -s "$input" ]] || { log_warn "no URLs for XSS scan."; return 0; }

    log_info "dalfox XSS scan ($(count_lines "$input") URLs)..."
    rf_timeout 1200 "dalfox" dalfox file "$input" --silence --no-spinner --skip-bav \
        -w 30 --output "xss-${dom}.txt" >/dev/null 2>&1 || true
    if [[ -s "xss-${dom}.txt" ]]; then
        log_hit "dalfox: $(count_lines "xss-${dom}.txt") XSS candidate(s) -> xss-${dom}.txt"
        if [[ -n "$RF_SNAP_DIR" ]]; then snapshot_save "xss-${dom}.txt" "$RF_SNAP_DIR/xss-${dom}.snap"; fi
    else
        log_info "dalfox: no XSS findings."
    fi
}

# ---------------------------------------------------------------------------
# Phase: CORS misconfiguration (parallel, dependency-free)
# ---------------------------------------------------------------------------
phase_cors() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || { log_warn "no live endpoints; skipping CORS check."; return 0; }
    log_info "checking CORS misconfiguration..."
    : > "cors-${dom}.txt"
    export RF_UA
    xargs -r -P "$RF_PAR" -I{} bash -c '
        hdr=$(curl -s --max-time '"$RF_HTTP_TO"' -A "$RF_UA" -H "Origin: https://reconforge-evil.invalid" -D - -o /dev/null "{}" 2>/dev/null)
        acao=$(printf "%s" "$hdr" | grep -i "^access-control-allow-origin:" | tr -d "\r" | head -1)
        acac=$(printf "%s" "$hdr" | grep -i "^access-control-allow-credentials:" | tr -d "\r" | head -1)
        case "$acao" in
            *reconforge-evil.invalid*|*"*"*) printf "%s | %s | %s\n" "{}" "$acao" "${acac:-no-credentials}" ;;
        esac
    ' < "$live" >> "cors-${dom}.txt" 2>/dev/null || true
    if [[ -s "cors-${dom}.txt" ]]; then
        log_hit "possible CORS misconfiguration -> cors-${dom}.txt"
    else
        log_info "no obvious CORS misconfiguration."
    fi
}

# ---------------------------------------------------------------------------
# Phase: security headers (parallel, advisory)
# ---------------------------------------------------------------------------
phase_headers() {
    local dom="$1" live="livedomains-${dom}.txt"
    [[ -s "$live" ]] || { log_warn "no live endpoints; skipping header audit."; return 0; }
    log_info "auditing security headers..."
    : > "headers-${dom}.txt"
    export RF_UA
    xargs -r -P "$RF_PAR" -I{} bash -c '
        hdr=$(curl -s --max-time '"$RF_HTTP_TO"' -A "$RF_UA" -D - -o /dev/null "{}" 2>/dev/null)
        miss=""
        for w in strict-transport-security content-security-policy x-frame-options \
                 x-content-type-options referrer-policy permissions-policy; do
            printf "%s" "$hdr" | grep -qi "^$w:" || miss="$miss $w"
        done
        printf "%s | missing:%s\n" "{}" "${miss:- none}"
    ' < "$live" >> "headers-${dom}.txt" 2>/dev/null || true
    log_ok "header audit -> headers-${dom}.txt"
}

# ---------------------------------------------------------------------------
# Phase: cloud-storage / dangling-resource heuristics (parallel)
# ---------------------------------------------------------------------------
phase_cloud() {
    local dom="$1" hosts="domains-${dom}.txt"
    [[ -s "$hosts" ]] || { log_warn "no hosts; skipping cloud check."; return 0; }
    log_info "checking hosts for dangling cloud storage..."
    : > "cloud-${dom}.txt"
    export RF_UA
    xargs -r -P "$RF_PAR" -I{} bash -c '
        body=$(curl -s --max-time 10 -A "$RF_UA" "http://{}" 2>/dev/null | head -c 2000)
        code=$(curl -s --max-time 10 -A "$RF_UA" -o /dev/null -w "%{http_code}" "http://{}" 2>/dev/null)
        case "$body" in
            *NoSuchBucket*|*"The specified bucket does not exist"*|*NoSuchKey*)
                printf "%s | HTTP %s | dangling S3 bucket\n" "{}" "$code" ;;
            *"Repository not found"*|*"There isn'\''t a GitHub Pages site here"*)
                printf "%s | HTTP %s | dangling GitHub Pages\n" "{}" "$code" ;;
            *"No such app"*|*"herokucdn.com/error-pages/no-such-app"*)
                printf "%s | HTTP %s | dangling Heroku app\n" "{}" "$code" ;;
        esac
    ' < "$hosts" >> "cloud-${dom}.txt" 2>/dev/null || true
    if [[ -s "cloud-${dom}.txt" ]]; then
        log_hit "dangling cloud resource(s) -> cloud-${dom}.txt"
    else
        log_info "no dangling cloud resources identified."
    fi
}

# ---------------------------------------------------------------------------
# Phase: subdomain permutation + resolution (alterx/dnsgen -> dnsx)
# ---------------------------------------------------------------------------
phase_permute() {
    local dom="$1" subs="domains-${dom}.txt"
    [[ -s "$subs" ]] || { log_warn "no subdomains; skipping permutation."; return 0; }
    local perm="permutations-${dom}.txt"

    if need alterx "permutation"; then
        rf_timeout 120 "alterx" alterx -silent -l "$subs" -o "$perm" >/dev/null 2>&1 || true
    elif need dnsgen "permutation"; then
        rf_timeout 120 "dnsgen" dnsgen "$subs" > "$perm" 2>/dev/null || true
    fi
    if [[ ! -s "$perm" ]]; then
        local p
        for p in dev test stage staging prod api admin portal app vpn mail \
                 internal jenkins gitlab grafana kibana backup old new beta uat; do
            printf '%s.%s\n' "$p" "$dom"
        done > "$perm"
    fi

    if need dnsx "permutation resolution"; then
        rf_timeout 300 "dnsx (permutation)" dnsx -silent -nc -l "$perm" -a -resp-only \
            -o "permuted-live-${dom}.txt" >/dev/null 2>&1 || true
        [[ -s "permuted-live-${dom}.txt" ]] || : > "permuted-live-${dom}.txt"
        local before after
        before=$(count_lines "$subs")
        cat "$subs" "permuted-live-${dom}.txt" 2>/dev/null | sort -u -o "$subs"
        after=$(count_lines "$subs")
        log_find "permutation: $(( after - before )) new resolvable host(s) (from $(count_lines "$perm") candidates)."
    else
        log_ok "permutation candidates: $(count_lines "$perm") -> $perm"
    fi
}

# ---------------------------------------------------------------------------
# Phase: URL dedupe (uro)
# ---------------------------------------------------------------------------
phase_dedupe() {
    local dom="$1" paths="paths-${dom}.txt" out="paths-deduped-${dom}.txt"
    [[ -s "$paths" ]] || { log_warn "no paths to dedupe."; return 0; }
    local before; before=$(count_lines "$paths")

    if have uro; then
        rf_timeout 120 "uro" uro -i "$paths" -o "$out" >/dev/null 2>&1 || \
            rf_timeout 120 "uro" uro < "$paths" > "$out" 2>/dev/null || true
    fi
    if [[ ! -s "$out" ]]; then
        log_debug "uro unavailable; using built-in parameter-shape dedupe."
        sed -E 's/=[^&]*/=/g' "$paths" | sort -u > "$out" || cp "$paths" "$out"
    fi
    log_ok "deduped: $before -> $(count_lines "$out") URL shape(s) -> $out"
}

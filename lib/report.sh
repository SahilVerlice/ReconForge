#!/usr/bin/env bash
# ReconForge :: report.sh
# Builds a machine-readable JSON summary, a Markdown report, and a
# self-contained neon "terminal" HTML dashboard for a scanned domain.
# Sourced by reconforge.sh.

_json_str() { jq -Rn --arg s "$1" '$s'; }

# HTML-escape the first N lines of a file, or empty string if absent.
_html_file() {
    local f="$1" n="${2:-300}"
    [[ -s "$f" ]] || { printf ''; return 0; }
    sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$f" 2>/dev/null | head -"$n"
}

# Collect the interesting bits of a domain directory into a JSON object.
build_domain_json() {
    local dom="$1" dir="$2"
    local f
    _n() { [[ -s "$dir/$1" ]] && wc -l < "$dir/$1" | tr -d ' ' || echo 0; }
    # `grep -c` prints 0 *and* exits 1 on no match, so `|| echo 0` would emit
    # "0\n0" (invalid JSON). Use an explicit if/else instead.
    _nc() { if [[ -s "$2" ]]; then grep -ci "$1" "$2" 2>/dev/null | head -1; else echo 0; fi; }
    _screenshot_count() {
        [[ -d "$1/screenshots" ]] || { echo 0; return; }
        find "$1/screenshots" -type f \
            \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' \) 2>/dev/null \
            | wc -l | tr -d ' '
    }

    local subs live ips ports nuclei_total nuclei_crit nuclei_high nuclei_med nuclei_low
    local takeover gf_hits secrets
    subs=$(_n "domains-${dom}.txt")
    live=$(_n "livedomains-${dom}.txt")
    ips=$(_n "ip-addresses-${dom}.txt")
    ports=$(_n "openports-${dom}.txt")
    nuclei_total=$(_n "nuclei-${dom}.txt")
    nuclei_crit=$(_nc '\[critical\]' "$dir/nuclei-${dom}.txt")
    nuclei_high=$(_nc '\[high\]'     "$dir/nuclei-${dom}.txt")
    nuclei_med=$(_nc  '\[medium\]'   "$dir/nuclei-${dom}.txt")
    nuclei_low=$(_nc  '\[low\]'      "$dir/nuclei-${dom}.txt")
    takeover=$(_n "subjack-${dom}.txt")
    secrets=0
    [[ -s "$dir/secrets-${dom}.json" ]] && secrets=$(_nc '"Secret' "$dir/secrets-${dom}.json")
    gf_hits=0
    for f in "$dir"/check-manually/*.txt; do
        [[ -s "$f" ]] && gf_hits=$(( gf_hits + $(wc -l < "$f" | tr -d ' ') ))
    done

    local waf=0
    [[ -s "$dir/waf-${dom}.txt" ]] && grep -qi 'behind' "$dir/waf-${dom}.txt" && waf=1

    # Risk score (0-100): weighted, capped. Drives the dashboard gauge.
    local risk=$(( nuclei_crit*25 + nuclei_high*12 + takeover*30 + secrets*15 \
                 + $(_n "potential-ssti.txt")*20 + $(_n "potential-lfi.txt")*20 \
                 + $(_n "cloud-${dom}.txt")*20 + $(_n "cors-${dom}.txt")*6 \
                 + $(_n "xss-${dom}.txt")*15 + $(_n "potential-or.txt")*5 ))
    (( risk > 100 )) && risk=100

    jq -n \
        --arg domain "$dom" \
        --argjson subdomains "$subs" \
        --argjson live "$live" \
        --argjson ips "$ips" \
        --argjson ports "$ports" \
        --argjson nuclei_total "$nuclei_total" \
        --argjson nuclei_critical "$nuclei_crit" \
        --argjson nuclei_high "$nuclei_high" \
        --argjson nuclei_medium "$nuclei_med" \
        --argjson nuclei_low "$nuclei_low" \
        --argjson takeover "$takeover" \
        --argjson secrets "$secrets" \
        --argjson gf_tagged "$gf_hits" \
        --argjson ssti "$(_n "potential-ssti.txt")" \
        --argjson lfi "$(_n "potential-lfi.txt")" \
        --argjson redirect "$(_n "potential-or.txt")" \
        --argjson tech "$(_n "tech-${dom}.txt")" \
        --argjson cdn "$(_n "cdn-${dom}.txt")" \
        --argjson screenshots "$(_screenshot_count "$dir")" \
        --argjson waf "$waf" \
        --argjson cors "$(_n "cors-${dom}.txt")" \
        --argjson headers "$(_n "headers-${dom}.txt")" \
        --argjson cloud "$(_n "cloud-${dom}.txt")" \
        --argjson xss "$(_n "xss-${dom}.txt")" \
        --argjson params "$(_n "params-${dom}.txt")" \
        --argjson ffuf "$(_n "ffuf-hits.txt")" \
        --argjson new_subs "$(_n "domains-${dom}.txt.new")" \
        --argjson risk "$risk" \
        '{
            domain: $domain,
            risk_score: $risk,
            counts: {
                subdomains: $subdomains, new_subdomains: $new_subs,
                live_endpoints: $live, ip_addresses: $ips,
                open_ports: $ports, tech_fingerprints: $tech, cdn_hosts: $cdn,
                screenshots: $screenshots, gf_tagged: $gf_tagged,
                nuclei_findings: $nuclei_total, nuclei_critical: $nuclei_critical,
                nuclei_high: $nuclei_high, nuclei_medium: $nuclei_medium,
                nuclei_low: $nuclei_low, subdomain_takeover: $takeover,
                secrets_found: $secrets,
                potential_ssti: $ssti, potential_lfi: $lfi, potential_open_redirect: $redirect,
                waf_detected: $waf, cors_misconfig: $cors, dangling_cloud: $cloud,
                xss_candidates: $xss, hidden_params: $params
            }
        }'
}

# Human-readable Markdown report.
build_markdown() {
    local dom="$1" dir="$2" json="$3" out="$4"
    local g; g() { jq -r ".counts.$1" "$json"; }
    local risk; risk=$(jq -r '.risk_score' "$json")

    {
        echo "# ReconForge report — \`$dom\`"
        echo
        echo "_Generated $(date -u +'%Y-%m-%d %H:%M:%SZ')_ · **risk score: ${risk}/100**"
        echo
        echo "## Summary"
        echo
        echo "| Metric | Value |"
        echo "| --- | ---: |"
        echo "| Subdomains | $(g subdomains) |"
        echo "| Live endpoints | $(g live_endpoints) |"
        echo "| IP addresses | $(g ip_addresses) |"
        echo "| Open ports | $(g open_ports) |"
        echo "| Technology fingerprints | $(g tech_fingerprints) |"
        echo "| CDN-fronted hosts | $(g cdn_hosts) |"
        echo "| Nuclei findings | $(g nuclei_findings) (crit $(g nuclei_critical) / high $(g nuclei_high) / med $(g nuclei_medium) / low $(g nuclei_low)) |"
        echo "| Subdomain takeover candidates | $(g subdomain_takeover) |"
        echo "| Secrets in JS | $(g secrets_found) |"
        echo "| New subdomains since last scan | $(g new_subdomains) |"
        echo "| gf-tagged endpoints | $(g gf_tagged) |"
        echo "| Potential SSTI | $(g potential_ssti) |"
        echo "| Potential LFI | $(g potential_lfi) |"
        echo "| Potential open redirect | $(g potential_open_redirect) |"
        echo "| Potential XSS (dalfox) | $(g xss_candidates) |"
        echo "| Hidden parameters | $(g hidden_params) |"
        echo "| CORS misconfigurations | $(g cors_misconfig) |"
        echo "| Dangling cloud resources | $(g dangling_cloud) |"
        echo "| WAF detected | $(g waf_detected) |"
        echo "| Screenshots | $(g screenshots) |"
        echo
        _md_list "Live endpoints" "$dir/livedomains-${dom}.txt"
        _md_list "New subdomains (since previous scan)" "$dir/domains-${dom}.txt.new"
        _md_list "WAF detection" "$dir/waf-${dom}.txt"
        _md_list "Hidden parameters" "$dir/params-${dom}.txt"
        _md_list "CORS misconfigurations" "$dir/cors-${dom}.txt"
        _md_list "Dangling cloud resources" "$dir/cloud-${dom}.txt"
        _md_list "Potential XSS" "$dir/xss-${dom}.txt"
        _md_list "Technology fingerprints" "$dir/tech-${dom}.txt"
        _md_list "Nuclei findings" "$dir/nuclei-${dom}.txt"
        _md_list "Subdomain takeover" "$dir/subjack-${dom}.txt"
        _md_list "Potential SSTI" "$dir/potential-ssti.txt"
        _md_list "Potential LFI" "$dir/potential-lfi.txt"
        _md_list "Potential open redirects" "$dir/potential-or.txt"
        echo "## Raw artifacts"
        echo
        echo '```'
        (cd "$dir" && ls -1 2>/dev/null)
        echo '```'
    } > "$out"
}

_md_list() {
    local title="$1" file="$2"
    echo "## $title"
    echo
    if [[ -s "$file" ]]; then
        echo '```'
        head -50 "$file"
        local n; n=$(wc -l < "$file" | tr -d ' ')
        (( n > 50 )) && echo "... ($(( n - 50 )) more)"
        echo '```'
    else
        echo "_None._"
    fi
    echo
}

# Self-contained neon dashboard (inline CSS/JS, no external assets).
build_html() {
    local dom="$1" dir="$2" json="$3" out="$4"
    local counts; counts=$(jq -c '.counts' "$json")
    local risk; risk=$(jq -r '.risk_score' "$json")

    local SCREENSHOT_LIST
    SCREENSHOT_LIST=$(cd "$dir" 2>/dev/null && \
        find screenshots -type f \( -iname '*.png' -o -iname '*.jpeg' -o -iname '*.jpg' \) \
        -printf '%p\n' 2>/dev/null | jq -R . | jq -sc . ) || SCREENSHOT_LIST='[]'
    [[ -n "$SCREENSHOT_LIST" && "$SCREENSHOT_LIST" != '[]' ]] || SCREENSHOT_LIST='[]'

    # Pre-render escaped panels (tolerate missing files).
    local live_html nuclei_html tech_html waf_html cors_html cloud_html
    local params_html headers_html xss_html ssti_html lfi_html or_html secrets_html
    live_html=$(_html_file "$dir/livedomains-${dom}.txt" 400)
    nuclei_html=$(_html_file "$dir/nuclei-${dom}.txt" 400)
    tech_html=$(_html_file "$dir/tech-${dom}.txt" 300)
    waf_html=$(_html_file "$dir/waf-${dom}.txt" 200)
    cors_html=$(_html_file "$dir/cors-${dom}.txt" 200)
    cloud_html=$(_html_file "$dir/cloud-${dom}.txt" 200)
    params_html=$(_html_file "$dir/params-${dom}.txt" 300)
    headers_html=$(_html_file "$dir/headers-${dom}.txt" 300)
    xss_html=$(_html_file "$dir/xss-${dom}.txt" 300)
    ssti_html=$(_html_file "$dir/potential-ssti.txt" 200)
    lfi_html=$(_html_file "$dir/potential-lfi.txt" 200)
    or_html=$(_html_file "$dir/potential-or.txt" 200)
    secrets_html=$(_html_file "$dir/secrets-${dom}.json" 200)

    local gen; gen=$(date -u +'%Y-%m-%d %H:%M:%SZ')

    cat > "$out" <<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconForge // ${dom}</title>
<style>
:root{
  --bg:#05070a;--bg2:#0a0f14;--panel:#0c1319;--fg:#d6ffe0;--mut:#4d6b57;
  --neon:#39ff88;--pink:#ff2d95;--cyan:#22d3ee;--amber:#ffb020;--red:#ff3b3b;
  --violet:#a78bfa;--bd:#12301f;--glow:0 0 8px rgba(57,255,136,.45);
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--fg);
  font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,"Cascadia Code",monospace}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:9;
  background:repeating-linear-gradient(0deg,rgba(0,0,0,0) 0 2px,rgba(0,0,0,.22) 2px 4px);
  mix-blend-mode:multiply;opacity:.5}
body::after{content:"";position:fixed;left:0;right:0;height:120px;z-index:10;pointer-events:none;
  background:linear-gradient(180deg,transparent,rgba(57,255,136,.05),transparent);
  animation:scan 7s linear infinite}
@keyframes scan{0%{top:-140px}100%{top:100%}}
a{color:var(--cyan)}
header{padding:26px 34px 18px;border-bottom:1px solid var(--bd);position:relative}
h1{margin:0;font-size:22px;letter-spacing:.06em;color:var(--neon);text-shadow:var(--glow)}
h1 .d{color:var(--pink);text-shadow:0 0 8px rgba(255,45,149,.5)}
.prompt{color:var(--mut);font-size:12px;margin-top:6px}
.prompt b{color:var(--neon);font-weight:600}
.cursor{display:inline-block;width:8px;height:14px;background:var(--neon);margin-left:4px;
  vertical-align:-2px;animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
main{padding:22px 34px;max-width:1240px;margin:auto}
.bar{display:flex;gap:18px;align-items:center;flex-wrap:wrap;margin-bottom:22px}
.gauge{--v:${risk};width:120px;height:120px;border-radius:50%;flex:0 0 auto;
  background:conic-gradient(var(--red) calc(var(--v)*1%),var(--bd) 0);
  display:grid;place-items:center;box-shadow:0 0 24px rgba(255,59,59,.15)}
.gauge .in{width:94px;height:94px;border-radius:50%;background:var(--bg2);display:grid;place-items:center;
  text-align:center}
.gauge .num{font-size:26px;font-weight:700;color:var(--fg);line-height:1}
.gauge .lbl{font-size:9px;color:var(--mut);letter-spacing:.15em;text-transform:uppercase}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:10px;flex:1}
.tile{background:linear-gradient(180deg,var(--panel),var(--bg2));border:1px solid var(--bd);
  border-radius:8px;padding:12px 14px;position:relative;overflow:hidden}
.tile::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--mut)}
.tile.crit::before{background:var(--red)}.tile.warn::before{background:var(--amber)}
.tile.ok::before{background:var(--neon)}.tile.info::before{background:var(--cyan)}
.tile .v{font-size:22px;font-weight:700}
.tile .k{color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:.09em;margin-top:2px}
.tile.crit .v{color:var(--red)}.tile.warn .v{color:var(--amber)}.tile.ok .v{color:var(--neon)}
.tile.info .v{color:var(--cyan)}
.sev{display:flex;gap:0;height:10px;border-radius:6px;overflow:hidden;border:1px solid var(--bd);
  margin-bottom:22px;background:var(--bg2)}
.sev i{display:block;height:100%}
.sev .c{background:var(--red)}.sev .h{background:var(--amber)}
.sev .m{background:var(--cyan)}.sev .l{background:var(--violet)}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 0}
.tab{padding:7px 13px;border:1px solid var(--bd);border-bottom:none;border-radius:8px 8px 0 0;
  background:var(--bg2);color:var(--mut);cursor:pointer;font:inherit;font-size:12px}
.tab:hover{color:var(--fg)}
.tab.on{background:var(--panel);color:var(--neon);box-shadow:inset 0 2px 0 var(--neon)}
.panel{display:none;border:1px solid var(--bd);border-radius:0 8px 8px 8px;background:var(--panel);padding:0}
.panel.on{display:block}
.panel h2{margin:0;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--mut);
  padding:11px 14px;border-bottom:1px solid var(--bd)}
pre{margin:0;padding:14px;overflow:auto;max-height:440px;white-space:pre-wrap;word-break:break-word}
pre .crit{color:var(--red);font-weight:700}
pre .high{color:var(--amber);font-weight:700}
pre .med{color:var(--cyan)}
pre .low{color:var(--violet)}
.empty{color:var(--mut);font-style:italic;padding:14px}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px;padding:14px}
.gallery figure{margin:0}
.gallery img{width:100%;border:1px solid var(--bd);border-radius:6px;display:block;
  filter:saturate(.9) contrast(1.05);transition:transform .15s,box-shadow .15s}
.gallery img:hover{transform:scale(1.02);box-shadow:0 0 16px rgba(57,255,136,.25)}
.gallery figcaption{color:var(--mut);font-size:10px;margin-top:4px;word-break:break-all}
footer{color:var(--mut);font-size:10px;padding:20px 34px;border-top:1px solid var(--bd);letter-spacing:.06em}
.badge{display:inline-block;padding:1px 7px;border-radius:20px;font-size:10px;font-weight:700}
</style></head><body>
<header>
  <h1>ReconForge<span class="d">//</span>${dom}</h1>
  <div class="prompt">root@reconforge:~# recon <b>${dom}</b> --report &nbsp;·&nbsp; ${gen}<span class="cursor"></span></div>
</header>
<main>
  <div class="bar">
    <div class="gauge"><div class="in"><div><div class="num">${risk}</div><div class="lbl">risk</div></div></div></div>
    <div class="tiles" id="tiles"></div>
  </div>
  <div class="sev" id="sev"></div>

  <div class="tabs" id="tabs"></div>
  <div id="panels"></div>
</main>
<footer>ReconForge v2 · for authorized security testing only · findings are candidates, verify manually</footer>
<script>
const C=${counts};
const esc=s=>s.replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const tiles=[
 ["Subdomains",C.subdomains,"info"],["New subs",C.new_subdomains,C.new_subdomains>0?"ok":"info"],
 ["Live",C.live_endpoints,"ok"],["IPs",C.ip_addresses,"info"],["Ports",C.open_ports,"info"],
 ["Tech",C.tech_fingerprints,"info"],["CDN",C.cdn_hosts,"info"],
 ["Nuclei",C.nuclei_findings,C.nuclei_critical>0?"crit":(C.nuclei_high>0?"warn":"info")],
 ["Critical",C.nuclei_critical,"crit"],["High",C.nuclei_high,"warn"],
 ["Takeover",C.subdomain_takeover,C.subdomain_takeover>0?"crit":"info"],
 ["Secrets",C.secrets_found,C.secrets_found>0?"crit":"info"],
 ["SSTI",C.potential_ssti,C.potential_ssti>0?"crit":"info"],
 ["LFI",C.potential_lfi,C.potential_lfi>0?"crit":"info"],
 ["Open redir",C.potential_open_redirect,C.potential_open_redirect>0?"warn":"info"],
 ["XSS",C.xss_candidates,C.xss_candidates>0?"crit":"info"],
 ["Params",C.hidden_params,"info"],["CORS",C.cors_misconfig,C.cors_misconfig>0?"warn":"info"],
 ["Cloud",C.dangling_cloud,C.dangling_cloud>0?"crit":"info"],
 ["WAF",C.waf_detected?"yes":"no",C.waf_detected?"ok":"info"],
 ["gf tagged",C.gf_tagged,"info"],["Shots",C.screenshots,"info"]
];
document.getElementById("tiles").innerHTML=tiles.map(([k,v,c])=>
 \`<div class="tile \${c||"info"}"><div class="v">\${v}</div><div class="k">\${k}</div></div>\`).join("");

const tot=(C.nuclei_findings||1);
document.getElementById("sev").innerHTML=
 [["c",C.nuclei_critical],["h",C.nuclei_high],["m",C.nuclei_medium],["l",C.nuclei_low]]
 .map(([k,n])=>\`<i class="\${k}" style="width:\${(n/tot*100).toFixed(1)}%" title="\${k}:\${n}"></i>\`).join("");

const panels=${SCREENSHOT_LIST}.length?true:true;
const defs=[
 ["Live endpoints",\`${live_html}\`],["Nuclei",\`${nuclei_html}\`],["Tech",\`${tech_html}\`],
 ["Headers",\`${headers_html}\`],["CORS",\`${cors_html}\`],["Cloud",\`${cloud_html}\`],
 ["Params",\`${params_html}\`],["XSS",\`${xss_html}\`],["SSTI",\`${ssti_html}\`],
 ["LFI",\`${lfi_html}\`],["Open redirect",\`${or_html}\`],["Secrets",\`${secrets_html}\`],
 ["WAF",\`${waf_html}\`],["Screenshots",null]
];
const tabsEl=document.getElementById("tabs"),panelsEl=document.getElementById("panels");
defs.forEach(([name,html],i)=>{
  const t=document.createElement("button");t.className="tab"+(i?"":" on");t.textContent=name;
  t.onclick=()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));
    document.querySelectorAll(".panel").forEach(x=>x.classList.remove("on"));
    t.classList.add("on");document.getElementById("p"+i).classList.add("on");};
  tabsEl.appendChild(t);
  const p=document.createElement("section");p.className="panel"+(i?"":" on");p.id="p"+i;
  if(name==="Screenshots"){
    p.innerHTML='<h2>Screenshots</h2><div class="gallery" id="gallery"></div>';
  }else{
    const cls=name==="Nuclei"||["XSS","SSTI","LFI","Secrets"].includes(name)?"":"";
    p.innerHTML='<h2>'+name+'</h2>'+(html.trim()?('<pre>'+html+'</pre>'):'<div class="empty">no data</div>');
  }
  panelsEl.appendChild(p);
});
const g=document.getElementById("gallery");
if(g){for(const f of ${SCREENSHOT_LIST}){const fig=document.createElement("figure");
  const im=document.createElement("img");im.src=f;im.loading="lazy";im.alt=f;
  const cap=document.createElement("figcaption");cap.textContent=f;
  fig.appendChild(im);fig.appendChild(cap);g.appendChild(fig);}
  if(!g.children.length)g.innerHTML="<div class=\\"empty\\">no screenshots</div>";}
</script></body></html>
HTML
}

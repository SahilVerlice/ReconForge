# ReconForge

**Resource-conscious, checkpointed reconnaissance orchestrator for authorized security testing.**

ReconForge is a hardened, feature-extended reimplementation inspired by
[chvancooten/BugBountyScanner](https://github.com/chvancooten/BugBountyScanner).
It runs a full external recon pipeline over one or more domains, is safe to
re-run (per-step checkpointing), degrades gracefully when tools are missing,
and can **auto-install** whatever it needs on Kali/Debian.

> ⚠️ **Authorized testing only.** Only point this at systems you have explicit
> permission to test. You are responsible for your own actions.

---

## What's new in v2

- **Neon "operator console" terminal UI** — block-logo banner, framed section
  boxes, per-phase status markers (`●` running / `+` ok / `☠` failed), phase
  counters (`7/20`), per-phase elapsed times, live progress bars for long
  loops (ffuf/arjun), and a mission-summary panel with a per-target scoreboard.
- **It no longer hangs.** *Every* external tool is wrapped in `timeout` with a
  sensible budget. The old `urls` phase could stall the whole run on a
  hanging `gau`; it is now capped at 240s (then 120s fallback) and the scan
  moves on. A killed tool is logged, never fatal.
- **Much faster** — parallelized the previously serial per-host phases
  (`cors`, `headers`, `waf`, `cloud`) with `xargs -P`, bumped `ffuf`/`katana`
  concurrency, and added extra web ports to the probe list.
- **Hacker dashboard** — the HTML report is now a self-contained neon CRT
  terminal: scanline/glow effects, a **risk gauge** (0–100, weighted by
  critical/high findings, takeovers, secrets, injection candidates), a
  critical→low severity bar, tabbed panels, and a screenshot gallery.
- **New flags:** `-q/--quiet` (minimal output), `--ascii` (ASCII-only UI).
- **More phases per pattern:** `gf` now tags `s3-buckets`, `urls`, `takeovers`;
  tech detection also records web servers; JSON gains `risk_score` and
  medium/low nuclei counts.

---

## Why a reimplementation?

The upstream Bash script is a great foundation but had a number of real bugs.
ReconForge fixes them and adds modern tooling.

### Bugs fixed (inherited from upstream)

| # | Issue in upstream | Fix in ReconForge |
|---|---|---|
| 1 | **`ffuf` directory handling was broken** — `cd ffuf` then a loop referencing `../livedomains-…`, an extra stray `fi`, and only returned to the parent in one branch. | Rewrote the phase to stay in the domain dir, write per-host CSV files under `ffuf/`, and always return cleanly. |
| 2 | **`nrich` is a defunct service** — `nrich ip-addresses-… > nrich-…` hangs/fails and the "IP enrichment" step never produced useful output. | Replaced with `httpx`-based enrichment (tech, CDN, CNAME) which works offline of any dead API. |
| 3 | **Partial IP list treated as success** — `grep … \| sort -u > out && rm dig.txt` used `&&`, so on no match the file was still created and the temp file leaked; later steps then ran on garbage. | `dnsx` with validation + `getent` fallback; empty results handled explicitly. |
| 4 | **Empty input could stall the pipeline** — e.g. an empty `livedomains` file was piped into `cat … \| aquatone`. | Every phase guards on empty inputs and short-circuits. |
| 5 | **Port scan derived IPs from a regex over `nmap` output** (`grep Port … \| cut -f2`) — brittle and wrong for some output formats. | `naabu` produces the canonical host:port list; ports are extracted from it directly. |
| 6 | **Active checks (SSTI/LFI/OR) ran through `xargs` with a marker literally in the command string**, so `grep -q` in the pipeline could report success even when nothing was found. | Markers are passed via the environment; each URL is fetched once and tested in-process. Parallelism is correct. |
| 7 | **Only a single global `--overwrite` flag** — an interrupted multi-day scan could not resume; you either redid everything or nothing. | Per-domain **state/checkpoint files** (`.reconforge-state/<domain>.state`). Re-running skips completed steps; `--overwrite` forces a full redo. |
| 8 | **Hard dependency on `$toolsDir/wordlists/tempfiles.txt`**, which `setup.sh` never created → `ffuf` silently no-oped. | Wordlist resolution order: `--toolsdir` → bundled `wordlists/tempfiles.txt` → SecLists → system paths. A wordlist ships with the repo. |
| 9 | **`aquatone` is abandoned** and no longer installs cleanly on modern systems. | Screenshots use `httpx -screenshot` (headless Chrome) with a `gowitness` fallback. |
| 10 | **`subjack` fingerprints path assumed** at `$toolsDir/subjack/fingerprints.json`, which `go install` never creates → takeover check always failed. | Fingerprints are discovered from the Go module cache, a shallow clone, or the bundled `patterns/subjack-fingerprints.json`. |
| 11 | **`grep -c … \|\| echo 0`** idiom produced `"0\n0"` in the report when there were zero matches (invalid JSON). | Explicit `if/else` counters. |
| 12 | **Argument parsing used `for arg in "$@"` with `shift`**, which does not actually advance and mis-handles values that look like flags. | Standard `while (($#)); do case … esac; done` parser. |
| 13 | **`set -e` absent, so silent failures accumulated**; conversely, some steps aborted the whole run. | `pipefail` + per-step error isolation: a failed step is logged and the scan continues. |
| 14 | **No input validation** — a malformed `-d` value was passed straight to scanners. | Domains are validated before use. |
| 15 | **ffuf reported 119 "hits" against a catch-all redirect** (e.g. http→https 302 on every path). | `ffuf -ac` auto-calibration eliminates wildcard/soft-404 false positives. |

### New features

- **Auto-install missing tools** (`--install`, or an interactive prompt) via
  `apt` + `go install` + `pipx`/`pip` + `cargo`, plus nuclei templates, gf
  patterns and subjack fingerprints. `setup.sh` installs without scanning;
  `setup.sh --check` reports status.
- **Three modes:** `quick` (subdomains → resolve → live → takeover),
  `standard` (adds screenshots, URLs, crawl, gf, nuclei), `deep` (everything).
- **Phase selection:** `--only` / `--skip` with a comma-separated phase list.
- **Checkpointing / resume** per domain, plus `--overwrite`.
- **Change detection (diffing):** subdomains, live endpoints, nuclei findings
  and XSS hits are snapshotted between runs; anything **new since the last
  scan** is written to `<file>.new`, reported, and pushed as a notification —
  ideal for recurring monitoring where you only care about what changed.
- **Intrusive-phase safety gate:** active XSS scanning (`dalfox`) only runs with
  `--active` (or an explicit `--only xss`), so default scans stay non-intrusive.
- **Structured output:** per-domain `reconforge-<domain>.json` (machine-readable),
  `report-<domain>.md` (Markdown), and a **self-contained dark-mode HTML dashboard**
  with a screenshot gallery (no external assets).
- **Richer fingerprinting:** technology detection, CDN identification, CNAME
  mapping, WAF detection, open-port list.
- **Webhook notifications:** Slack / Discord / generic webhooks in addition to
  Telegram (set `slack_webhook_url`, `discord_webhook_url`, `generic_webhook_url`).
- **Modern tooling:** `subfinder`/`amass`/`assetfinder`, `dnsx`, `naabu`+`nmap`,
  `katana` (JS-aware) + `gospider`, `gau`+`waybackurls`, `nuclei` v3, `ffuf`,
  `arjun`, `dalfox`, `alterx`/`dnsgen`, `uro`, `wafw00f`, `gitleaks`, `gowitness`.
- **Graceful degradation:** missing optional tools are reported once and their
  phases are skipped — the run never dies because one tool is absent.
- **Dry-run mode** (`-n`) to preview what would execute.

### Bug-hunter phase reference

| Phase | What it does | Tool |
|---|---|---|
| `subdomains` | Passive subdomain enumeration | subfinder / amass / assetfinder |
| `resolve` | DNS → unique IPs | dnsx (+getent fallback) |
| `live` | HTTP probe, tech/CDN/CNAME fingerprint | httpx |
| `screenshots` | Headless-Chrome captures + gallery | httpx / gowitness |
| `takeover` | Subdomain takeover candidates | subjack |
| `urls` | Historical parameterized URLs | gau / waybackurls |
| `crawl` | JS-aware crawl + combined path list | katana / gospider |
| `gf` | Tag endpoints by vuln class | gf (+auto patterns) |
| `nuclei` | CVE/misconfig/template scan | nuclei |
| `ffuf` | Temp-file/backup discovery (auto-calibrated) | ffuf |
| `checks` | SSTI / LFI / open-redirect probes | curl |
| `ports` | TCP port + service scan | naabu + nmap |
| `secrets` | Secrets in JS / responses | gitleaks |
| `waf` | WAF fingerprinting | wafw00f |
| `params` | Hidden parameter discovery | arjun |
| `permute` | Subdomain permutation + resolve | alterx / dnsgen + dnsx |
| `xss` | Active XSS scanning (**needs `--active`**) | dalfox |
| `cors` | CORS misconfiguration check | curl |
| `headers` | Security-header audit | curl |
| `cloud` | Dangling S3/GitHub Pages/Heroku | curl |
| `dedupe` | URL-shape deduplication | uro (+fallback) |

---

## Install

```bash
git clone <this-repo> ReconForge && cd ReconForge
chmod +x reconforge.sh setup.sh
bash setup.sh            # install missing tools (Kali/Debian)
```

`setup.sh` installs what it can: `apt` packages (jq, nmap, gobuster, nikto,
whatweb, dirsearch …) and Go tools (`subfinder`, `httpx`, `nuclei`, `ffuf`,
`katana`, `naabu`, `dnsx`, `gau`, `katana`, `gf`, `qsreplace`, `subjack`,
`gowitness`, `gitleaks`, …). Requires Go (Kali: `sudo apt install -y golang`).

You don't strictly have to run setup first — on the first scan, if tools are
missing, ReconForge offers to install them:

```bash
./reconforge.sh -d example.com          # prompts to install missing tools
./reconforge.sh --install -d example.com   # install without prompting
./reconforge.sh --no-install -d example.com
```

## Usage

```
./reconforge.sh [options] -d <domain> [-d <domain> ...]

  -d, --domain <d>        Target domain (repeatable). Prompts if omitted.
  -o, --output <dir>      Parent output dir (default: current dir).
  -t, --toolsdir <dir>    Tools dir for wordlists/fingerprints (default: /opt).
  -m, --mode <mode>       quick | standard | deep        (default: standard)
      --only <list>       Comma-separated phases to run exclusively.
      --skip <list>       Comma-separated phases to skip.
      --threads <n>       Parallelism for httpx/ad-hoc checks   (default: 40)
  -w, --overwrite         Re-run every step, ignoring checkpoints.
  -n, --dry-run           Show what would run, do not execute scans.
      --install           Auto-install missing tools, then scan.
      --no-install        Never install tools.
      --active            Enable intrusive phases (xss/dalfox). Off by default.
  -q, --quiet             Minimal output (log file still gets everything).
      --ascii             ASCII-only UI (no box-drawing / braille glyphs).
      --no-notify         Disable Telegram notifications.
      --no-color          Disable colored output (also honors NO_COLOR).
      --debug             Verbose debug logging.
  -h, --help / -V, --version
```

**Phases:** `subdomains resolve live screenshots takeover urls crawl gf nuclei ffuf checks ports secrets waf params permute xss cors headers cloud dedupe`

### Examples

```bash
./reconforge.sh -d example.com
./reconforge.sh -d example.com -m deep --threads 80 -o ~/recon
./reconforge.sh -d example.com --only subdomains,live,nuclei
./reconforge.sh -d example.com --skip ports,secrets
./reconforge.sh -d a.com -d b.com -m quick --no-install
```

## Output layout

```
<outdir>/
├── reconforge-<timestamp>.log
├── .reconforge-state/<domain>.state     # resume checkpoints
└── <domain>/
    ├── domains-<domain>.txt             # subdomains
    ├── ip-addresses-<domain>.txt        # resolved IPs
    ├── httpx-<domain>.json              # full probe data
    ├── livedomains-<domain>.txt         # live endpoints
    ├── tech-<domain>.txt, cdn-<domain>.txt
    ├── screenshots/                     # headless-Chrome captures
    ├── WayBack-<domain>.txt             # historical parameterized URLs
    ├── crawl-<domain>.txt, paths-<domain>.txt
    ├── check-manually/*.txt             # gf-tagged candidates
    ├── nuclei-<domain>.txt              # findings
    ├── potential-{ssti,lfi,or}.txt
    ├── ffuf/                            # content discovery
    ├── nmap/, naabu-<domain>.txt
    ├── report-<domain>.md               # Markdown report
    ├── report-<domain>.html             # HTML dashboard
    └── reconforge-<domain>.json         # machine-readable summary
```

## Notifications (optional)

Copy `.env.example` to `.env` and set `telegram_api_key` / `telegram_chat_id`
to receive progress messages. Without it, notifications are simply disabled.

## Legal

Provided for authorized security testing and educational use only. Do not use
against systems you do not own or lack written permission to test.

## Credits

Inspired by [BugBountyScanner](https://github.com/chvancooten/BugBountyScanner)
by Cas van Cooten. ReconForge is an independent reimplementation.

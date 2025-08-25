#!/usr/bin/env bash
# XCS Bug Bounty FULL Toolkit (single-file)
# Company: X Cyber Squad
# Author: Neerav Patel
# Version: 3.0.0 (All-in-one: Recon, Vuln, Param discovery, XSS/SQLi/CSRF, OSINT)
#
# NOTE: Use only on assets you own or have explicit permission to test.
# This script orchestrates many 3rd-party pentest tools (sqlmap, dalfox, xsstrike, nuclei, nmap).
# It does not use paid APIs. For best accuracy, install and keep tools updated.
set -Eeuo pipefail
IFS=$'\n\t'

########## CONFIG ##########
GOBIN="${GOBIN:-$(go env GOPATH 2>/dev/null)/bin}"
OUT_ROOT="out"
BREACH_DIR="${HOME}/breach_dumps"      # put local breach dumps here (optional)
FEEDS_DIR="${HOME}/.xcs_feeds"        # optional local feeds (NVD, phishtank, urlhaus)
WORDLIST_DIR="/usr/share/wordlists"   # adapt if needed
DEFAULT_WORDLIST="$WORDLIST_DIR/raft-large-words.txt"   # used by ffuf if present
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
VERSION="3.0.0"
########## END CONFIG ##########

# Helpers
echoinfo(){ echo -e "\e[36m[+]\e[0m $*"; }
echoerr(){ echo -e "\e[31m[!]\e[0m $*" >&2; }
echowarn(){ echo -e "\e[33m[-]\e[0m $*"; }

# Tool check
require(){ command -v "$1" >/dev/null 2>&1 || { echoerr "Missing required tool: $1"; return 1; }; }
optional(){ command -v "$1" >/dev/null 2>&1 && return 0 || return 1; }

# Print usage
usage(){
  cat <<EOF
XCS Bug Bounty FULL Toolkit v$VERSION

Usage:
  $0 [options]

Interactive menu (run without args):
  $0

Direct flags:
  --bugbounty -d <domain>       Run full bug-bounty flow (recon -> vuln -> params -> xss/sqli/csrf)
  --osint --email <email>       Run OSINT breach checks for email
  --osint --phone <phone>       Run OSINT breach checks for phone (E.164)
  --full -d <domain> --email <email> --phone <phone>   Run both bugbounty and OSINT
  --setup                       Install dependencies (Debian/Ubuntu/Kali; requires sudo)
  --init-feeds                  Download offline feeds (NVD, PhishTank, URLHaus)
  -o, --out <dir>               Output directory (default: out/<timestamp>)
  -h, --help                    Show this help

Examples:
  $0 --setup
  $0 --init-feeds
  $0 --bugbounty -d example.com -o out/example
  $0 --full -d example.com --email victim@ex.com --phone +919876543210 -o out/case1

EOF
  exit 0
}

# Argument parsing
DOMAIN=""
OUTDIR=""
MODE=""
EMAILS=()
PHONES=()
DO_SETUP=false
DO_INIT_FEEDS=false

# Short/long mapping
parselong(){
  for arg in "$@"; do shift
    case "$arg" in
      --bugbounty) set -- "$@" --bugbounty ;;
      --full) set -- "$@" --full ;;
      --osint) set -- "$@" --osint ;;
      --init-feeds) set -- "$@" --init-feeds ;;
      --setup) set -- "$@" --setup ;;
      --email) set -- "$@" --email ;;
      --phone) set -- "$@" --phone ;;
      --out) set -- "$@" -o ;;
      --domain) set -- "$@" -d ;;
      --help) set -- "$@" -h ;;
      *) set -- "$@" "$arg" ;;
    esac
  done
  echo "$@"
}

ARGS=$(parselong "$@")
set -- $ARGS
while (( "$#" )); do
  case "$1" in
    --bugbounty) MODE="BUGB"; shift ;;
    --full) MODE="FULL"; shift ;;
    --osint) MODE="OSINT"; shift ;;
    --init-feeds) DO_INIT_FEEDS=true; shift ;;
    --setup) DO_SETUP=true; shift ;;
    -d) DOMAIN="${2:-}"; shift 2 ;;
    -o) OUTDIR="${2:-}"; shift 2 ;;
    --email) EMAILS+=("${2:-}"); shift 2 ;;
    --phone) PHONES+=("${2:-}"); shift 2 ;;
    -h|--help) usage ;;
    *) echoerr "Unknown arg: $1"; usage ;;
  esac
done

# default outdir
[[ -z "$OUTDIR" ]] && OUTDIR="${OUT_ROOT}/${TIMESTAMP}"
mkdir -p "$OUTDIR"

# Setup installer (Debian/Ubuntu/Kali)
if [[ "$DO_SETUP" == true ]]; then
  echoinfo "Running setup (apt) - you will be prompted for sudo..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt update
    sudo apt install -y jq curl wget unzip python3 python3-pip golang-go git whois nmap pandoc wkhtmltopdf ffuf \
         build-essential libssl-dev zlib1g-dev
    pip3 install --break-system-packages dalfox xsstrike || pip3 install dalfox xsstrike
    pip3 install holehe h8mail
    # Go installs
    export PATH="$PATH:$GOBIN"
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/lc/gau/v2/cmd/gau@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest || true
    # paramspider & xsstrike/dalfox/sqlmap install hints:
    pip3 install paramspider
    # sqlmap
    if ! command -v sqlmap >/dev/null 2>&1; then
      git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$HOME/sqlmap" 2>/dev/null || true
      ln -sf "$HOME/sqlmap/sqlmap.py" /usr/local/bin/sqlmap || true
    fi
    echoinfo "Setup finished. Ensure $GOBIN is in your PATH, then re-open your shell."
  else
    echoerr "APT not available on this system. Manual install required."
  fi
  exit 0
fi

# Init offline feeds
if [[ "$DO_INIT_FEEDS" == true ]]; then
  echoinfo "Initializing offline feeds into $FEEDS_DIR"
  mkdir -p "$FEEDS_DIR"
  # NVD recent
  wget -q -O "$FEEDS_DIR/nvdcve-recent.json.gz" "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz" || true
  [[ -f "$FEEDS_DIR/nvdcve-recent.json.gz" ]] && gunzip -f "$FEEDS_DIR/nvdcve-recent.json.gz" || true
  # PhishTank + URLHaus
  wget -q -O "$FEEDS_DIR/phishtank.csv" "http://data.phishtank.com/data/online-valid.csv" || true
  wget -q -O "$FEEDS_DIR/urlhaus.csv" "https://urlhaus.abuse.ch/downloads/csv_recent/" || true
  echoinfo "Feeds updated (if downloads succeeded)."
  exit 0
fi

# If no direct modes and no args -> show interactive menu
if [[ -z "$MODE" && -z "$DOMAIN" && ${#EMAILS[@]} -eq 0 && ${#PHONES[@]} -eq 0 ]]; then
  cat <<MENU
XCS Bug Bounty Toolkit v$VERSION (Interactive Menu)
1) Bug Bounty Recon & Vulnerability Scan
2) Data Breach / OSINT
3) Full Scan (1 + 2)
4) Setup (install dependencies)
5) Init Offline Feeds (NVD, PhishTank, URLHaus)
0) Exit
Choose [0-5]:
MENU
  read -r CH
  case "$CH" in
    1) MODE="BUGB"; read -p "Domain: " DOMAIN ;;
    2) MODE="OSINT"; read -p "Email (leave blank to skip): " e; read -p "Phone (E.164) (leave blank to skip): " p; [[ -n "$e" ]] && EMAILS+=("$e"); [[ -n "$p" ]] && PHONES+=("$p") ;;
    3) MODE="FULL"; read -p "Domain: " DOMAIN; read -p "Email (optional): " e; read -p "Phone (optional): " p; [[ -n "$e" ]] && EMAILS+=("$e"); [[ -n "$p" ]] && PHONES+=("$p") ;;
    4) DO_SETUP=true; $0 --setup; exit 0 ;;
    5) DO_INIT_FEEDS=true; $0 --init-feeds; exit 0 ;;
    *) echoinfo "Bye."; exit 0 ;;
  esac
fi

# Basic prechecks
echoinfo "Output directory: $OUTDIR"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/run.log"
exec > >(tee -a "$LOG") 2>&1

# Severity mapping helper (basic)
severity_from_nuclei(){
  local sev="$1"
  case "$sev" in
    critical|high) echo "High";;
    medium) echo "Medium";;
    low) echo "Low";;
    info|unknown|none|"") echo "Info";;
    *) echo "Info";;
  esac
}

# ---- MODULES ----

# Subdomain enumeration (subfinder, amass, assetfinder)
do_subenum(){
  local domain="$1"
  local out="$2/subdomains.txt"
  echoinfo "Subdomain enumeration for $domain -> $out"
  > "$out"
  if command -v subfinder >/dev/null 2>&1; then
    subfinder -d "$domain" -silent -o "$out.tmp" || true
    cat "$out.tmp" >> "$out" 2>/dev/null || true
  fi
  if command -v amass >/dev/null 2>&1; then
    amass enum -passive -d "$domain" -o "$out.amass" || true
    cat "$out.amass" >> "$out" 2>/dev/null || true
  fi
  if command -v assetfinder >/dev/null 2>&1; then
    assetfinder --subs-only "$domain" >> "$out" 2>/dev/null || true
  fi
  sort -u "$out" -o "$out" || true
  echoinfo "Found $(wc -l < "$out" || echo 0) subdomains"
}

# Probe HTTP with httpx -> produce CSV: url,status,title,ip,tech
do_http_probe(){
  local subs_file="$1"
  local out_csv="$2/httpx_live.csv"
  echoinfo "Probing HTTP (httpx) -> $out_csv"
  if ! command -v httpx >/dev/null 2>&1; then
    echoerr "httpx not installed; skipping http probe"
    return 0
  fi
  httpx -silent -l "$subs_file" -status-code -title -tech-detect -ip -ports 80,443,8080,8443,8000,3000 -json \
    | jq -r '[.url, (.status_code|tostring), (.title//""), (.ip//.a[0].ip//""), ((.tech|join(";"))//"")] | @csv' > "$out_csv" || true
  echoinfo "httpx results: $(wc -l < "$out_csv" || echo 0)"
}

# Parse httpx CSV into status-per-subdomain map
build_status_table(){
  local httpx_csv="$1"
  local status_table="$2/status_table.csv"
  > "$status_table"
  if [[ -s "$httpx_csv" ]]; then
    awk -F, '{gsub(/\\"/,"",$0); print $1","$2","$4}' "$httpx_csv" | sort -u > "$status_table"
  fi
  echoinfo "Status table -> $status_table"
}

# Ports: naabu -> nmap (detailed)
do_port_scan(){
  local live_hosts="$1"
  local ports_out="$2/naabu_ports.txt"
  local nmap_out="$2/nmap.txt"
  echoinfo "Running naabu -> $ports_out"
  if command -v naabu >/dev/null 2>&1; then
    naabu -silent -iL "$live_hosts" -o "$ports_out" || true
  else
    echowarn "naabu not installed; skipping fast port scan"
  fi

  # Prepare nmap input: hosts with ports
  if [[ -s "$ports_out" ]]; then
    echoinfo "Running nmap (service detection + OS) -> $nmap_out"
    # ports_out format may be host:port per line from naabu; we'll extract hosts
    awk -F: '{print $1}' "$ports_out" | sort -u > "$2/hosts_for_nmap.txt"
    if command -v nmap >/dev/null 2>&1; then
      nmap -sC -sV -O -iL "$2/hosts_for_nmap.txt" -oN "$nmap_out" || true
    fi
  else
    echowarn "No ports found by naabu; you can run nmap manually"
  fi
}

# Directory brute-force (ffuf)
do_dir_enum(){
  local host="$1"
  local out="$2/ffuf_${host//[:\/]/_}.json"
  if command -v ffuf >/dev/null 2>&1; then
    local wordlist="${DEFAULT_WORDLIST}"
    [[ -f "$WORDLIST_DIR/common.txt" ]] && wordlist="$WORDLIST_DIR/common.txt"
    echoinfo "Running ffuf on $host using $wordlist -> $out"
    ffuf -u "${host%/}/FUZZ" -w "$wordlist" -t 40 -mc all -of json -o "$out" || true
  else
    echowarn "ffuf not installed; skipping dir brute"
  fi
}

# Nuclei scan
do_nuclei(){
  local targets="$1"
  local out="$2/nuclei_findings.txt"
  if command -v nuclei >/dev/null 2>&1; then
    echoinfo "Running nuclei -> $out"
    nuclei -l "$targets" -c 50 -o "$out" || true
  else
    echowarn "nuclei not installed; skipping nuclei scan"
  fi
}

# Golismero (optional)
do_golismero(){
  local domain="$1"
  local out="$2/golismero_report.html"
  if command -v golismero >/dev/null 2>&1; then
    echoinfo "Running golismero -> $out"
    golismero scan "$domain" -o "$out" || true
  else
    echowarn "golismero not installed; skipping"
  fi
}

# Param discovery (paramspider + gau + katana)
do_param_discovery(){
  local domain="$1"
  local out_params="$2/params.txt"
  > "$out_params"
  echoinfo "Discovering parameters (paramspider, gau, katana) -> $out_params"
  if command -v paramspider >/dev/null 2>&1; then
    paramspider -d "$domain" -o "$2/paramspider.txt" || true
    cat "$2/paramspider.txt" >> "$out_params" 2>/dev/null || true
  fi
  if command -v gau >/dev/null 2>&1; then
    gau --subs "$domain" | grep -E '\?.+=' >> "$out_params" 2>/dev/null || true
  fi
  if command -v katana >/dev/null 2>&1; then
    katana -d 2 -u "https://$domain" -jc -o "$2/katana_urls.txt" || true
    grep -E '\?.+=' "$2/katana_urls.txt" >> "$out_params" 2>/dev/null || true
  fi
  sort -u "$out_params" -o "$out_params" || true
  echoinfo "Found $(wc -l < "$out_params" || echo 0) param-containing URLs"
}

# XSS scanning (dalfox + xsstrike)
do_xss_tests(){
  local params_file="$1"
  local out_dir="$2/xss"
  mkdir -p "$out_dir"
  echoinfo "Running XSS scanners on parameterized URLs -> $out_dir"
  if [[ ! -s "$params_file" ]]; then echowarn "No params file to test"; return 0; fi

  # dalfox pipe
  if command -v dalfox >/dev/null 2>&1; then
    echoinfo "dalfox scanning..."
    cat "$params_file" | dalfox pipe -o "$out_dir/dalfox.json" -w 50 || true
  else
    echowarn "dalfox not installed"
  fi

  # xsstrike (per URL)
  if command -v xsstrike >/dev/null 2>&1; then
    echoinfo "xsstrike scanning (may be slow)..."
    while read -r url; do
      [[ -z "$url" ]] && continue
      # safe filename
      fname="$out_dir/xs_$(echo "$url" | sha1sum | awk '{print $1}').txt"
      xsstrike -u "$url" --crawl 2 --thread 10 -o "$fname" || true
    done < "$params_file"
  else
    echowarn "xsstrike not installed"
  fi
}

# SQLi testing (sqlmap)
do_sqli_tests(){
  local params_file="$1"
  local out_dir="$2/sqlmap"
  mkdir -p "$out_dir"
  echoinfo "Running sqlmap on parameterized URLs -> $out_dir"
  if [[ ! -s "$params_file" ]]; then echowarn "No params file to test"; return 0; fi
  if ! command -v sqlmap >/dev/null 2>&1; then
    echowarn "sqlmap not installed"
    return 0
  fi
  # use -m to read many URLs; avoid destructive options
  cp "$params_file" "$out_dir/targets.txt"
  sqlmap -m "$out_dir/targets.txt" --batch --threads=5 --random-agent --crawl=1 --output-dir="$out_dir" || true
}

# CSRF basic checks (nuclei templates or simple heuristic)
do_csrf_check(){
  local live_list="$1"
  local out="$2/csrf.txt"
  echoinfo "Running CSRF checks (heuristic + nuclei if available) -> $out"
  > "$out"
  # heuristic: find forms without anti-csrf tokens (simple)
  if command -v httpx >/dev/null 2>&1 && command -v pup >/dev/null 2>&1; then
    # pup optional, skip if not installed
    while read -r url; do
      [[ -z "$url" ]] && continue
      # get forms
      curl -sL "$url" | pup 'form json{}' | grep -i -E 'csrf|token|authenticity_token' >/dev/null || echo "$url" >> "$out"
    done < "$live_list"
  else
    echowarn "pup/httpx not present for advanced csrf heuristics; fallback: use nuclei templates (if available)."
  fi

  if command -v nuclei >/dev/null 2>&1; then
    nuclei -l "$live_list" -tags csrf -o "$2/nuclei_csrf.txt" || true
    [[ -s "$2/nuclei_csrf.txt" ]] && cat "$2/nuclei_csrf.txt" >> "$out"
  fi
}

# OSINT: email (holehe/h8mail + local dump grep)
do_email_osint(){
  local email="$1"
  local outdir="$2"
  mkdir -p "$outdir"
  echoinfo "OSINT email: $email -> $outdir"
  if command -v holehe >/dev/null 2>&1; then
    holehe "$email" --only-used > "$outdir/holehe_${email}.txt" 2>/dev/null || true
  fi
  if command -v h8mail >/dev/null 2>&1; then
    if [[ -d "$BREACH_DIR" ]]; then
      h8mail -t "$email" --local-breach "$BREACH_DIR" -o "$outdir/h8mail_${email}.csv" 2>/dev/null || true
    else
      h8mail -t "$email" -o "$outdir/h8mail_${email}.csv" 2>/dev/null || true
    fi
  fi
  # local grep hits
  if [[ -d "$BREACH_DIR" ]]; then
    grep -RIn --binary-files=without-match -E "\\b${email}\\b" "$BREACH_DIR" | head -n 200 > "$outdir/grep_${email}.txt" || true
  fi
}

# OSINT: phone (PhoneInfoga + local grep)
do_phone_osint(){
  local phone="$1"
  local outdir="$2"
  mkdir -p "$outdir"
  echoinfo "OSINT phone: $phone -> $outdir"
  if command -v phoneinfoga >/dev/null 2>&1; then
    phoneinfoga scan -n "$phone" -o json > "$outdir/phoneinfoga_${phone}.json" 2>/dev/null || true
  fi
  if [[ -d "$BREACH_DIR" ]]; then
    digits=$(echo "$phone" | tr -cd '0-9')
    grep -RIn --binary-files=without-match -E "${phone}|${digits}" "$BREACH_DIR" | head -n 200 > "$outdir/grep_${phone}.txt" || true
  fi
}

# Build final report (Markdown + optional HTML/PDF)
build_report(){
  local base="$1"
  local target="$2"
  local out_md="$base/report.md"
  local out_html="$base/report.html"
  local out_pdf="$base/report.pdf"
  echoinfo "Building report -> $out_md"
  {
    echo "# XCS Bug Bounty Report"
    echo ""
    echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ") UTC"
    echo ""
    echo "## Target"
    echo "- Domain: $target"
    echo ""
    echo "## Summary"
    # counts
    subc=$(wc -l < "$base/subdomains.txt" 2>/dev/null || echo 0)
    livec=$(wc -l < "$base/httpx_live.csv" 2>/dev/null || echo 0)
    nuc=$(wc -l < "$base/nuclei_findings.txt" 2>/dev/null || echo 0)
    xssc=$(ls "$base/xss" 2>/dev/null | wc -l || echo 0)
    sqlc=$(ls "$base/sqlmap" 2>/dev/null | wc -l || echo 0)
    echo "- Subdomains found: $subc"
    echo "- Live hosts (httpx): $livec"
    echo "- Nuclei findings lines: $nuc"
    echo "- XSS results files: $xssc"
    echo "- SQLmap output dirs: $sqlc"
    echo ""
    echo "## Subdomains (sample)"
    head -n 50 "$base/subdomains.txt" 2>/dev/null || true
    echo ""
    echo "## Live Hosts & Status (httpx)"
    if [[ -s "$base/httpx_live.csv" ]]; then
      awk -F, '{gsub(/\\"/,"",$0); printf(\"- %s  (status: %s)\\n\", $1, $2)}' "$base/httpx_live.csv"
    else
      echo "_No httpx data_"
    fi
    echo ""
    echo "## Nuclei Findings (first 50 lines)"
    if [[ -s "$base/nuclei_findings.txt" ]]; then
      sed -n '1,50p' "$base/nuclei_findings.txt"
    else
      echo "_No nuclei output_"
    fi
    echo ""
    echo "## XSS Results (files)"
    ls -1 "$base/xss" 2>/dev/null || echo "_No XSS results_"
    echo ""
    echo "## SQLmap results (dirs)"
    ls -1 "$base/sqlmap" 2>/dev/null || echo "_No SQLmap results_"
    echo ""
    echo "## WHOIS (first 40 lines)"
    head -n 40 "$base/whois.txt" 2>/dev/null || echo "_No whois_"
    echo ""
    echo "## Notes"
    echo "- This report is automated. Validate all findings manually before disclosure."
    echo "- Use legal/ethical rules: test only allowed assets."
  } > "$out_md"

  # optional HTML/PDF if pandoc/wkhtmltopdf present
  if command -v pandoc >/dev/null 2>&1; then
    pandoc "$out_md" -o "$out_html" || true
    if command -v weasyprint >/dev/null 2>&1; then
    weasyprint "$OUT/report.html" "$OUT/report.pdf"
    echo "[+] PDF report generated using WeasyPrint"
else
    echo "[!] WeasyPrint not installed, skipping PDF export."
    echo "    Install with: pip3 install weasyprint"
fi

  fi
  echoinfo "Report files: $out_md ${out_html:-} ${out_pdf:-}"
}

# ---- EXECUTION FLOW ----

# If OSINT-only or emails/phones passed, run those first
if [[ "${MODE}" == "OSINT" || "${MODE}" == "FULL" ]] || [[ ${#EMAILS[@]} -gt 0 || ${#PHONES[@]} -gt 0 ]]; then
  echoinfo "Starting OSINT section"
  OSINT_DIR="$OUTDIR/osint"
  mkdir -p "$OSINT_DIR"
  for e in "${EMAILS[@]}"; do
    do_email_osint "$e" "$OSINT_DIR"
  done
  for p in "${PHONES[@]}"; do
    do_phone_osint "$p" "$OSINT_DIR"
  done
  echoinfo "OSINT complete"
fi

if [[ "${MODE}" == "BUGB" || "${MODE}" == "FULL" ]]; then
  if [[ -z "$DOMAIN" ]]; then echoerr "No domain provided for bugbounty"; exit 1; fi
  echoinfo "Starting Bug Bounty flow for $DOMAIN"
  mkdir -p "$OUTDIR"
  # modules
  do_subenum "$DOMAIN" "$OUTDIR"
  SUBS_FILE="$OUTDIR/subdomains.txt"

  # HTTP probe
  do_http_probe "$SUBS_FILE" "$OUTDIR"
  build_status_table "$OUTDIR/httpx_live.csv" "$OUTDIR"

  # Build live hosts list for tools (just URLs)
  awk -F, '{gsub(/\\"/,"",$0); print $1}' "$OUTDIR/httpx_live.csv" | sed 's/\\r//g' | sort -u > "$OUTDIR/live_hosts.txt" || true

  # Ports and OS
  do_port_scan "$OUTDIR/live_hosts.txt" "$OUTDIR"

  # Directory enumeration per live host (limited number to avoid long runs)
  if [[ -s "$OUTDIR/live_hosts.txt" ]]; then
    head -n 10 "$OUTDIR/live_hosts.txt" | while read -r host; do
      do_dir_enum "$host" "$OUTDIR"
    done
  fi

  # Vulnerability scans
  do_nuclei "$OUTDIR/live_hosts.txt" "$OUTDIR"
  do_golismero "$DOMAIN" "$OUTDIR"

  # Param discovery and tests
  do_param_discovery "$DOMAIN" "$OUTDIR"
  PARAMS_FILE="$OUTDIR/params.txt"

  # XSS tests
  do_xss_tests "$PARAMS_FILE" "$OUTDIR"

  # SQLi tests (non-destructive defaults)
  do_sqli_tests "$PARAMS_FILE" "$OUTDIR"

  # CSRF checks
  do_csrf_check "$OUTDIR/live_hosts.txt" "$OUTDIR"

  # WhoIs & DNS
  whois "$DOMAIN" > "$OUTDIR/whois.txt" 2>/dev/null || true
  dig +short "$DOMAIN" | sort -u > "$OUTDIR/ips.txt" 2>/dev/null || true

  # Build report
  build_report "$OUTDIR" "$DOMAIN"
  echoinfo "BugBounty flow complete -> $OUTDIR"
fi

# If MODE empty but user passed email/phone flags, we already handled OSINT above.
if [[ -z "$MODE" && ${#EMAILS[@]} -eq 0 && ${#PHONES[@]} -eq 0 ]]; then
  usage
fi

echoinfo "All done. See $OUTDIR for outputs and $LOG for full log."
exit 0

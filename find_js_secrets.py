#!/usr/bin/env python3
"""
find_js_secrets.py

Usage:
  python3 find_js_secrets.py --domain https://example.com --out evidence_example
  python3 find_js_secrets.py --urls-file js_urls.txt --out evidence_urls
  python3 find_js_secrets.py --domain https://example.com --use-wayback --out evidence_wayback

Outputs:
  - <outdir>/downloads/
  - <outdir>/headers/
  - <outdir>/report.json
  - <outdir>/summary.txt
  - <outdir>/hashes.txt

Requirements:
  - Python 3.8+
  - pip install requests beautifulsoup4
  - Optional: pip install jsbeautifier
  - Optional: waybackurls in PATH if using --use-wayback

Only run against targets you are authorized to test.
"""
import argparse
import os
import re
import sys
import json
import hashlib
import subprocess
from urllib.parse import urljoin, urlparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    print("Missing dependency. Run: pip install requests beautifulsoup4")
    sys.exit(1)

# Optional beautifier
try:
    import jsbeautifier
    HAVE_JSBEAUT = True
except Exception:
    HAVE_JSBEAUT = False

# common vendor noise to skip by default
IGNORE_FN_PATTERNS = [
    r'jquery', r'bootstrap', r'google-analytics', r'ga-', r'googleapis', r'fontawesome', r'cdnjs',
    r'sentry', r'sentry.io', r'segment', r'adservice', r'track', r'ads', r'gtag',
]

USER_AGENT = "find_js_secrets/1.0 (+pentest)"

def safe_filename_from_url(u):
    return re.sub(r'[:/\\?&=]', '_', u)

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()

def download_url(url, timeout=20):
    try:
        headers = {"User-Agent": USER_AGENT}
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None

def extract_script_urls_from_html(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            full = urljoin(base_url, src)
            urls.add(full)
        else:
            text = s.string or ""
            for m in re.findall(r'https?://[^\'" >)]+\.js', text, flags=re.I):
                urls.add(m)
    for m in re.findall(r'https?://[^\'" >)]+\.js', html, flags=re.I):
        urls.add(m)
    return urls

def looks_like_vendor(fn):
    for pat in IGNORE_FN_PATTERNS:
        if re.search(pat, fn, re.I):
            return True
    return False

def crawl_domain_for_scripts(start_url, max_pages=200, max_depth=2):
    parsed = urlparse(start_url)
    base_host = parsed.netloc
    q = deque([(start_url, 0)])
    visited = set()
    found = set()
    headers = {"User-Agent": USER_AGENT}
    while q and len(visited) < max_pages:
        url, depth = q.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            r = requests.get(url, headers=headers, timeout=10)
        except Exception:
            continue
        if not r.ok:
            continue
        html = r.text
        scripts = extract_script_urls_from_html(url, html)
        for s in scripts:
            found.add(s)
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            nxt = urljoin(url, a['href'])
            p = urlparse(nxt)
            if p.netloc == base_host and nxt not in visited:
                q.append((nxt, depth + 1))
    return sorted(found)

def get_wayback_urls_for_host(host):
    try:
        proc = subprocess.run(["waybackurls"], input=host.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
        out = proc.stdout.decode().splitlines()
        return [u for u in out if u.lower().endswith(".js")]
    except Exception:
        return []

# ---------------- Patterns with metadata (compiled below) ----------------
# All regexes are raw strings. Character classes place '-' at the end to avoid Python PatternError.
PATTERN_DEFS = [
  # Cloud provider & IAM
  { "id": "aws_access_key_id", "regex": r'AKIA[0-9A-Z]{16}', "flags": "g", "severity": 10,
    "description": "AWS Access Key ID (AKIA...)", "tags": ["aws","iam"] },

  { "id": "aws_secret_access_key_like", "regex": r'(?i)aws[_-]?(secret|access)[^A-Za-z0-9"\'\']{0,6}["\']?([A-Za-z0-9+/\.=]{16,128})["\']?', "flags": "gi", "severity": 10,
    "description": "Possible AWS secret key or mention of aws_secret keyword", "tags": ["aws","secret"],
    "false_positive_note": "May match long base64-like strings near 'aws_secret' text" },

  { "id": "aws_session_token", "regex": r'FQoGZXIvYXdzEP[A-Za-z0-9+/]{100,}', "flags": "g", "severity": 9,
    "description": "AWS STS session token (heuristic)", "tags": ["aws","sts"] },

  { "id": "aws_arn", "regex": r'arn:aws:[a-z0-9-]+::\d{12}:[A-Za-z0-9_./-]+', "flags": "g", "severity": 6,
    "description": "AWS ARN (resource/role/etc.)", "tags": ["aws","arn"] },

  { "id": "gcp_api_key", "regex": r'AIza[0-9A-Za-z-_]{35}', "flags": "g", "severity": 9,
    "description": "Google API key (AIza...)", "tags": ["gcp","api"] },

  { "id": "gcp_refresh_token", "regex": r'1\/\/[0-9A-Za-z_-]{20,}', "flags": "g", "severity": 9,
    "description": "GCP OAuth refresh token (1//...)", "tags": ["gcp","oauth"] },

  { "id": "gcp_service_account", "regex": r'"type"\s*:\s*"service_account"', "flags": "i", "severity": 10,
    "description": "GCP service account JSON present", "tags": ["gcp","service_account"] },

  { "id": "azure_conn_string", "regex": r'DefaultEndpointsProtocol=.*;AccountName=[^;]+;AccountKey=[^;]+;', "flags": "gi", "severity": 10,
    "description": "Azure storage connection string (AccountKey present)", "tags": ["azure","storage"] },

  { "id": "azure_sas_sig", "regex": r'([?&])sig=[A-Za-z0-9%_-]{10,}', "flags": "g", "severity": 8,
    "description": "Azure SAS token signature in URL", "tags": ["azure","sas"] },

  { "id": "oci_ocid", "regex": r'ocid1\.[a-z0-9._-]{10,}', "flags": "g", "severity": 6,
    "description": "Oracle Cloud Identifier (ocid1..)", "tags": ["oci"] },

  # Identity & OAuth / JWT
  { "id": "jwt_compact", "regex": r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', "flags": "g", "severity": 9,
    "description": "JWT (compact serialized) pattern", "tags": ["jwt","oauth"] },

  { "id": "oauth_bearer_header", "regex": r'(?i)Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~\+\/=]+', "flags": "gi", "severity": 8,
    "description": "Authorization Bearer token header present in code", "tags": ["auth"] },

  { "id": "google_oauth", "regex": r'ya29\.[0-9A-Za-z-_]{20,}', "flags": "g", "severity": 9,
    "description": "Google OAuth access token (ya29...)", "tags": ["gcp","oauth"] },

  # Source control & CI tokens
  { "id": "github_pat", "regex": r'ghp_[A-Za-z0-9_]{36}', "flags": "g", "severity": 10,
    "description": "GitHub personal access token (ghp_)", "tags": ["github","pat"] },

  { "id": "github_app_token", "regex": r'ghs_[A-Za-z0-9_]{36}|gho_[A-Za-z0-9_]{36}', "flags": "g", "severity": 9,
    "description": "GitHub app/other tokens (ghs_, gho_)", "tags": ["github"] },

  { "id": "gitlab_pat", "regex": r'glpat-[A-Za-z0-9_-]{20,255}', "flags": "g", "severity": 10,
    "description": "GitLab personal access token (glpat-)", "tags": ["gitlab"] },

  { "id": "bitbucket_app_password", "regex": r'[A-Za-z0-9]{20}:[A-Za-z0-9]{20}', "flags": "g", "severity": 8,
    "description": "Bitbucket app password-like (heuristic: user:apppwd)", "tags": ["bitbucket","ci"] },

  { "id": "github_actions_token", "regex": r'github_token\b|GITHUB_TOKEN\b', "flags": "gi", "severity": 7,
    "description": "Reference to GitHub Actions token or env var", "tags": ["ci","github"] },

  { "id": "gitlab_ci", "regex": r'CI_JOB_TOKEN|GITLAB_TOKEN|GITLAB_CI', "flags": "gi", "severity": 7,
    "description": "CI tokens/variables for GitLab/CI", "tags": ["ci","gitlab"] },

  # Payment & Messaging providers
  { "id": "stripe_secret", "regex": r'sk_live_[0-9a-zA-Z]{24}', "flags": "g", "severity": 10,
    "description": "Stripe production secret key", "tags": ["stripe","payments"] },

  { "id": "stripe_publishable", "regex": r'pk_live_[0-9a-zA-Z]{24}', "flags": "g", "severity": 6,
    "description": "Stripe publishable key (less critical)", "tags": ["stripe","payments"] },

  { "id": "sendgrid", "regex": r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', "flags": "g", "severity": 10,
    "description": "SendGrid API key", "tags": ["email","sendgrid"] },

  { "id": "mailgun", "regex": r'key-[0-9a-zA-Z]{32}', "flags": "g", "severity": 9,
    "description": "Mailgun API key", "tags": ["email","mailgun"] },

  { "id": "postmark", "regex": r'pm_[0-9a-fA-F]{32}', "flags": "g", "severity": 9,
    "description": "Postmark server token", "tags": ["email"] },

  { "id": "twilio", "regex": r'SK[0-9a-fA-F]{32}', "flags": "g", "severity": 9,
    "description": "Twilio API key/secret (SID-like)", "tags": ["twilio","sms"] },

  { "id": "slack_token", "regex": r'xox[baprs]-[A-Za-z0-9._-]{10,48}', "flags": "g", "severity": 9,
    "description": "Slack token (bot or user token)", "tags": ["slack","messaging"] },

  { "id": "discord_token", "regex": r'mfa\.[A-Za-z0-9-_]{84}|[A-Za-z0-9_]{24}\.[A-Za-z0-9_]{6}\.[A-Za-z0-9_\-]{27}', "flags": "g", "severity": 9,
    "description": "Discord token formats", "tags": ["discord","messaging"] },

  # DBs, DSNs, credentials
  { "id": "db_connection", "regex": r'(postgres|mysql|mongodb|redis|mssql)://[^\s"\']+', "flags": "gi", "severity": 9,
    "description": "Database connection string (DSN)", "tags": ["db","credentials"] },

  { "id": "basic_auth_url", "regex": r'https?://[^/\s:@]+:[^@\s/]+@[^"\s]+', "flags": "g", "severity": 9,
    "description": "URL containing HTTP basic auth credentials", "tags": ["credentials","url"] },

  # Keys, certs, SSH, PGP
  { "id": "pem_private", "regex": r'-----BEGIN\s+(?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', "flags": "gi", "severity": 10,
    "description": "PEM private key block (RSA/DSA/EC/OPENSSH)", "tags": ["private_key"] },

  { "id": "pem_certificate", "regex": r'-----BEGIN CERTIFICATE-----', "flags": "gi", "severity": 7,
    "description": "PEM certificate", "tags": ["certificate"] },

  { "id": "ssh_rsa_pub", "regex": r'ssh-(rsa|ed25519|dsa)\s+[A-Za-z0-9+/=]{100,}', "flags": "g", "severity": 6,
    "description": "SSH public key-like (long base64 string)", "tags": ["ssh","pubkey"] },

  { "id": "pgp_private", "regex": r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "flags": "gi", "severity": 10,
    "description": "PGP private key block", "tags": ["pgp","private_key"] },

  # Generic long secrets / heuristics
  { "id": "long_base64", "regex": r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']', "flags": "g", "severity": 6,
    "description": "Long base64-like blob in quotes (possible secret)", "tags": ["base64"] },

  { "id": "long_hex", "regex": r'["\']([0-9a-fA-F]{32,})["\']', "flags": "g", "severity": 6,
    "description": "Long hex-like blob (possible secret)", "tags": ["hex"] },

  { "id": "uuid_like", "regex": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "flags": "g", "severity": 4,
    "description": "UUID-like token (may be harmless)", "tags": ["uuid"] },

  # Platform service & monitoring DSNs
  { "id": "sentry_dsn", "regex": r'https?://[0-9a-f]+@[A-Za-z0-9.\-]+/\d+', "flags": "gi", "severity": 7,
    "description": "Sentry DSN (project key in URL)", "tags": ["sentry","monitoring"] },

  # -> corrected Datadog pattern (you asked datlog change)
  { "id": "datadog_api", "regex": r'api_key\s*[:=]\s*["\']?[0-9a-f]{32}["\']?', "flags": "gi", "severity": 7,
    "description": "Datadog API key-like", "tags": ["datadog","monitoring"] },

  { "id": "newrelic", "regex": r'NRUM-?[0-9A-Za-z]{16,64}', "flags": "gi", "severity": 6,
    "description": "NewRelic key/agent id", "tags": ["newrelic"] },

  # Package manager & token formats
  { "id": "npm_token", "regex": r'npm_[A-Za-z0-9_-]{36,}', "flags": "g", "severity": 8,
    "description": "npm token (npm_)", "tags": ["npm","package"] },

  { "id": "npmrc_basic", "regex": r'_auth\s*=|npm_token|npm_auth', "flags": "gi", "severity": 7,
    "description": "npmrc authentication lines", "tags": ["npm","auth"] },

  # CI / Terraform / Vault / Cloud tooling
  { "id": "terraform_cloud_token", "regex": r'tfe-?[A-Za-z0-9_-]{20,64}|tfcloud_[A-Za-z0-9_-]{20,64}', "flags": "g", "severity": 9,
    "description": "Terraform Cloud token (heuristic)", "tags": ["terraform"] },

  { "id": "vault_token", "regex": r'vault\.[A-Za-z0-9_-]{20,128}|s\.vault\.[A-Za-z0-9_-]{20,128}', "flags": "g", "severity": 10,
    "description": "Vault token like patterns (heuristic)", "tags": ["vault","secrets"] },

  # Common filenames & references (possible leaks)
  { "id": "env_file_ref", "regex": r'\.(env|env\.example|bash_profile|envrc|credentials)$', "flags": "gi", "severity": 8,
    "description": "References to env/credentials files", "tags": ["file","leak"] },

  { "id": "git_file_ref", "regex": r'/\.git/(HEAD|config|objects|logs|index)', "flags": "gi", "severity": 10,
    "description": ".git repository files referenced (possible repo leakage)", "tags": ["git","leak"] },

  # Payment / crypto exchanges
  { "id": "coinbase", "regex": r'coinbase\.[A-Za-z0-9-]+|CB-[A-Za-z0-9]{16,}', "flags": "gi", "severity": 7,
    "description": "Coinbase-like identifiers or keys (heuristic)", "tags": ["crypto","payment"] },

  { "id": "binance", "regex": r'binance[._-]api|apiKey=[A-Za-z0-9]{32,}', "flags": "gi", "severity": 7,
    "description": "Binance/api-like strings (heuristic)", "tags": ["crypto"] },

  # Misc / generic heuristics
  # -> password_assignment updated with two extra properties as requested
  { "id": "password_assignment",
    "regex": r'(?i)password\s*[:=]\s*["\']?[^"\s]{4,200}["\']?',
    "flags": "gi", "severity": 9,
    "description": "Password assignment in code",
    "tags": ["credentials"],
    "false_positive_note": "May capture non-secret strings or test passwords; verify before acting",
    "example_matches": ["password = \"secret123\"", "password:'P@ssw0rd'"] },

  { "id": "possible_url_with_creds", "regex": r'https?://[^/\s@]+:[^@\s/]+@[^"\s]+', "flags": "g", "severity": 9,
    "description": "URL with embedded credentials", "tags": ["credentials","url"] },

  { "id": "long_string_heuristic", "regex": r'["\']([A-Za-z0-9_.-]{50,})["\']', "flags": "g", "severity": 5,
    "description": "Very long alphanumeric string (heuristic, may be secret)", "tags": ["heuristic"] },

  # Original/script heuristics
  { "id": "document_cookie", "regex": r'document\.cookie', "flags": "g", "severity": 6,
    "description": "document.cookie usage", "tags": ["cookie"] },

  { "id": "localstorage", "regex": r'localStorage|sessionStorage', "flags": "g", "severity": 5,
    "description": "localStorage/sessionStorage usage", "tags": ["storage"] },

  { "id": "pem_block_generic", "regex": r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "flags": "gi", "severity": 10,
    "description": "Private key PEM block (generic)", "tags": ["private_key"] },
]

# Compile patterns into PATTERNS: id -> compiled + metadata
PATTERNS = {}
for p in PATTERN_DEFS:
    flags = 0
    fstr = p.get("flags", "")
    if 'i' in fstr.lower():
        flags |= re.IGNORECASE
    try:
        compiled = re.compile(p["regex"], flags)
    except re.error:
        # fallback: try compile without flags; if still fails, raise a helpful message
        try:
            compiled = re.compile(p["regex"], 0)
        except re.error as e:
            print(f"[!] Fatal: pattern {p.get('id')} failed to compile. regex={p.get('regex')}")
            print("    re.error:", e)
            sys.exit(2)
    PATTERNS[p["id"]] = {
        "re": compiled,
        "severity": p.get("severity", 5),
        "description": p.get("description", ""),
        "tags": p.get("tags", []),
        "false_positive_note": p.get("false_positive_note"),
        "example_matches": p.get("example_matches"),
        "raw_regex": p["regex"]
    }

def scan_file_for_patterns(content):
    findings = []
    for pid, meta in PATTERNS.items():
        pat = meta["re"]
        for m in pat.finditer(content):
            start = max(0, m.start() - 80)
            end = min(len(content), m.end() + 80)
            snippet = content[start:end].replace('\n',' ')
            match_text = m.group(0) if isinstance(m.group(0), str) else str(m.group(0))
            findings.append({
                "pattern": pid,
                "match": match_text,
                "context": snippet[:300],
                "severity": meta.get("severity"),
                "description": meta.get("description"),
                "tags": meta.get("tags"),
                "false_positive_note": meta.get("false_positive_note"),
                "example_matches": meta.get("example_matches"),
            })
    return findings

def main():
    ap = argparse.ArgumentParser(description="Find secrets/sensitive strings in JS assets for a target (ONLY run with permission).")
    ap.add_argument("--domain", help="A domain/page to crawl for JS (e.g. https://example.com)")
    ap.add_argument("--urls-file", help="File with JS URLs (one per line). If given, crawl is skipped.")
    ap.add_argument("--use-wayback", action="store_true", help="Also use waybackurls (if available) to collect historical JS urls for the domain.")
    ap.add_argument("--out", default="evidence", help="Output folder")
    ap.add_argument("--max-workers", type=int, default=8, help="Concurrent downloads")
    ap.add_argument("--max-depth", type=int, default=2, help="Max crawl depth if using --domain")
    ap.add_argument("--include-vendor", action="store_true", help="Include likely vendor files (jquery/bootstrap) in scan (noisy)")
    args = ap.parse_args()

    outdir = args.out
    downloads_dir = os.path.join(outdir, "downloads")
    headers_dir = os.path.join(outdir, "headers")
    os.makedirs(downloads_dir, exist_ok=True)
    os.makedirs(headers_dir, exist_ok=True)

    js_urls = set()
    if args.urls_file:
        with open(args.urls_file, "r", encoding="utf-8") as f:
            for l in f:
                u = l.strip()
                if u:
                    js_urls.add(u)
    elif args.domain:
        print("[*] Crawling domain for script URLs:", args.domain)
        crawled = crawl_domain_for_scripts(args.domain, max_depth=args.max_depth)
        print(f"  Found {len(crawled)} script URLs from crawl")
        for u in crawled:
            js_urls.add(u)
        if args.use_wayback:
            print("[*] Using waybackurls to supplement JS list (if waybackurls installed)")
            host = args.domain
            way = get_wayback_urls_for_host(host)
            print(f"  Wayback provided {len(way)} URLs")
            for u in way:
                js_urls.add(u)
    else:
        ap.print_help()
        sys.exit(1)

    if not args.include_vendor:
        js_urls = {u for u in js_urls if not looks_like_vendor(u)}

    js_urls = sorted(js_urls)
    print(f"[*] Total JS urls to process: {len(js_urls)}")

    findings = []
    hashes = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        future_map = {}
        for url in js_urls:
            future = ex.submit(download_url, url)
            future_map[future] = url

        for fut in as_completed(future_map):
            url = future_map[fut]
            r = fut.result()
            safe = safe_filename_from_url(url)
            header_path = os.path.join(headers_dir, safe + ".hdr")
            out_path = os.path.join(downloads_dir, safe)
            if r is None:
                print(f"[!] Failed to download {url}")
                continue
            try:
                with open(header_path, "w", encoding="utf-8") as hf:
                    hf.write(str(r.status_code) + " " + (r.reason or "") + "\n")
                    for k, v in r.headers.items():
                        hf.write(f"{k}: {v}\n")
            except Exception:
                pass
            try:
                with open(out_path, "wb") as of:
                    of.write(r.content)
            except Exception:
                print(f"[!] Failed to write file for {url}")
                continue
            sha = sha256_bytes(r.content)
            hashes.append({"url": url, "sha256": sha, "size": len(r.content), "status": r.status_code})
            text = ""
            try:
                text = r.content.decode('utf-8', errors='ignore')
            except Exception:
                text = ""
            beautified = None
            if HAVE_JSBEAUT:
                try:
                    beautified = jsbeautifier.beautify(text)
                except Exception:
                    beautified = None
            to_scan = beautified if beautified else text

            file_findings = scan_file_for_patterns(to_scan)
            for fnd in file_findings:
                fnd.update({"url": url, "file": out_path})
                findings.append(fnd)
            print(f"[+] Processed {url}  ({len(file_findings)} findings)")

    report = {
        "metadata": {
            "tool": "find_js_secrets.py",
            "note": "Run only with authorization",
            "patterns_count": len(PATTERNS),
        },
        "hashes": hashes,
        "findings": findings
    }
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as rf:
        json.dump(report, rf, indent=2)

    with open(os.path.join(outdir, "hashes.txt"), "w", encoding="utf-8") as hf:
        for h in hashes:
            hf.write(f"{h['sha256']}  {h['url']}  status={h['status']} size={h['size']}\n")

    with open(os.path.join(outdir, "summary.txt"), "w", encoding="utf-8") as sf:
        sf.write("find_js_secrets summary\n")
        sf.write("======================\n\n")
        sf.write(f"Total JS urls processed: {len(hashes)}\n")
        sf.write(f"Total findings: {len(findings)}\n\n")
        if findings:
            sf.write("Top findings (first 50):\n")
            for i, f in enumerate(findings[:50], 1):
                sf.write(f"{i}. [{f['pattern']}] {f['url']}\n")
                sf.write(f"    severity: {f.get('severity')}\n")
                sf.write(f"    description: {f.get('description')}\n")
                if f.get("false_positive_note"):
                    sf.write(f"    false_positive_note: {f.get('false_positive_note')}\n")
                if f.get("example_matches"):
                    sf.write(f"    example_matches: {f.get('example_matches')}\n")
                sf.write(f"    match snippet: {f['context'][:200].strip()}\n\n")
        else:
            sf.write("No suspicious patterns detected by heuristics.\n")
    print(f"[*] Done. Evidence saved in: {outdir}")
    print("Summary:", os.path.join(outdir, "summary.txt"))
    print("Report JSON:", os.path.join(outdir, "report.json"))
    print("Downloaded files in:", downloads_dir)

if __name__ == "__main__":
    main()

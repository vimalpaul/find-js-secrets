# find-js-secrets

**find-js-secrets** is an open-source Python utility to discover secrets, API keys, tokens and other sensitive strings in JavaScript assets. It is intended for **authorized security testing and research** only.

---

## Key features

- Crawl a domain and discover `.js` assets.
- Optionally use the Wayback Machine (via `waybackurls`) to include archived `.js` files.
- Concurrent download and scanning of JS files.
- Heuristics and vendor-specific regex patterns (AWS, GCP, Azure, GitHub, GitLab, Stripe, SendGrid, Twilio, Slack, etc.).
- Optional JS beautification (improves detection for minified code) via `jsbeautifier`.
- Outputs:
  - `report.json` — structured, machine-readable findings
  - `summary.txt` — human-friendly summary
  - `hashes.txt` — SHA256 hashes for downloads
  - `downloads/` and `headers/` — saved artifacts and HTTP headers

---

##  Important legal & safety notice

**Only run this tool against targets you are explicitly authorized to test.**  
Unauthorized scanning or harvesting of data from third-party infrastructure can be illegal and unethical. If you discover secrets or credentials, follow responsible disclosure procedures for the affected organization.

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Lamiv1311/find-js-secrets.git
cd find-js-secrets
```

2. Install Python dependencies:
```bash
python3 -m pip install -r requirements.txt
```

3. (Optional, but recommended) Install `waybackurls` if you plan to use the `--use-wayback` option:
```bash
# if you have Go installed
go install github.com/tomnomnom/waybackurls@latest
# ensure $GOPATH/bin or $HOME/go/bin is in your PATH
```

---

## Usage examples

### Crawl a domain (discover scripts and scan)
```bash
python3 find_js_secrets.py --domain https://example.com --out evidence_example --max-depth 2
```

### Scan a pre-built list of JS URLs
```bash
python3 find_js_secrets.py --urls-file js_urls.txt --out evidence_from_list
```

### Use Wayback to include archived JS
```bash
python3 find_js_secrets.py --domain https://cdn.example.com --use-wayback --out evidence_wayback
```

### Useful flags
- `--max-workers N` : number of parallel downloads (default 8)  
- `--max-depth N` : crawl depth (default 2)  
- `--include-vendor` : include vendor JS (jquery/bootstrap — noisy)  
- `--urls-file FILE` : use file with JS URLs (one per line)

---

## Output directory layout
After a run, the specified `--out` directory contains:
```
<outdir>/
  downloads/       # downloaded .js files
  headers/         # saved HTTP response headers
  report.json      # structured findings
  summary.txt      # human readable summary
  hashes.txt       # sha256 sums
```

---

## False positives & responsible triage
The scanner uses heuristics and pattern matching. Some matches may be false positives (long base64 strings, vendor keys, placeholders). Treat findings as **suspicious** and validate before taking action.

---

## Contributing

Contributions welcome. Suggested workflow:
1. Fork this repository.
2. Create a feature branch: `git checkout -b feat/my-change`
3. Commit changes and push to your fork.
4. Open a pull request describing the change.

Please avoid adding any real credentials or private data to commits.

---

## License

This project is licensed under the **MIT License** — see `LICENSE` for details.

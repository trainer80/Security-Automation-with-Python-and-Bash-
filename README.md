# Python Security Recon Automation

A Python command-line tool that automates the first phase of a security assessment (reconnaissance) by chaining four popular open-source tools and turning their output into a clean report. It replaces running each tool by hand and copying results around, which saves time and reduces human error.

```
subfinder  ->  httpx  ->  nmap  ->  nuclei  ->  JSON + Markdown report
(subdomains)  (live hosts) (open ports) (known vulnerabilities)
```

## Legal and ethical use

Only run this against systems **you own or have written permission to test**. The tool enforces this:

- you must pass `--i-have-permission`
- the target must be listed in a scope file you control (`scope/scope.txt`)
- inputs are validated, and commands are run without a shell (no command injection)

Good places to practice legally: your own local lab such as `localhost` with OWASP Juice Shop or DVWA running in Docker, or a domain you own.

## Features

- Scope-file allow-list (subdomains of a listed domain are allowed, look-alike domains are rejected)
- Input validation and shell-free command execution
- Timeouts so a hung tool cannot block the pipeline
- JSON output (for automation) and Markdown output (for humans)
- `--dry-run` mode
- Unit tests that mock the external tools

## Requirements

- Python 3.9+
- The tools below installed and on your PATH:
  - [subfinder](https://github.com/projectdiscovery/subfinder)
  - [httpx](https://github.com/projectdiscovery/httpx) (ProjectDiscovery's httpx, not the Python library)
  - [nmap](https://nmap.org)
  - [nuclei](https://github.com/projectdiscovery/nuclei)

The Python script itself uses only the standard library. Install Kali Linux or follow each project's install guide.

## Usage

```bash
# 1. Add your authorized target to the scope file
echo "localhost" >> scope/scope.txt

# 2. Check everything is wired up
python recon_pipeline.py -t localhost --i-have-permission --dry-run

# 3. Run it
python recon_pipeline.py -t localhost --i-have-permission

# Options
#   -t / --target          domain, IPv4 or localhost
#   -s / --scope-file      default scope/scope.txt
#   -o / --output          default reports/
```

Reports are saved to `reports/` as `recon_<target>_<timestamp>.json` and `.md`.

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

## How it works

1. `find_subdomains()` runs subfinder (skipped for IPs and localhost).
2. `find_live_hosts()` pipes the hosts into httpx to keep only live web servers.
3. `scan_ports()` runs `nmap -F -sV -T3` (top 100 ports, service detection) on each live host.
4. `scan_vulnerabilities()` runs nuclei with medium/high/critical templates.
5. `build_markdown()` and the JSON writer produce the final reports.

## Limitations

- Automated findings can be false positives and **must be validated manually**.
- Scans are noisy; use only within an agreed testing window.
- No rate-limit tuning yet.

## Ideas to extend

- Run it automatically in GitHub Actions against a staging site you own
- Add an HTML report and severity summary
- Send a Slack or email notification when new high-severity findings appear
- Dockerize the tool with all four binaries included

## What I learned

(Write 3-4 lines in your own words.)

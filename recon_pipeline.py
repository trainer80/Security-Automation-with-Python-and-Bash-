#!/usr/bin/env python3
"""Authorized-scope reconnaissance pipeline.

Chains four open-source tools and writes a JSON + Markdown report:

    subfinder (subdomains) -> httpx (live web hosts) -> nmap (open ports)
                                                     -> nuclei (known issues)

SAFETY: this tool only runs against targets that appear in a scope file you
control, and you must pass --i-have-permission. Only scan systems that you own
or have written permission to test.
"""
import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REQUIRED_TOOLS = ["subfinder", "httpx", "nmap", "nuclei"]

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE
)
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_valid_target(target):
    """Accept a plain domain, IPv4 address or localhost (no URLs, no shell characters)."""
    t = target.strip()
    return bool(HOSTNAME_RE.match(t) or IPV4_RE.match(t) or t.lower() == "localhost")


def is_ip_or_localhost(target):
    return bool(IPV4_RE.match(target) or target.lower() == "localhost")


def load_scope(path):
    """Read allowed targets from a file (one per line, '#' starts a comment)."""
    scope = set()
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            scope.add(line)
    return scope


def in_scope(target, scope):
    """A target is in scope if it equals a scope entry or is a subdomain of one."""
    t = target.strip().lower()
    return any(t == s or t.endswith("." + s) for s in scope)


def host_from_url(url):
    return re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]


def check_tools():
    return [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]


def run(cmd, timeout=300, stdin_text=None):
    """Run a command WITHOUT a shell and return its non-empty output lines."""
    try:
        result = subprocess.run(
            cmd, input=stdin_text, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        print(f"[!] Timed out: {' '.join(cmd)}", file=sys.stderr)
        return []
    except FileNotFoundError:
        print(f"[!] Tool not found: {cmd[0]}", file=sys.stderr)
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def find_subdomains(target):
    if is_ip_or_localhost(target):
        return [target]
    found = run(["subfinder", "-d", target, "-silent"])
    return sorted(set(found) | {target})


def find_live_hosts(hosts):
    return sorted(set(run(["httpx", "-silent"], stdin_text="\n".join(hosts))))


def scan_ports(host):
    lines = run(["nmap", "-F", "-sV", "-T3", host], timeout=600)
    return [ln for ln in lines if "/tcp" in ln and "open" in ln]


def scan_vulnerabilities(url):
    return run(["nuclei", "-u", url, "-severity", "medium,high,critical", "-silent"], timeout=900)


def build_markdown(results):
    lines = [
        f"# Recon Report: {results['target']}",
        "",
        f"- Generated: {results['generated_at']}",
        f"- Subdomains found: {len(results['subdomains'])}",
        f"- Live web hosts: {len(results['live_hosts'])}",
        "",
        "## Live hosts and open ports",
    ]
    for host, ports in results["open_ports"].items():
        lines.append(f"### {host}")
        lines.extend([f"- `{p}`" for p in ports] or ["- no open ports found in top 100"])
    lines += ["", "## Nuclei findings (medium / high / critical)"]
    if results["nuclei_findings"]:
        for url, findings in results["nuclei_findings"].items():
            lines.append(f"### {url}")
            lines.extend(f"- {f}" for f in findings)
    else:
        lines.append("- none reported")
    lines += ["", "> Findings must be manually validated before being reported."]
    return "\n".join(lines) + "\n"


def pipeline(target, outdir, dry_run=False):
    if dry_run:
        print("[dry-run] would run: subfinder -> httpx -> nmap -F -sV -> nuclei")
        return None
    results = {
        "target": target,
        "generated_at": dt.datetime.now().isoformat(timespec="seconds"),
        "subdomains": [],
        "live_hosts": [],
        "open_ports": {},
        "nuclei_findings": {},
    }
    print(f"[+] Finding subdomains for {target}")
    results["subdomains"] = find_subdomains(target)
    print(f"[+] Probing {len(results['subdomains'])} hosts for live web servers")
    results["live_hosts"] = find_live_hosts(results["subdomains"])
    for url in results["live_hosts"]:
        host = host_from_url(url)
        print(f"[+] Scanning ports on {host}")
        results["open_ports"][host] = scan_ports(host)
        print(f"[+] Running nuclei on {url}")
        findings = scan_vulnerabilities(url)
        if findings:
            results["nuclei_findings"][url] = findings

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    (outdir / f"recon_{target}_{stamp}.json").write_text(json.dumps(results, indent=2))
    (outdir / f"recon_{target}_{stamp}.md").write_text(build_markdown(results))
    print(f"[+] Reports saved in {outdir}/")
    return results


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Authorized-scope recon pipeline")
    p.add_argument("-t", "--target", required=True, help="domain, IPv4 or localhost")
    p.add_argument("-s", "--scope-file", default="scope/scope.txt", help="allowed targets file")
    p.add_argument("-o", "--output", default="reports", help="output directory")
    p.add_argument("--i-have-permission", action="store_true",
                   help="confirm you own the target or have written permission to test it")
    p.add_argument("--dry-run", action="store_true", help="validate inputs, run nothing")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not args.i_have_permission:
        print("Refusing to run: pass --i-have-permission only for systems you are authorized to test.")
        return 2
    if not is_valid_target(args.target):
        print("Invalid target. Use a plain domain, IPv4 address or localhost (no URLs).")
        return 2
    if not Path(args.scope_file).exists():
        print(f"Scope file not found: {args.scope_file}")
        return 2
    if not in_scope(args.target, load_scope(args.scope_file)):
        print(f"{args.target} is NOT in {args.scope_file}. Add it only if you are authorized.")
        return 2
    missing = check_tools()
    if missing and not args.dry_run:
        print("Missing tools: " + ", ".join(missing) + " (see README for installation)")
        return 2
    pipeline(args.target, args.output, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())

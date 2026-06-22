#!/usr/bin/env python3
"""
VLESS Subscription Audit Script
Fetches a subscription URL, parses every proxy, spins up xray per proxy,
runs full audit, prints detailed per-proxy report.

Requirements:
  pip install requests
  xray-core in PATH  (or: export XRAY_BIN=/path/to/xray)

Usage:
  python3 audit.py --sub https://example.com/sub/token
  python3 audit.py --sub https://... --abuseipdb-key YOUR_KEY
  python3 audit.py --sub https://... --json-out report.json
"""

import argparse
import base64
import json
import os
import random
import socket
import string
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, unquote

import requests


XRAY_BIN = os.environ.get("XRAY_BIN", "xray")

BOLD   = "\033[1m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RESET  = "\033[0m"


# ── VLESS URI parsing ─────────────────────────────────────────────────────────

def parse_vless_uri(uri: str) -> dict:
    uri = uri.strip()
    parsed = urlparse(uri)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    return {
        "uri":                uri,
        "name":               unquote(parsed.fragment) if parsed.fragment else parsed.hostname,
        "uuid":               parsed.username,
        "server":             parsed.hostname,
        "port":               parsed.port,
        "security":           params.get("security", "none"),
        "sni":                params.get("sni", params.get("host", parsed.hostname)),
        "fingerprint":        params.get("fp", "chrome"),
        "flow":               params.get("flow", ""),
        "network":            params.get("type", "tcp"),
        "path":               params.get("path", ""),
        "host_header":        params.get("host", ""),
        "mode":               params.get("mode", "auto"),
        "reality_public_key": params.get("pbk", ""),
        "reality_short_id":   params.get("sid", ""),
        "alpn":               params.get("alpn", ""),
        "allow_insecure":     params.get("allowInsecure", "0") == "1",
    }


# ── Subscription fetch ────────────────────────────────────────────────────────

def fetch_subscription(url: str) -> list[str]:
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    try:
        decoded = base64.b64decode(r.text.strip() + "==").decode("utf-8")
        lines = decoded.splitlines()
    except Exception:
        lines = r.text.splitlines()
    return [l.strip() for l in lines if l.strip().startswith("vless://")]


# ── Xray config + process ─────────────────────────────────────────────────────

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_xray_config(proxy: dict, socks_port: int) -> dict:
    stream: dict = {"network": proxy["network"], "security": proxy["security"]}

    if proxy["security"] == "reality":
        stream["realitySettings"] = {
            "serverName":  proxy["sni"],
            "fingerprint": proxy["fingerprint"] or "chrome",
            "publicKey":   proxy["reality_public_key"],
            "shortId":     proxy["reality_short_id"],
        }
    elif proxy["security"] == "tls":
        tls: dict = {
            "serverName":    proxy["sni"],
            "fingerprint":   proxy["fingerprint"] or "chrome",
            "allowInsecure": proxy["allow_insecure"],
        }
        if proxy["alpn"]:
            tls["alpn"] = proxy["alpn"].split(",")
        stream["tlsSettings"] = tls

    if proxy["network"] == "ws":
        stream["wsSettings"] = {
            "path":    proxy["path"] or "/",
            "headers": {"Host": proxy["host_header"] or proxy["sni"]},
        }
    elif proxy["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": proxy["path"]}
    elif proxy["network"] == "xhttp":
        stream["xhttpSettings"] = {
            "path": proxy["path"] or "/",
            "host": proxy["host_header"] or proxy["sni"],
            "mode": proxy["mode"] or "auto",
        }

    user: dict = {"id": proxy["uuid"], "encryption": "none"}
    if proxy["flow"]:
        user["flow"] = proxy["flow"]

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port":     socks_port,
            "listen":   "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": proxy["server"],
                    "port":    proxy["port"],
                    "users":   [user],
                }]
            },
            "streamSettings": stream,
        }],
    }


def start_xray(config: dict) -> tuple[subprocess.Popen, str]:
    fd, path = tempfile.mkstemp(suffix=".json", prefix="xray_audit_")
    with os.fdopen(fd, "w") as f:
        json.dump(config, f)
    proc = subprocess.Popen(
        [XRAY_BIN, "run", "-c", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc, path


def wait_for_socks(port: int, timeout: float = 6.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


# ── Audit checks ──────────────────────────────────────────────────────────────

def get_exit_ip(session: requests.Session) -> dict:
    r = session.get(
        "http://ip-api.com/json?fields=status,query,country,city,isp,org,proxy,hosting",
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def dns_leak_test(session: requests.Session) -> list[dict]:
    """
    Try bash.ws first. Fall back to ipleak.net if bash.ws returns empty/invalid
    (common from CI/datacenter IPs that get rate-limited by bash.ws).
    """
    # attempt 1: bash.ws
    try:
        uid = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        for i in range(6):
            try:
                session.get(f"https://{i}.{uid}.bash.ws", timeout=5)
            except Exception:
                pass
        time.sleep(1)
        r = session.get(f"https://bash.ws/dnsleak/test/{uid}/?&lang=en", timeout=10)
        r.raise_for_status()
        data = r.json()
        if data:
            return [d for d in data if not d.get("you")]
    except Exception:
        pass

    # attempt 2: ipleak.net
    uid = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    for i in range(6):
        try:
            session.get(f"https://{uid}{i}.ipleak.net", timeout=5)
        except Exception:
            pass
    time.sleep(1)
    r = session.get(f"https://ipleak.net/dnsdetection/?uid={uid}", timeout=10)
    r.raise_for_status()
    data = r.json()
    return [
        {"ip": d.get("ip"), "isp": d.get("isp", ""), "country_code": d.get("country_code", "")}
        for d in data
    ]


def ipv6_leak_test() -> dict:
    try:
        r = requests.get("https://ipv6.icanhazip.com", timeout=5)
        return {"has_ipv6": True, "addr": r.text.strip()}
    except Exception:
        return {"has_ipv6": False, "addr": None}


def reputation_ipapi(ip: str) -> dict:
    r = requests.get(
        f"http://ip-api.com/json/{ip}?fields=status,proxy,hosting,isp,org",
        timeout=10,
    )
    return r.json()


def reputation_abuseipdb(ip: str, api_key: str) -> dict:
    r = requests.get(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Accept": "application/json", "Key": api_key},
        timeout=10,
    )
    r.raise_for_status()
    return r.json().get("data", {})


# ── Per-proxy audit ───────────────────────────────────────────────────────────

def audit_proxy(proxy: dict, abuseipdb_key: str | None) -> dict:
    result: dict = {"proxy": proxy, "checks": {}, "passed": True}

    socks_port = free_port()
    config = build_xray_config(proxy, socks_port)
    proc, cfg_path = start_xray(config)

    try:
        if not wait_for_socks(socks_port):
            result["error"] = "xray failed to start or proxy unreachable"
            result["passed"] = False
            return result

        session = requests.Session()
        session.proxies = {
            "http":  f"socks5://127.0.0.1:{socks_port}",
            "https": f"socks5://127.0.0.1:{socks_port}",
        }
        session.headers["User-Agent"] = "curl/8.4.0"

        # Exit IP
        exit_ip = None
        try:
            info = get_exit_ip(session)
            exit_ip = info.get("query")
            result["checks"]["exit_ip"] = {
                "passed":  True,
                "ip":      exit_ip,
                "country": info.get("country"),
                "city":    info.get("city"),
                "isp":     info.get("isp"),
                "org":     info.get("org"),
            }
        except Exception as e:
            result["checks"]["exit_ip"] = {"passed": False, "error": str(e)}
            result["passed"] = False

        # DNS leak
        try:
            dns = dns_leak_test(session)
            servers = [d for d in dns if not d.get("you")]
            leaked  = any("your isp" in d.get("isp", "").lower() for d in servers)
            result["checks"]["dns_leak"] = {"passed": not leaked, "servers": servers}
            if leaked:
                result["passed"] = False
        except Exception as e:
            result["checks"]["dns_leak"] = {"passed": False, "error": str(e)}
            result["passed"] = False

        # IPv6 leak
        ipv6 = ipv6_leak_test()
        if not ipv6["has_ipv6"]:
            result["checks"]["ipv6_leak"] = {"passed": True, "note": "no IPv6 on machine"}
        else:
            leaked_v6 = bool(exit_ip and ipv6["addr"] != exit_ip)
            result["checks"]["ipv6_leak"] = {"passed": not leaked_v6, "addr": ipv6["addr"]}
            if leaked_v6:
                result["passed"] = False

        # IP reputation
        if exit_ip:
            try:
                rep = reputation_ipapi(exit_ip)
                p_flag = rep.get("proxy", False)
                h_flag = rep.get("hosting", False)
                result["checks"]["reputation"] = {
                    "passed":       not p_flag and not h_flag,
                    "proxy_flag":   p_flag,
                    "hosting_flag": h_flag,
                }
                if p_flag or h_flag:
                    result["passed"] = False
            except Exception as e:
                result["checks"]["reputation"] = {"passed": False, "error": str(e)}

            if abuseipdb_key:
                try:
                    abuse = reputation_abuseipdb(exit_ip, abuseipdb_key)
                    score = abuse.get("abuseConfidenceScore", 0)
                    result["checks"]["abuseipdb"] = {
                        "passed":        score < 15,
                        "score":         score,
                        "total_reports": abuse.get("totalReports", 0),
                    }
                    if score >= 15:
                        result["passed"] = False
                except Exception as e:
                    result["checks"]["abuseipdb"] = {"passed": False, "error": str(e)}

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        os.unlink(cfg_path)

    return result


# ── Report printer ────────────────────────────────────────────────────────────

def icon(passed) -> str:
    if passed is True:  return f"{GREEN}✓{RESET}"
    if passed is False: return f"{RED}✗{RESET}"
    return f"{YELLOW}?{RESET}"


def print_proxy_report(r: dict, index: int):
    p      = r["proxy"]
    passed = r.get("passed", False)
    err    = r.get("error")
    color  = GREEN if passed else RED
    status = "PASSED" if passed else "FAILED"

    print(f"\n{'─'*62}")
    print(f"{BOLD}[{index}] {p['name']}{RESET}  {color}{status}{RESET}")
    print(f"{'─'*62}")

    # Proxy details block
    print(f"  {CYAN}Server          {RESET}{p['server']}:{p['port']}")
    print(f"  {CYAN}UUID            {RESET}{p['uuid']}")
    print(f"  {CYAN}Security        {RESET}{p['security']}")
    print(f"  {CYAN}SNI             {RESET}{p['sni']}")
    print(f"  {CYAN}Network         {RESET}{p['network']}")
    print(f"  {CYAN}Flow            {RESET}{p['flow'] or '—'}")
    print(f"  {CYAN}TLS Fingerprint {RESET}{p['fingerprint'] or '—'}")
    if p["security"] == "reality":
        print(f"  {CYAN}Reality pbk     {RESET}{p['reality_public_key']}")
        print(f"  {CYAN}Reality sid     {RESET}{p['reality_short_id']}")
    if p["network"] == "ws":
        print(f"  {CYAN}WS Path         {RESET}{p['path'] or '/'}")
        print(f"  {CYAN}Host header     {RESET}{p['host_header'] or '—'}")
    if p["network"] == "xhttp":
        print(f"  {CYAN}XHTTP Path      {RESET}{p['path'] or '/'}")
        print(f"  {CYAN}XHTTP Host      {RESET}{p['host_header'] or p['sni'] or '—'}")
        print(f"  {CYAN}XHTTP Mode      {RESET}{p['mode']}")
    if p["alpn"]:
        print(f"  {CYAN}ALPN            {RESET}{p['alpn']}")

    if err:
        print(f"\n  [{RED}✗{RESET}] {err}")
        return

    # Check results
    checks = r.get("checks", {})
    print()

    ei = checks.get("exit_ip", {})
    print(f"  [{icon(ei.get('passed'))}] Exit IP          "
          f"{ei.get('ip','?')}  {ei.get('city','?')}, {ei.get('country','?')}  ({ei.get('isp','?')})")

    dns = checks.get("dns_leak", {})
    if dns.get("passed"):
        servers_str = "  |  ".join(
            f"{d.get('ip','?')} [{d.get('isp','?')}, {d.get('country_code','?')}]"
            for d in dns.get("servers", [])
        )
        print(f"  [{icon(True)}] DNS leak         clean — {servers_str}")
    else:
        print(f"  [{icon(False)}] DNS leak         LEAKED  {dns.get('error','')}")

    ipv6 = checks.get("ipv6_leak", {})
    ipv6_detail = ipv6.get("note") or (
        f"LEAKED {ipv6.get('addr')}" if not ipv6.get("passed") else f"clean ({ipv6.get('addr')})"
    )
    print(f"  [{icon(ipv6.get('passed'))}] IPv6 leak        {ipv6_detail}")

    rep = checks.get("reputation", {})
    print(f"  [{icon(rep.get('passed'))}] IP reputation    "
          f"proxy_flag={rep.get('proxy_flag')}  hosting_flag={rep.get('hosting_flag')}")

    if "abuseipdb" in checks:
        ab = checks["abuseipdb"]
        print(f"  [{icon(ab.get('passed'))}] AbuseIPDB        "
              f"score={ab.get('score')}/100  reports={ab.get('total_reports')}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="VLESS subscription audit tool")
    parser.add_argument("--sub", required=True, help="Subscription URL")
    parser.add_argument("--abuseipdb-key", default=None, help="Optional AbuseIPDB API key")
    parser.add_argument("--json-out", default=None, help="Save full results to JSON file")
    args = parser.parse_args()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n{BOLD}VLESS Subscription Audit — {now}{RESET}")
    print(f"Fetching: {args.sub}")

    uris = fetch_subscription(args.sub)
    if not uris:
        print("No VLESS URIs found in subscription.")
        sys.exit(1)

    print(f"Found {len(uris)} proxies\n")

    all_results = []
    for i, uri in enumerate(uris, 1):
        proxy = parse_vless_uri(uri)
        print(f"  [{i}/{len(uris)}] {proxy['name']} ({proxy['server']}) ... ", end="", flush=True)
        result = audit_proxy(proxy, args.abuseipdb_key)
        color  = GREEN if result["passed"] else RED
        print(f"{color}{'PASSED' if result['passed'] else 'FAILED'}{RESET}")
        all_results.append(result)

    # Full per-proxy reports
    for i, r in enumerate(all_results, 1):
        print_proxy_report(r, i)

    # Summary
    passed = sum(1 for r in all_results if r["passed"])
    failed = len(all_results) - passed
    print(f"\n{'═'*62}")
    print(f"{BOLD}Summary:{RESET}  {GREEN}{passed} passed{RESET}  {RED}{failed} failed{RESET}  of {len(all_results)} total")
    print(f"{'═'*62}\n")

    out = args.json_out or f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"Report saved → {out}\n")


if __name__ == "__main__":
    main()

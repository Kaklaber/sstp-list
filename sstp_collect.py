#!/usr/bin/env python3
"""Collect working SSTP servers from the VPN Gate iPhone API.

Each run:
  1. Downloads the API list (or reads --csv FILE).
  2. Adds the servers already in sstp.txt (the API only lists servers that
     are up right now, so older ones would otherwise be lost).
  3. Tests all of them: API servers on port 443 and on their own TCP port
     (taken from the OpenVPN settings in the API list), saved servers on
     their saved port. A server passes when it answers a real SSTP request.
  4. Writes only the servers that passed to sstp.txt. Servers that no longer
     work are removed. No line appears twice.

Output (the only file it writes):
  sstp.txt   "Country | ip:port", sorted by country, then IP

Proxy: http_proxy / https_proxy is used only to download the VPN Gate list.
The SSTP test always connects directly.

If the download fails, the servers in sstp.txt are still re-tested.
If not a single server passes (for example no internet), sstp.txt is left
unchanged.

Standard library only. Python 3.8 or newer.
"""

import argparse
import base64
import csv
import ipaddress
import os
import re
import socket
import ssl
import sys
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

API_URLS = ["http://www.vpngate.net/api/iphone/", "https://www.vpngate.net/api/iphone/"]
DEFAULT_PORT = 443
SSTP_URI = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
OUT_FILE = "sstp.txt"
OLD_OUT_FILE = "sstp_with_country_ip.txt"   # earlier name, read once if sstp.txt does not exist yet
TIMEOUT = 8
WORKERS = 32
# API country names that differ from the names in the F0rc3Run list.
COUNTRY_NAMES = {
    "Korea Republic of": "South Korea",
    "Viet Nam": "Vietnam",
    "Russian Federation": "Russia",
}
LINE_RE = re.compile(r"^\s*(.+?)\s*\|\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s*$")

# VPN Gate servers use self-signed certificates, so the test checks the SSTP answer, not the certificate.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def fetch_api():
    """The API list as text, or None if it cannot be downloaded."""
    proxy = urllib.request.getproxies()
    proxy = proxy.get("http") or proxy.get("https") or proxy.get("all")
    if proxy:
        print(f"Downloading the VPN Gate list through proxy {proxy}")
    errors = []
    for attempt in range(3):
        for url in API_URLS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "sstp-collector/3.0"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return resp.read().decode("utf-8", errors="replace")
            except OSError as e:
                errors.append(f"{url}: {e}")
        if attempt < 2:
            time.sleep(10)
    print("Download failed:\n  " + "\n  ".join(errors))
    return None


def parse_api(text):
    """The VPN Gate list starts with a '*' line, then a '#HostName' header, then rows, then a '*' line."""
    header, body = None, []
    for line in text.splitlines():
        if not line.strip():
            continue
        if header is None:
            if line.lstrip("#").startswith("HostName"):
                header = next(csv.reader([line.lstrip("#")]))
        elif not line.startswith("*"):
            body.append(line)
    if header is None:
        print("The download is not the VPN Gate list (no HostName header).")
        return []
    return [dict(zip(header, rec)) for rec in csv.reader(body) if rec]


def country_name(row):
    name = (row.get("CountryLong") or row.get("CountryShort") or "Unknown").strip() or "Unknown"
    return COUNTRY_NAMES.get(name, name)


def own_tcp_port(row):
    """The TCP port from the server's OpenVPN settings, or None if it uses UDP or has none."""
    data = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
    if not data:
        return None
    try:
        cfg = base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="replace")
    except ValueError:
        return None
    proto = re.search(r"^\s*proto\s+(\S+)", cfg, re.M)
    remote = re.search(r"^\s*remote\s+\S+\s+(\d+)", cfg, re.M)
    if not proto or not remote or not proto.group(1).lower().startswith("tcp"):
        return None
    port = int(remote.group(1))
    return port if 0 < port < 65536 else None


def candidates(rows):
    """{ip: server} from the API rows, with the ports to test."""
    out = {}
    for r in rows:
        ip = (r.get("IP") or "").strip()
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        name = (r.get("HostName") or "").strip().lower()
        host = name if "." in name else (name + ".opengw.net" if name else ip)
        c = out.setdefault(ip, {"ip": ip, "host": host, "country": country_name(r), "ports": [DEFAULT_PORT]})
        port = own_tcp_port(r)
        if port and port not in c["ports"]:
            c["ports"].append(port)
    return out


def add_saved(servers, saved):
    """Add the saved servers to the test list. Returns how many addresses were only in the saved file."""
    only_saved = 0
    for (ip, port), country in saved.items():
        c = servers.get(ip)
        if c is None:
            # Not in today's API list: the name is unknown, so the IP is used as the host.
            c = servers[ip] = {"ip": ip, "host": ip, "country": country, "ports": []}
        if port not in c["ports"]:
            c["ports"].append(port)
            only_saved += 1
    return only_saved


def sstp_ok(host, ip, port):
    """True if the server answers an SSTP_DUPLEX_POST with HTTP 200. Always a direct connection."""
    request = (
        f"SSTP_DUPLEX_POST {SSTP_URI} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"SSTPCORRELATIONID: {{{uuid.uuid4()}}}\r\n"
        "Content-Length: 18446744073709551615\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as raw:
            with TLS.wrap_socket(raw) as tls:
                tls.sendall(request)
                reply = tls.recv(256)
        return reply.startswith(b"HTTP/1.1 200")
    except (OSError, ValueError):
        return False


def test_server(c):
    """The ports of this server that passed the SSTP test."""
    return [p for p in c["ports"] if sstp_ok(c["host"], c["ip"], p)]


def load_saved(path):
    """{(ip, port): country} from an earlier output file."""
    saved = {}
    if not os.path.exists(path):
        return saved
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            try:
                ipaddress.IPv4Address(m.group(2))
            except ValueError:
                continue
            port = int(m.group(3))
            if 0 < port < 65536:
                saved.setdefault((m.group(2), port), m.group(1))
    return saved


def write_file(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser(description="Collect working SSTP servers from the VPN Gate API.")
    ap.add_argument("--csv", help="read this file instead of downloading the API list")
    ap.add_argument("--out", default=OUT_FILE, help=f"output file (default {OUT_FILE})")
    args = ap.parse_args()

    if args.csv:
        with open(args.csv, encoding="utf-8-sig", errors="replace") as f:
            text = f.read()
    else:
        text = fetch_api()

    servers = candidates(parse_api(text)) if text else {}
    api_count = len(servers)

    saved_from = args.out
    if not os.path.exists(saved_from) and args.out == OUT_FILE and os.path.exists(OLD_OUT_FILE):
        saved_from = OLD_OUT_FILE
    saved = load_saved(saved_from)
    only_saved = add_saved(servers, saved)

    todo = list(servers.values())
    addresses = sum(len(c["ports"]) for c in todo)
    if not todo:
        sys.exit(f"Nothing to test: the VPN Gate list could not be read and {args.out} has no servers.")

    print(f"Testing {addresses} addresses directly "
          f"(VPN Gate list: {api_count} servers, saved: {len(saved)}, only in saved file: {only_saved})")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(test_server, todo))

    working = {}
    for c, ports in zip(todo, results):
        for p in ports:
            working[(c["ip"], p)] = c["country"]

    if not working:
        sys.exit(f"No server passed the SSTP test (is the internet working?). {args.out} was left unchanged.")

    entries = sorted(working.items(), key=lambda kv: (kv[1].lower(), ipaddress.IPv4Address(kv[0][0]), kv[0][1]))
    write_file(args.out, "".join(f"{country} | {ip}:{port}\n" for (ip, port), country in entries))

    kept = sum(1 for k in working if k in saved)
    print(f"Working: {len(entries)} | still working from before: {kept} | new: {len(entries) - kept} | "
          f"removed (stopped working): {len(saved) - kept} | countries: {len(set(working.values()))} | file: {args.out}")


if __name__ == "__main__":
    main()

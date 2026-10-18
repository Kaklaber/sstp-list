#!/usr/bin/env python3
"""Collect working SSTP servers from the VPN Gate iPhone API.

Each run:
  1. Downloads the API list (or reads --csv FILE).
  2. Adds the servers already in sstp.txt (the API only lists servers that
     are up right now, so older ones would otherwise be lost).
  3. Tests all of them: API servers on port 443 and on their own TCP port
     (taken from the OpenVPN settings in the API list), saved servers on
     their saved port. A server passes when it answers a real SSTP request.
     A network error (timeout, reset) is tried twice before the server counts
     as failed. The test accepts old servers (TLS 1.0 / 1.1, weak ciphers) and
     never checks the certificate, the same as an SSTP client with the
     certificate check turned off.
  4. Writes only the servers that passed to sstp.txt. Servers that no longer
     work are removed. No line appears twice.
  5. Safety check: if fewer than half of the saved servers work (a sign of a
     network problem on the runner, not of 50% of the servers dying within
     one hour), sstp.txt is NOT changed and the run ends with an error.
     Use --force to write the file anyway.

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
import warnings
from concurrent.futures import ThreadPoolExecutor

API_URLS = ["http://www.vpngate.net/api/iphone/", "https://www.vpngate.net/api/iphone/"]
DEFAULT_PORT = 443
SSTP_URI = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
OUT_FILE = "sstp.txt"
OLD_OUT_FILE = "sstp_with_country_ip.txt"   # earlier name, read once if sstp.txt does not exist yet
TIMEOUT = 8
ATTEMPTS = 2          # tries per address when the connection fails with a network error
RETRY_DELAY = 3       # seconds between those tries
MIN_SAVED_FOR_CHECK = 20   # the safety check only applies when the saved file has at least this many entries
MIN_KEEP_RATIO = 0.5       # ...and refuses to write if fewer than this share of them work now
WORKERS = 32
# API country names that differ from the names in the F0rc3Run list.
COUNTRY_NAMES = {
    "Korea Republic of": "South Korea",
    "Viet Nam": "Vietnam",
    "Russian Federation": "Russia",
}
LINE_RE = re.compile(r"^\s*(.+?)\s*\|\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s*$")

# VPN Gate servers use self-signed certificates, so the test checks the SSTP answer, not the certificate
# (no certificate check, the same as an SSTP client with the check turned off).
# Python on a current Linux refuses TLS 1.0 / 1.1 by default, so a working server that only speaks an old
# TLS version would be dropped. The test only asks "does it answer SSTP?" and sends no secrets, so the
# minimum version and the OpenSSL security level are lowered.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE
try:
    TLS.set_ciphers("DEFAULT:@SECLEVEL=0")
except ssl.SSLError:
    pass    # this Python/OpenSSL build does not know SECLEVEL: keep the default ciphers
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)     # Python 3.12 warns that TLSv1 is deprecated
    try:
        TLS.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError, ssl.SSLError):
        pass    # this build cannot go below its default: keep it


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
                req = urllib.request.Request(url, headers={"User-Agent": "sstp-collector/3.1"})
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
    """True if the server answers an SSTP_DUPLEX_POST with HTTP 200. Always a direct connection.

    A network error (timeout, reset, failed handshake) is tried ATTEMPTS times in total, so one lost
    packet does not remove a good server. A refused connection, or an answer that is not HTTP 200, is final.
    """
    request = (
        f"SSTP_DUPLEX_POST {SSTP_URI} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"SSTPCORRELATIONID: {{{uuid.uuid4()}}}\r\n"
        "Content-Length: 18446744073709551615\r\n\r\n"
    ).encode("ascii")
    for attempt in range(ATTEMPTS):
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT) as raw:
                with TLS.wrap_socket(raw) as tls:
                    tls.sendall(request)
                    reply = b""
                    while len(reply) < 12:      # "HTTP/1.1 200" is 12 bytes; a first recv() can be shorter
                        chunk = tls.recv(256)
                        if not chunk:
                            break
                        reply += chunk
            return reply.startswith(b"HTTP/1.1 200")
        except ConnectionRefusedError:
            return False
        except (OSError, ValueError):
            if attempt + 1 < ATTEMPTS:
                time.sleep(RETRY_DELAY)
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
    ap.add_argument("--force", action="store_true",
                    help="write the file even if fewer than half of the saved servers work")
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

    if (not args.force and len(saved) >= MIN_SAVED_FOR_CHECK
            and len(working) < len(saved) * MIN_KEEP_RATIO):
        sys.exit(f"Only {len(working)} working now, but {len(saved)} were saved. That is a drop of more than "
                 f"{round((1 - MIN_KEEP_RATIO) * 100)}%, which looks like a network problem and not real change. "
                 f"{args.out} was left unchanged. Use --force to write it anyway.")

    entries = sorted(working.items(), key=lambda kv: (kv[1].lower(), ipaddress.IPv4Address(kv[0][0]), kv[0][1]))
    write_file(args.out, "".join(f"{country} | {ip}:{port}\n" for (ip, port), country in entries))

    kept = sum(1 for k in working if k in saved)
    print(f"Working: {len(entries)} | still working from before: {kept} | new: {len(entries) - kept} | "
          f"removed (stopped working): {len(saved) - kept} | countries: {len(set(working.values()))} | file: {args.out}")


if __name__ == "__main__":
    main()

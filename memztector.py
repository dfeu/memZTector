#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import ipaddress
import sqlite3
import tempfile
import os
from typing import Optional, Tuple

# --- Einstellungen ---
CHUNK = 1024 * 1024          # 1 MiB per chunk
OVERLAP_SCAN = 64            # Overlap for IP-search
MAX_BUF = 8 * 1024 * 1024    # max. buffer for JSON-search
MAX_JSON_WINDOW = 4 * 1024 * 1024  # windows size while finding arrays

# --- Byte-RegEx (case-insensitive) ---
ALLOWDNS_RX = re.compile(rb'allowdns', re.I)
ID_RX       = re.compile(rb'"(?:id|nwid)"\s*:\s*"([^"]+)"', re.I)
TARGET_RX   = re.compile(rb'"target"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})"', re.I)
NAME_RX     = re.compile(rb'"name"\s*:\s*"([^"]+)"', re.I)  # Netzwerkname
IP_RX       = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Arrays mit Endpunkten
ARRAY_RX    = re.compile(rb'"(surfaceaddresses|listeningon)"\s*:\s*\[(.*?)\]', re.I | re.S)
ENDPOINT_RX = re.compile(rb'"((?:\d{1,3}\.){3}\d{1,3})/(\d{1,5})"')

def ip_to_int(ip_str: str) -> int:
    a, b, c, d = (int(x) for x in ip_str.split('.'))
    return (a << 24) | (b << 16) | (c << 8) | d

def find_network_info(path: str) -> Tuple[Optional[str], Optional[ipaddress.IPv4Network], Optional[str]]:
    """
    ToDo.
    """
    buf = b""
    anchored = False

    with open(path, 'rb', buffering=0) as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk and not buf:
                break

            scan = buf + (chunk or b"")

            if not anchored:
                m = ALLOWDNS_RX.search(scan)
                if not m:
                    keep = max(0, len(scan) - 32)
                    buf = scan[keep:]
                    if not chunk:
                        break
                    continue
                scan = scan[m.start():]
                anchored = True

            buf = scan if len(scan) <= MAX_BUF else scan[-MAX_BUF:]

            id_m   = ID_RX.search(buf)
            tgt_m  = TARGET_RX.search(buf)
            name_m = NAME_RX.search(buf)

            if id_m and tgt_m:
                net_id = id_m.group(1).decode('utf-8', errors='ignore')
                ip_s   = tgt_m.group(1).decode('ascii', errors='ignore')
                prefix = int(tgt_m.group(2).decode('ascii', errors='ignore'))
                try:
                    net = ipaddress.ip_network(f"{ip_s}/{prefix}", strict=False)
                except ValueError:
                    net = None
                net_name = name_m.group(1).decode('utf-8', errors='ignore') if name_m else None
                return net_id, net, net_name

            # zum nächsten allowdns innerhalb des Puffers springen, falls vorhanden
            next_m = ALLOWDNS_RX.search(buf, 1)
            if next_m:
                buf = buf[next_m.start():]
                anchored = True
                continue

            if not chunk:
                break

    return None, None, None

def stream_ips_to_sqlite(path: str, net: ipaddress.IPv4Network, db_path: str) -> int:
    """
    IPs scan, store hits unique in SQLite.
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("PRAGMA journal_mode=OFF;")
    cur.execute("PRAGMA synchronous=OFF;")
    cur.execute("CREATE TABLE IF NOT EXISTS ips (ip TEXT PRIMARY KEY, ip_int INTEGER NOT NULL)")
    con.commit()

    total_seen = 0
    carry = b""

    with open(path, 'rb', buffering=0) as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk and not carry:
                break
            scan = carry + (chunk or b"")

            to_insert = []
            for m in IP_RX.finditer(scan):
                try:
                    ip_s = m.group(0).decode('ascii')
                except UnicodeDecodeError:
                    continue
                try:
                    ip = ipaddress.ip_address(ip_s)
                except ValueError:
                    continue
                if isinstance(ip, ipaddress.IPv4Address) and ip in net:
                    total_seen += 1
                    to_insert.append((ip_s, ip_to_int(ip_s)))

            if to_insert:
                cur.executemany("INSERT OR IGNORE INTO ips(ip, ip_int) VALUES(?,?)", to_insert)
                con.commit()

            if not chunk:
                break
            carry = scan[-OVERLAP_SCAN:] if len(scan) > OVERLAP_SCAN else scan

    con.close()
    return total_seen

def extract_public_endpoints(path: str, db_path: str) -> Tuple[int, int]:
    """
    Find arrays  'surfaceAddresses' und 'listeningOn' (case-insensitive),
    extract "IP/PORT"-pairs, filtering for public ipv4, store unique values in SQLite.
    """
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("PRAGMA journal_mode=OFF;")
    cur.execute("PRAGMA synchronous=OFF;")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pub_endpoints (
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            source TEXT NOT NULL,
            ip_int INTEGER NOT NULL,
            PRIMARY KEY (ip, port, source)
        )
    """)
    con.commit()

    carry = b""
    scanned = 0

    with open(path, 'rb', buffering=0) as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk and not carry:
                break

            window = (carry + (chunk or b""))
            if len(window) > MAX_JSON_WINDOW:
                window = window[-MAX_JSON_WINDOW:]

            for m in ARRAY_RX.finditer(window):
                source = m.group(1).decode('ascii', errors='ignore').lower()  # 'surfaceaddresses'/'listeningon'
                content = m.group(2)
                pairs = ENDPOINT_RX.findall(content)
                if not pairs:
                    continue

                rows = []
                for ip_b, port_b in pairs:
                    try:
                        ip_s = ip_b.decode('ascii')
                        port = int(port_b.decode('ascii'))
                    except Exception:
                        continue
                    try:
                        ip_obj = ipaddress.ip_address(ip_s)
                    except ValueError:
                        continue
                    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_global:
                        rows.append((ip_s, port, source, ip_to_int(ip_s)))
                        scanned += 1

                if rows:
                    cur.executemany(
                        "INSERT OR IGNORE INTO pub_endpoints(ip, port, source, ip_int) VALUES(?,?,?,?)",
                        rows
                    )
                    con.commit()

            if not chunk:
                break
            carry = window[-(OVERLAP_SCAN * 8):] if len(window) > (OVERLAP_SCAN * 8) else window

    cur.execute("SELECT COUNT(*) FROM pub_endpoints")
    unique_public = cur.fetchone()[0]
    con.close()
    return scanned, unique_public

def main(path: str) -> None:
    net_id, net, net_name = find_network_info(path)
    if not net_id or not net:
        print("No network-id/nwid or target-network found.")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "zt.sqlite")

        total_seen = stream_ips_to_sqlite(path, net, db_path)
        scanned_pub, unique_pub = extract_public_endpoints(path, db_path)

        con = sqlite3.connect(db_path)
        cur = con.cursor()

        print("=== Results ===")
        if net_name:
            print(f"Network name: {net_name}")
        print(f"Networkid: {net_id}")
        print(f"Subnet: {net.with_prefixlen}")

        print("\n--Found IPs in subnet (unique) --")
        count = 0
        for (ip,) in cur.execute("SELECT ip FROM ips ORDER BY ip_int ASC"):
            print(" ", ip)
            count += 1
        print(f"Total: {count} (scanned: {total_seen})")

        print("\n-- Public endpoints --")
        for row in cur.execute("""
            SELECT ip, port, source FROM pub_endpoints
            ORDER BY ip_int ASC, port ASC, source ASC
        """):
            ip, port, source = row
            print(f"  {ip}:{port}  [{source}]")
        print(f"Unique public endpoints: {unique_pub} (read: {scanned_pub})")

        con.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_dumpfile>")
        sys.exit(64)
    main(sys.argv[1])

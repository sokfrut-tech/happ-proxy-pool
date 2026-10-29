#!/usr/bin/env python3
"""Build an Xray-compatible Happ config from publicly listed HTTP CONNECT proxies.

WARNING: Public proxies are untrusted. TLS protects HTTPS contents only when the
certificate validates end-to-end; proxies can still observe metadata and traffic
to non-HTTPS destinations. Do not use this pool for sensitive activity.
"""
import json
import re
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

OUTPUT_FILE = "happ_config.json"
TIMEOUT = 2
MAX_WORKERS = 60
TARGET_LIMIT = 12
MAX_CANDIDATES = 120
TEST_HOST = "www.cloudflare.com"
TEST_PATH = "/cdn-cgi/trace"

SOURCES = [
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/DE/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
]
PROXY_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")


def fetch_candidates():
    candidates, seen = [], set()
    for url in SOURCES:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "HappProxyPool/1.0"})
            with urllib.request.urlopen(request, timeout=15) as response:
                text = response.read(2_000_000).decode("utf-8", errors="ignore")
            for raw_line in text.splitlines():
                line = raw_line.strip()
                match = PROXY_RE.fullmatch(line)
                if not match:
                    continue
                octets = match.group(1).split(".")
                port = int(match.group(2))
                if any(int(part) > 255 for part in octets) or not 1 <= port <= 65535:
                    continue
                if line not in seen:
                    seen.add(line)
                    candidates.append(line)
        except Exception as exc:
            print(f"Source unavailable: {url} ({type(exc).__name__})")
    return candidates[:MAX_CANDIDATES]


def read_http_headers(sock, limit=16384):
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) < limit:
        chunk = sock.recv(2048)
        if not chunk:
            break
        data.extend(chunk)
    if b"\r\n\r\n" not in data:
        raise ValueError("Incomplete proxy response")
    return bytes(data).split(b"\r\n\r\n", 1)[0]


def verify_proxy(proxy):
    host, port_text = proxy.split(":")
    port = int(port_text)
    started = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        request = (
            f"CONNECT {TEST_HOST}:443 HTTP/1.1\r\n"
            f"Host: {TEST_HOST}:443\r\n"
            "Proxy-Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        status_line = read_http_headers(sock).split(b"\r\n", 1)[0]
        if not re.match(rb"^HTTP/\d(?:\.\d)? 200(?:\s|$)", status_line):
            return None

        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=TEST_HOST) as tls:
            sock = None
            tls.settimeout(TIMEOUT)
            tls.sendall(
                f"GET {TEST_PATH} HTTP/1.1\r\n"
                f"Host: {TEST_HOST}\r\n"
                "User-Agent: HappProxyPool/1.0\r\n"
                "Connection: close\r\n\r\n".encode("ascii")
            )
            response = bytearray()
            while len(response) < 8192:
                chunk = tls.recv(2048)
                if not chunk:
                    break
                response.extend(chunk)
            raw = bytes(response)
        if b"HTTP/1.1 200" not in raw.split(b"\r\n", 1)[0] and b"HTTP/2 200" not in raw[:100]:
            return None
        body = raw.split(b"\r\n\r\n", 1)[-1].decode("utf-8", errors="ignore")
        if "visit_scheme=https" not in body:
            return None

        location = re.search(r"(?m)^loc=([A-Z]{2})$", body)
        country = location.group(1) if location else "UN"
        if country in {"RU", "BY", "CN", "IR"}:
            return None
        return {
            "address": host,
            "port": port,
            "country": country,
            "latency": round((time.monotonic() - started) * 1000),
        }
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def build_happ_json(verified):
    outbounds = []
    for index, item in enumerate(verified, 1):
        outbounds.append({
            "tag": f"proxy_{index}_{item['country']}",
            "protocol": "http",
            "settings": {
                "servers": [{"address": item["address"], "port": item["port"]}]
            },
        })
    outbounds.extend([
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ])

    routing_rules = [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
        {"type": "field", "network": "udp", "outboundTag": "block"},
    ]
    routing = {"domainStrategy": "AsIs", "rules": routing_rules}
    if verified:
        routing["balancers"] = [{
            "tag": "auto-balancer",
            "selector": ["proxy_"],
            "strategy": {"type": "leastPing"},
        }]
        routing_rules.append({
            "type": "field", "network": "tcp", "balancerTag": "auto-balancer"
        })
    else:
        routing_rules.append({
            "type": "field", "network": "tcp", "outboundTag": "direct"
        })

    config = {
        "remarks": f"GitHub Auto-Pool ({len(verified)} tested HTTPS nodes)",
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": ["tcp://1.1.1.1:53", "tcp://8.8.8.8:53"],
            "queryStrategy": "UseIPv4",
        },
        "inbounds": [
            {
                "tag": "socks-in", "port": 10808, "listen": "127.0.0.1",
                "protocol": "socks",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                "settings": {"auth": "noauth", "udp": True},
            },
            {
                "tag": "http-in", "port": 10809, "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
        ],
        "outbounds": outbounds,
        "routing": routing,
    }
    if verified:
        config["burstObservatory"] = {
            "subjectSelector": ["proxy_"],
            "pingConfig": {
                "destination": "https://www.cloudflare.com/cdn-cgi/trace",
                "interval": "30s", "sampling": 3, "timeout": "5s",
            },
        }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2, ensure_ascii=False)
        file.write("\n")


def main():
    candidates = fetch_candidates()
    print(f"Found {len(candidates)} candidate proxies")
    verified = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(verify_proxy, proxy) for proxy in candidates]
        for future in as_completed(futures):
            result = future.result()
            if result:
                verified.append(result)
                print(f"Verified {result['country']} proxy ({result['latency']} ms)")
                if len(verified) >= TARGET_LIMIT * 2:
                    break

    verified.sort(key=lambda item: (item["country"] != "DE", item["latency"]))
    selected = verified[:TARGET_LIMIT]
    build_happ_json(selected)
    print(f"Wrote {OUTPUT_FILE} with {len(selected)} tested proxies")


if __name__ == "__main__":
    main()

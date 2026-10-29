#!/usr/bin/env python3
"""Build a conservative Happ/Xray config from public HTTP CONNECT proxies.

Candidates are checked from GitHub Actions with repeated, certificate-validated
HTTPS requests. This is a reachability filter, not a privacy or uptime guarantee.
"""
import json
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

OUTPUT_FILE = "happ_config.json"
TIMEOUT = 5
MAX_WORKERS = 60
MAX_CANDIDATES = 1000
TARGET_LIMIT = 12
CHECKS_PER_PROXY = 2
TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"
USER_AGENT = "HappProxyPool/3.0"
BLOCKED_EXIT_COUNTRIES = {"RU", "BY", "CN", "IR"}

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
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = response.read(2_000_000).decode("utf-8", errors="ignore")
            added = 0
            for raw_line in payload.splitlines():
                line = raw_line.strip()
                match = PROXY_RE.fullmatch(line)
                if not match:
                    continue
                octets = [int(part) for part in match.group(1).split(".")]
                port = int(match.group(2))
                if any(part > 255 for part in octets) or not 1 <= port <= 65535:
                    continue
                if line not in seen:
                    seen.add(line)
                    candidates.append(line)
                    added += 1
            print(f"Source loaded: {url} ({added} new candidates)")
        except Exception as exc:
            print(f"Source unavailable: {url} ({type(exc).__name__})")
    print(f"Collected {len(candidates)} unique candidates")
    return candidates[:MAX_CANDIDATES]


def verify_proxy(proxy):
    """Require repeated HTTPS 200 responses through a validated CONNECT tunnel."""
    proxy_url = "http://" + proxy
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    latencies = []
    response_body = ""

    try:
        for _ in range(CHECKS_PER_PROXY):
            request = urllib.request.Request(
                TEST_URL,
                headers={"User-Agent": USER_AGENT, "Accept": "text/plain"},
            )
            started = time.monotonic()
            with opener.open(request, timeout=TIMEOUT) as response:
                if response.status != 200:
                    return None
                body = response.read(8192).decode("utf-8", errors="ignore")
                if "visit_scheme=https" not in body:
                    return None
            latencies.append(round((time.monotonic() - started) * 1000))
            response_body = body

        location = re.search(r"(?m)^loc=([A-Z]{2})$", response_body)
        country = location.group(1) if location else "UN"
        if country in BLOCKED_EXIT_COUNTRIES:
            return None

        host, port_str = proxy.rsplit(":", 1)
        return {
            "address": host,
            "port": int(port_str),
            "country": country,
            "latency": max(latencies),
        }
    except (OSError, TimeoutError, urllib.error.URLError, ValueError):
        return None
    except Exception:
        return None


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

    rules = [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
        {"type": "field", "network": "udp", "outboundTag": "block"},
    ]
    routing = {"domainStrategy": "AsIs", "rules": rules}

    if verified:
        # Round-robin avoids Xray's runtime observatory/ping subsystem.
        # It distributes new connections; it is NOT a guaranteed per-request failover.
        routing["balancers"] = [{
            "tag": "safe-balancer",
            "selector": ["proxy_"],
            "strategy": {"type": "roundRobin"},
        }]
        rules.append({
            "type": "field",
            "network": "tcp",
            "balancerTag": "safe-balancer",
        })
    else:
        # Never publish an empty balancer or retain a stale dead proxy list.
        rules.append({
            "type": "field",
            "network": "tcp",
            "outboundTag": "direct",
        })

    config = {
        "remarks": f"Safe Auto-Pool ({len(verified)} repeated-HTTPS-tested nodes)",
        "log": {"loglevel": "warning"},
        "stats": {},
        "dns": {
            "servers": ["tcp://1.1.1.1:53", "tcp://8.8.8.8:53"],
            "queryStrategy": "UseIPv4",
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                "settings": {"auth": "noauth", "udp": True},
            },
            {
                "tag": "http-in",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
        ],
        "outbounds": outbounds,
        "routing": routing,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2, ensure_ascii=False)
        file.write("\n")


def main():
    candidates = fetch_candidates()
    print(
        f"Testing up to {len(candidates)} candidates with "
        f"{MAX_WORKERS} workers; {CHECKS_PER_PROXY} HTTPS checks each"
    )
    verified = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(verify_proxy, proxy): proxy for proxy in candidates}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            if result:
                verified.append(result)
            if completed % 100 == 0:
                print(f"Progress: {completed}/{len(futures)} checked; {len(verified)} passed")

    # Prefer German exits, then proxies with the best worst-case test latency.
    verified.sort(key=lambda item: (item["country"] != "DE", item["latency"]))
    selected = verified[:TARGET_LIMIT]
    build_happ_json(selected)
    print(
        f"RESULT: {len(selected)} repeated-HTTPS-tested proxies selected "
        f"from {len(candidates)} candidates"
    )
    print(f"Wrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

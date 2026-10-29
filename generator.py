#!/usr/bin/env python3
"""Collect public share links, verify real HTTPS traffic, and prefer German nodes.

A successful probe does not prove UDP support, long-term availability, or privacy.
Public nodes are untrusted; never use them for sensitive traffic.
"""
import base64
import concurrent.futures
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

OUTPUT_FILE = "happ_config.json"
SOURCES = ["https://radarhub.top/by-country/germany.txt", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt", "https://raw.githubusercontent.com/freefq/free/master/v2"]
MAX_NODES = 10
MAX_CANDIDATES = 120
CHECK_WORKERS = 12
CONNECT_TIMEOUT = 3
USER_AGENT = "HappFreeNodePool/1.2"
# Only verified German VPN exits are published; no overseas fallback.
EUROPE_COUNTRIES = {
    "DE", "AT", "CH", "NL", "BE", "LU", "FR", "PL", "CZ", "DK",
    "SE", "NO", "FI", "IT", "ES", "PT", "GB", "IE", "EE", "LV",
    "LT", "SK", "SI", "HR", "HU", "RO", "BG", "GR", "IS", "UA",
}


def decode_subscription(text):
    text = text.strip().lstrip("\ufeff")
    decoded = text
    compact = "".join(text.split())
    if compact and not compact.startswith(("ss://", "vless://", "vmess://")):
        try:
            padded = compact + "=" * (-len(compact) % 4)
            candidate = base64.urlsafe_b64decode(padded).decode("utf-8", "ignore")
            if any(x in candidate for x in ("ss://", "vless://", "vmess://")):
                decoded = candidate
        except Exception:
            pass
    return [line.strip() for line in decoded.splitlines()
            if line.strip().startswith(("ss://", "vless://", "vmess://"))]


def fetch_links():
    found, seen = [], set()
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=15) as response:
                body = response.read(2_000_000).decode("utf-8", "ignore")
            for link in decode_subscription(body):
                if link not in seen:
                    seen.add(link)
                    found.append(link)
            print(f"Loaded {len(found)} unique links after {url}")
        except Exception as exc:
            print(f"Source error {url}: {type(exc).__name__}: {exc}")
    return found[:MAX_CANDIDATES]


def b64decode(value):
    value = urllib.parse.unquote(value)
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value).decode("utf-8")


def parse_ss(link):
    parsed = urllib.parse.urlsplit(link)
    raw = parsed.netloc + parsed.path
    if "@" in raw:
        userinfo, endpoint = raw.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = b64decode(userinfo)
        method, password = userinfo.split(":", 1)
        endpoint = endpoint.split("?", 1)[0]
        host, port = endpoint.rsplit(":", 1)
    else:
        decoded = b64decode(raw.split("?", 1)[0])
        credentials, endpoint = decoded.rsplit("@", 1)
        method, password = credentials.split(":", 1)
        host, port = endpoint.rsplit(":", 1)
    host, port = host.strip("[]"), int(port)
    if not host or not (1 <= port <= 65535) or not method or not password:
        raise ValueError("invalid Shadowsocks endpoint or credentials")
    return {"tag": "node_ss", "protocol": "shadowsocks",
            "settings": {"servers": [{"address": host, "port": port,
                                      "method": method, "password": password}]}}, host, port


def stream_settings(query, host):
    network = query.get("type", ["tcp"])[0]
    security = query.get("security", ["none"])[0]
    stream = {"network": network, "security": security}
    if security == "tls":
        tls = {"serverName": query.get("sni", [host])[0]}
        if query.get("fp"):
            tls["fingerprint"] = query["fp"][0]
        if query.get("alpn"):
            tls["alpn"] = query["alpn"][0].split(",")
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {"serverName": query.get("sni", [host])[0],
                   "fingerprint": query.get("fp", ["chrome"])[0],
                   "publicKey": query.get("pbk", [""])[0],
                   "shortId": query.get("sid", [""])[0]}
        if query.get("spx"):
            reality["spiderX"] = query["spx"][0]
        stream["realitySettings"] = reality
    if network == "ws":
        ws = {"path": query.get("path", ["/"])[0]}
        if query.get("host"):
            ws["headers"] = {"Host": query["host"][0]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": query.get("serviceName", [""])[0],
                                  "multiMode": query.get("mode", [""])[0] == "multi"}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": query.get("path", ["/"])[0],
                                          "host": query.get("host", [""])[0]}
    return stream


def parse_vless(link):
    parsed = urllib.parse.urlsplit(link)
    query = urllib.parse.parse_qs(parsed.query)
    user_id, host, port = urllib.parse.unquote(parsed.username or ""), parsed.hostname, parsed.port
    if not user_id or not host or not port:
        raise ValueError("invalid VLESS URI")
    user = {"id": user_id, "encryption": query.get("encryption", ["none"])[0]}
    if query.get("flow", [""])[0]:
        user["flow"] = query["flow"][0]
    return {"tag": "node_vless", "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": stream_settings(query, host)}, host, port


def parse_vmess(link):
    item = json.loads(b64decode(link[len("vmess://"):]))
    host, port, user_id = item.get("add"), int(item.get("port", 0)), item.get("id")
    if not host or not user_id or not (1 <= port <= 65535):
        raise ValueError("invalid VMess JSON")
    network, security = item.get("net", "tcp"), item.get("tls", "")
    query = {"type": [network], "security": [security if security in ("tls", "reality") else "none"],
             "sni": [item.get("sni") or item.get("host") or host],
             "path": [item.get("path", "/")], "host": [item.get("host", "")],
             "serviceName": [item.get("path", "")], "fp": [item.get("fp", "chrome")]}
    stream = stream_settings(query, host)
    if network == "tcp" and item.get("type") == "http":
        stream["tcpSettings"] = {"header": {"type": "http"}}
    return {"tag": "node_vmess", "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port,
                                    "users": [{"id": user_id, "alterId": int(item.get("aid", 0)),
                                               "security": item.get("scy", "auto")}]}]},
            "streamSettings": stream}, host, port


def parse_link(link):
    """Accept only encrypted transports with authenticated TLS/Reality or AEAD SS."""
    if link.startswith("ss://"):
        result = parse_ss(link)
        method = result[0]["settings"]["servers"][0]["method"].lower()
        allowed = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}
        if method not in allowed:
            raise ValueError("Shadowsocks cipher is not on the approved AEAD allowlist")
        return result
    if link.startswith("vless://"):
        result = parse_vless(link)
        stream = result[0].get("streamSettings", {})
        security = stream.get("security")
        if security == "tls":
            tls = stream.get("tlsSettings", {})
            if not tls.get("serverName"):
                raise ValueError("TLS server name is required")
            if query.get("allowInsecure", ["false"])[0].lower() in ("1", "true", "yes"):
                raise ValueError("TLS certificate verification cannot be disabled")
        elif security == "reality":
            reality = stream.get("realitySettings", {})
            if not reality.get("serverName") or not reality.get("publicKey") or not reality.get("shortId"):
                raise ValueError("Reality authentication parameters are incomplete")
        else:
            raise ValueError("VLESS without authenticated TLS/Reality is rejected")
        return result
    if link.startswith("vmess://"):
        raise ValueError("VMess is excluded from the strict mobile pool; use VLESS TLS/Reality or AEAD Shadowsocks")
    raise ValueError("unsupported scheme")


def country_code(host):
    """Resolve endpoint and use a public IP geolocation endpoint; unknown stays last."""
    try:
        try:
            ipaddress.ip_address(host)
            ip = host
        except ValueError:
            ip = socket.gethostbyname(host)
        req = urllib.request.Request(
            f"https://ipapi.co/{urllib.parse.quote(ip, safe='')}/country/",
            headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=4) as response:
            code = response.read(32).decode("ascii", "ignore").strip().upper()
        return code if len(code) == 2 and code.isalpha() else "ZZ"
    except Exception as exc:
        print(f"GEO UNKNOWN {host}: {type(exc).__name__}")
        return "ZZ"


def geo_rank(code):
    if code == "DE":
        return 0
    if code in EUROPE_COUNTRIES:
        return 1
    return 2


def real_proxy_check(xray_bin, outbound):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        local_port = sock.getsockname()[1]
    probe = {"log": {"loglevel": "error"},
             "inbounds": [{"listen": "127.0.0.1", "port": local_port,
                           "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
             "outbounds": [outbound]}
    with tempfile.TemporaryDirectory() as tmp:
        config_path = os.path.join(tmp, "probe.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(probe, handle)
        try:
            proc = subprocess.Popen([xray_bin, "run", "-c", config_path],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            return None
        try:
            ready = False
            for _ in range(20):
                if proc.poll() is not None:
                    return None
                try:
                    with socket.create_connection(("127.0.0.1", local_port), timeout=0.2):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.15)
            if not ready:
                return None
            started = time.monotonic()
            # Verify HTTPS and detect the actual VPN exit country through the proxy.
            proxy = f"127.0.0.1:{local_port}"
            result = subprocess.run(
                ["curl", "--silent", "--show-error", "--fail", "--connect-timeout", "4",
                 "--max-time", "10", "--socks5-hostname", proxy, "https://ipwho.is/"],
                capture_output=True, text=True, timeout=12)
            elapsed = round((time.monotonic() - started) * 1000)
            if result.returncode != 0:
                return None
            # Independently verify a second HTTPS destination through the same tunnel.
            # curl validates TLS certificates by default; no -k/--insecure is used.
            second = subprocess.run(
                ["curl", "--silent", "--show-error", "--fail", "--connect-timeout", "4",
                 "--max-time", "8", "--socks5-hostname", proxy,
                 "https://www.cloudflare.com/cdn-cgi/trace"],
                capture_output=True, text=True, timeout=10)
            if second.returncode != 0 or "ip=" not in second.stdout:
                return None
            try:
                geo = json.loads(result.stdout)
                country = str(geo.get("country_code", "ZZ")).upper()
                if geo.get("success") is False or len(country) != 2 or not country.isalpha():
                    country = "ZZ"
            except (ValueError, TypeError):
                country = "ZZ"
            return elapsed, country
        except (subprocess.TimeoutExpired, OSError):
            return None
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)


def build_config(candidates):
    outbounds = []
    for index, (outbound, _host, _port, _latency, _link, _country) in enumerate(candidates, 1):
        outbound["tag"] = f"node_{index}"
        outbounds.append(outbound)
    outbounds.extend([{"tag": "direct", "protocol": "freedom"},
                      {"tag": "block", "protocol": "blackhole"}])
    rules = [{"type": "field",
              "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                     "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"],
              "outboundTag": "direct"}]
    routing = {"domainStrategy": "AsIs", "rules": rules}
    if outbounds[:-2]:
        routing["balancers"] = [{"tag": "free-node-balancer", "selector": ["node_"],
                                 "strategy": {"type": "leastPing",
                                              "settings": {"expected": 2, "maxRTT": 1500,
                                                           "tolerance": 0}}}]
        rules.append({"type": "field", "network": "tcp,udp",
                      "balancerTag": "free-node-balancer"})
    config = {"remarks": f"Germany Strict Security ({len(candidates)} verified nodes)",
              "log": {"loglevel": "warning"}, "stats": {},
              "dns": {"servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]},
              "observatory": {"subjectSelector": ["node_"],
                              "probeURL": "https://www.gstatic.com/generate_204",
                              "probeInterval": "5m"},
              "inbounds": [
                  {"tag": "socks-in", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
                   "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
                   "settings": {"auth": "noauth", "udp": True}},
                  {"tag": "http-in", "port": 10809, "listen": "127.0.0.1", "protocol": "http",
                   "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}],
              "outbounds": outbounds, "routing": routing}
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2, ensure_ascii=False)
        file.write("\n")
    with open("happ_subscription.txt", "w", encoding="utf-8") as file:
        file.write("#profile-title: Germany Strict Security\n")
        for _outbound, _host, _port, _latency, link, _country in candidates:
            file.write(link + "\n")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", default=os.environ.get("XRAY_BIN", "xray"))
    args = parser.parse_args()
    xray_bin = shutil.which(args.xray) or (args.xray if os.path.isfile(args.xray) else None)
    if not xray_bin:
        raise SystemExit("Xray binary not found; refusing TCP-only publication")
    links = fetch_links()
    parsed, seen = [], set()
    for link in links:
        try:
            outbound, host, port = parse_link(link)
            key = json.dumps(outbound, sort_keys=True, separators=(",", ":"))
            if key not in seen:
                seen.add(key)
                parsed.append((outbound, host, port, link))
        except Exception as exc:
            print(f"REJECT insecure/invalid candidate: {type(exc).__name__}: {exc}")
    print(f"Parsed {len(parsed)} unique candidates; resolving endpoint countries")
    print(f"Resolving endpoint countries concurrently ({CHECK_WORKERS} workers)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        geo_results = list(pool.map(lambda item: country_code(item[1]), parsed))
    located = []
    for (outbound, host, port, link), country in zip(parsed, geo_results):
        located.append((outbound, host, port, link, country))
        print(f"GEO {country} {host}:{port}")
    located.sort(key=lambda item: (geo_rank(item[4]), item[4] != "DE", item[1]))
    print("Strict mode: AEAD SS or authenticated TLS/Reality only; verifying proxied HTTPS and actual German exit")
    def check_one(item):
        outbound, host, port, link, country = item
        probe = real_proxy_check(xray_bin, outbound)
        if probe is None:
            return None, f"FAIL {country} {host}:{port}"
        latency, exit_country = probe
        record = (outbound, host, port, latency, link, exit_country)
        return record, f"PASS EXIT={exit_country} {host}:{port} HTTPS={latency}ms"
    verified = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        futures = [pool.submit(check_one, item) for item in located]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            record, message = future.result()
            if record is not None:
                verified.append(record)
            print(f"CHECK {index}/{len(located)} {message}")
    verified.sort(key=lambda item: (geo_rank(item[5]), item[3]))
    german_verified = [item for item in verified if item[5] == "DE"]
    selected = german_verified[:MAX_NODES]
    if not selected:
        raise SystemExit("No verified German VPN exit found; preserving existing German subscription")
    germany_count = sum(1 for item in selected if item[5] == "DE")
    europe_count = sum(1 for item in selected if item[5] in EUROPE_COUNTRIES)
    build_config(selected)
    print(f"RESULT: published {len(selected)} HTTPS-verified nodes; Germany={germany_count}, Europe={europe_count}.")
    if germany_count != len(selected):
        raise SystemExit("Safety check failed: non-German node would be published.")
    print("UDP, long-term availability, and operator privacy are not verified.")


if __name__ == "__main__":
    main()

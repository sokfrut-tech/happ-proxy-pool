#!/usr/bin/env python3
"""Collect public Shadowsocks/VLESS/VMess share links and build an Xray config.

A TCP connect check only confirms that an endpoint accepts TCP connections.
It does NOT prove VPN authentication, end-to-end traffic, UDP support, privacy,
or continuing availability. Public nodes are untrusted.
"""
import base64
import concurrent.futures
import json
import socket
import time
import urllib.parse
import urllib.request

OUTPUT_FILE = "happ_config.json"
SOURCES = ["https://raw.githubusercontent.com/freefq/free/master/v2"]
MAX_NODES = 10
MAX_CANDIDATES = 150
CONNECT_TIMEOUT = 3
USER_AGENT = "HappFreeNodePool/1.0"


def decode_subscription(text):
    """Accept plain share links or a base64-encoded subscription body."""
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
    links = []
    for line in decoded.splitlines():
        line = line.strip()
        if line.startswith(("ss://", "vless://", "vmess://")):
            links.append(line)
    return links


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
    host = host.strip("[]")
    port = int(port)
    if not host or not (1 <= port <= 65535) or not method or not password:
        raise ValueError("invalid Shadowsocks endpoint or credentials")
    return {
        "tag": "node_ss",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{"address": host, "port": port, "method": method, "password": password}]
        },
    }, host, port


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
        reality = {
            "serverName": query.get("sni", [host])[0],
            "fingerprint": query.get("fp", ["chrome"])[0],
            "publicKey": query.get("pbk", [""])[0],
            "shortId": query.get("sid", [""])[0],
        }
        if query.get("spx"):
            reality["spiderX"] = query["spx"][0]
        stream["realitySettings"] = reality

    if network == "ws":
        ws = {"path": query.get("path", ["/"])[0]}
        if query.get("host"):
            ws["headers"] = {"Host": query["host"][0]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": query.get("serviceName", [""])[0],
            "multiMode": query.get("mode", [""])[0] == "multi",
        }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": query.get("path", ["/"])[0],
            " host": query.get("host", [""])[0],
        }
    return stream


def parse_vless(link):
    parsed = urllib.parse.urlsplit(link)
    query = urllib.parse.parse_qs(parsed.query)
    user_id = urllib.parse.unquote(parsed.username or "")
    host, port = parsed.hostname, parsed.port
    if not user_id or not host or not port:
        raise ValueError("invalid VLESS URI")
    user = {"id": user_id, "encryption": query.get("encryption", ["none"])[0]}
    flow = query.get("flow", [""])[0]
    if flow:
        user["flow"] = flow
    outbound = {
        "tag": "node_vless",
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": stream_settings(query, host),
    }
    return outbound, host, port


def parse_vmess(link):
    payload = b64decode(link[len("vmess://"):])
    item = json.loads(payload)
    host = item.get("add")
    port = int(item.get("port", 0))
    user_id = item.get("id")
    if not host or not user_id or not (1 <= port <= 65535):
        raise ValueError("invalid VMess JSON")
    network = item.get("net", "tcp")
    security = item.get("tls", "")
    query = {
        "type": [network],
        "security": [security if security in ("tls", "reality") else "none"],
        "sni": [item.get("sni") or item.get("host") or host],
        "path": [item.get("path", "/")],
        "host": [item.get("host", "")],
        "serviceName": [item.get("path", "")],
        "fp": [item.get("fp", "chrome")],
    }
    stream = stream_settings(query, host)
    if network == "tcp" and item.get("type") == "http":
        stream["tcpSettings"] = {"header": {"type": "http"}}
    outbound = {
        "tag": "node_vmess",
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": user_id,
                    "alterId": int(item.get("aid", 0)),
                    "security": item.get("scy", "auto"),
                }],
            }]
        },
        "streamSettings": stream,
    }
    return outbound, host, port


def parse_link(link):
    if link.startswith("ss://"):
        return parse_ss(link)
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("vmess://"):
        return parse_vmess(link)
    raise ValueError("unsupported scheme")


def tcp_reachable(host, port):
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return round((time.monotonic() - started) * 1000)
    except OSError:
        return None


def build_config(candidates):
    outbounds = []
    for index, (outbound, _host, _port, _latency) in enumerate(candidates, 1):
        outbound["tag"] = f"node_{index}"
        outbounds.append(outbound)

    outbounds.extend([
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ])
    rules = [
        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
    ]
    routing = {"domainStrategy": "AsIs", "rules": rules}
    if outbounds[:-2]:
        routing["balancers"] = [{
            "tag": "free-node-balancer",
            "selector": ["node_"],
            "strategy": {"type": "roundRobin"},
        }]
        rules.append({
            "type": "field",
            "network": "tcp,udp",
            "balancerTag": "free-node-balancer",
        })
    else:
        rules.append({
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": "direct",
        })

    config = {
        "remarks": f"GitHub Free Encrypted Pool ({len(candidates)} TCP-reachable nodes)",
        "log": {"loglevel": "warning"},
        "stats": {},
        "dns": {"servers": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]},
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
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2, ensure_ascii=False)
        file.write("\n")


def main():
    links = fetch_links()
    parsed = []
    for link in links:
        try:
            outbound, host, port = parse_link(link)
            parsed.append((outbound, host, port, None))
        except Exception as exc:
            print(f"Skipping malformed share link: {type(exc).__name__}")

    print(f"Parsed {len(parsed)} protocol configurations; testing TCP endpoints")
    reachable = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        jobs = {
            pool.submit(tcp_reachable, host, port): (outbound, host, port)
            for outbound, host, port, _ in parsed
        }
        for future in concurrent.futures.as_completed(jobs):
            outbound, host, port = jobs[future]
            latency = future.result()
            if latency is not None:
                reachable.append((outbound, host, port, latency))

    reachable.sort(key=lambda item: item[3])
    selected = reachable[:MAX_NODES]
    build_config(selected)
    print(
        f"RESULT: {len(selected)} nodes have open TCP ports. "
        "VPN handshake, end-to-end traffic, UDP and privacy are NOT verified."
    )


if __name__ == "__main__":
    main()

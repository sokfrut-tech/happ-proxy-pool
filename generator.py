#!/usr/bin/env python3
"""Collect public Shadowsocks/VLESS/VMess share links and build an Xray config.

A TCP connect check only confirms that an endpoint accepts TCP connections.
It does NOT prove VPN authentication, end-to-end traffic, UDP support, privacy,
or continuing availability. Public nodes are untrusted.
"""
import base64
import concurrent.futures
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
SOURCES = ["https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt", "https://raw.githubusercontent.com/freefq/free/master/v2"]
MAX_NODES = 10
MAX_CANDIDATES = 80
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
            "host": query.get("host", [""])[0],
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


def real_proxy_check(xray_bin, outbound):
    """Require a real HTTPS request through an isolated Xray SOCKS inbound."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        local_port = sock.getsockname()[1]
    probe = {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [outbound],
    }
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
            result = subprocess.run(
                ["curl", "--silent", "--show-error", "--fail", "--connect-timeout", "3",
                 "--max-time", "7", "--socks5-hostname", f"127.0.0.1:{local_port}",
                 "https://www.cloudflare.com/cdn-cgi/trace"],
                capture_output=True, text=True, timeout=9)
            elapsed = round((time.monotonic() - started) * 1000)
            if result.returncode == 0 and "ip=" in result.stdout and "http=" in result.stdout:
                return elapsed
            return None
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
    for index, (outbound, _host, _port, _latency, _link) in enumerate(candidates, 1):
        outbound["tag"] = f"node_{index}"
        outbounds.append(outbound)

    outbounds.extend([
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ])
    rules = [
        {
            "type": "field",
            "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"],
            "outboundTag": "direct",
        },
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
        "remarks": f"GitHub Free Encrypted Pool ({len(candidates)} HTTPS-verified nodes)",
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
        file.write("\\n")

    # Happ mobile subscriptions should be share-link lists, not a full Xray
    # core config with localhost inbounds that bypasses Happ's TUN setup.
    with open("happ_subscription.txt", "w", encoding="utf-8") as file:
        file.write("#profile-title: Free Verified Pool\\n")
        for _outbound, _host, _port, _latency, link in candidates:
            file.write(link + "\\n")


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
            print(f"Skipping unsupported/malformed share link: {type(exc).__name__}")
    print(f"Parsed {len(parsed)} unique SS/VLESS/VMess candidates; testing real HTTPS proxy traffic")
    verified = []
    for index, (outbound, host, port, link) in enumerate(parsed, 1):
        latency = real_proxy_check(xray_bin, outbound)
        if latency is not None:
            verified.append((outbound, host, port, latency, link))
            print(f"PASS {index}/{len(parsed)} {host}:{port} HTTPS={latency}ms")
        else:
            print(f"FAIL {index}/{len(parsed)} {host}:{port}")
        if len(verified) >= MAX_NODES:
            break
    verified.sort(key=lambda item: item[3])
    if not verified:
        raise SystemExit("No node passed a real proxied HTTPS request; preserving existing config")
    build_config(verified)
    print(f"RESULT: published {len(verified)} nodes that completed a proxied HTTPS request.")
    print("UDP, long-term availability, and operator privacy are not verified.")


if __name__ == "__main__":
    main()

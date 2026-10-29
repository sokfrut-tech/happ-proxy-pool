# Happ-compatible Android client (prototype)

This is a separate Android client companion to the proxy-pool project. It does **not** modify or inject code into Happ.

## Current milestone

- Android project scaffold and CI build.
- Subscription line parser for VLESS, VMess, Trojan, Shadowsocks and SOCKS URI schemes.
- No credentials are sent to telemetry; there is no telemetry implementation.
- VPN tunnel is intentionally not enabled yet. A real VPN requires a single `VpnService` plus an integrated Xray engine and explicit socket protection. The UI must not claim that a tunnel is active until the engine confirms it.

## Architecture

1. UI/import layer: accepts a subscription URL or pasted URI list.
2. Parser: validates supported URI schemes and reports malformed/unsupported rows without logging secrets.
3. Core adapter (next milestone): isolate Xray/libXray behind an interface. Pin an audited upstream release and its licence/checksum before adding binaries.
4. VPN service (next milestone): one Android `VpnService`, foreground notification, revoke/stop cleanup, protected upstream sockets.
5. DPI experiments (later): selectable, opt-in transport strategies, each independently measurable. Do not claim a strategy works on a carrier until tested on a real SIM.

## Build

From this directory with JDK 17 and Android SDK installed:

```sh
gradle assembleDebug testDebugUnitTest
```

CI runs the same tasks. The debug APK is a development scaffold, **not a working VPN client**.

## Security constraints

- Never commit subscription URLs containing credentials, private keys, UUIDs or server secrets.
- Do not log raw imported links or generated Xray configuration.
- Do not silently change DNS, route all traffic, or activate always-on VPN.
- Keep the existing proxy-pool branches and production subscription unchanged.

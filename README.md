# Happ Proxy Pool

GitHub Actions checks public HTTP CONNECT proxy lists hourly and generates `happ_config.json`.

## Generated configuration

After a successful workflow run, import this raw file into Happ:

`https://raw.githubusercontent.com/sokfrut-tech/happ-proxy-pool/main/happ_config.json`

## Important security notice

This project uses **public, unauthenticated proxy servers**. They are untrusted and may log connection metadata, inject content into unencrypted HTTP traffic, or stop working without notice. The generator verifies that an HTTPS CONNECT tunnel can reach Cloudflare and that TLS certificate validation succeeds; this is only a connectivity check, not a security audit or guarantee of privacy. Do not use public proxies for banking, passwords, confidential work, or other sensitive traffic. Prefer a reputable paid VPN/proxy provider for that.

The generated file contains server addresses and ports only; it does not contain credentials. If no proxies pass verification, a valid direct-only configuration is generated instead of leaving a stale pool behind.

## Automation

- Runs hourly at minute 15 (UTC).
- Also runs after commits to `main`.
- Can be started manually from the Actions tab.

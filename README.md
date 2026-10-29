# Happ Free Encrypted Node Pool

GitHub Actions periodically fetches public Shadowsocks, VLESS and VMess share links and converts supported links into an Xray/Happ JSON configuration.

## Import into Happ

After a successful workflow run, import this raw file:

`https://raw.githubusercontent.com/sokfrut-tech/happ-proxy-pool/main/happ_config.json`

## What the checks mean

The generator parses supported share-link formats and checks whether each server accepts a TCP connection from GitHub Actions. **An open TCP port does not prove that authentication succeeds, that VPN traffic works end-to-end, that UDP works, or that a node will remain online.** The current workflow does not perform a protocol handshake or UDP test.

Public nodes are operated by unknown third parties. They can log metadata, intercept unencrypted traffic, inject content, or disappear at any time. Do not use them for banking, passwords, confidential work, or sensitive accounts. Use a reputable provider if privacy or reliability matters.

GitHub Actions is only the free automation host within GitHub's usage limits. It does not provide VPN egress bandwidth or turn GitHub into a VPN server.

## Automation

- Runs hourly at minute 15 (UTC).
- Runs after commits to `main`.
- Can be started manually from Actions.

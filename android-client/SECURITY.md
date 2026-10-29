# Security notes

- This prototype currently has no VPN tunnel and no networking code.
- Imported proxy links contain secrets. The parser deliberately returns counts only; do not add raw-link logging, analytics, crash breadcrumbs, or clipboard uploads.
- Before integrating Xray/libXray, pin the upstream commit/release, verify licence compatibility and checksums, produce an SBOM, and scan dependencies.
- VPN implementation must use Android's single active VpnService model, protect upstream sockets against routing loops, and close TUN descriptors on revoke/stop.
- DPI strategy experiments must be opt-in and must not weaken TLS certificate validation or encryption.

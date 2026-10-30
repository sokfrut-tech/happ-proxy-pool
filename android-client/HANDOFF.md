# HANDOFF — Happ-compatible Android client
Last updated: 2026-10-30
Repository: sokfrut-tech/happ-proxy-pool
Working branch: feature/happ-compatible-android-client
Base branch: prototype/xray-real-checks

## Purpose
Build a separate Android client with a Happ-like user experience and Xray-based proxy support, because injecting a native DPI/VPN engine into the official Happ app is not currently feasible. Keep all work isolated on this feature branch. Do not modify production subscriptions or the base branch.

## Verified repository state
- Android scaffold lives in android-client/.
- Kotlin UI and URI parser exist.
- Supported parser schemes: VLESS, VMess, Trojan, Shadowsocks (ss), SOCKS/SOCKS5.
- Parser returns aggregate counts only; it must not print or expose raw credentials.
- No Xray/libXray runtime is integrated yet.
- No Android VpnService/tunnel is integrated yet.
- The connect control is intentionally disabled. Do not claim the app is a functioning VPN.
- No DPI bypass strategy is implemented or verified on a real carrier.

## CI evidence
Successful GitHub Actions run:
- Run ID: 40973304226
- Run number: 5
- Commit: bf5080184389cc25eb79e0c314357f4e1166f17f
- URL: https://github.com/sokfrut-tech/happ-proxy-pool/actions/runs/40973304226
- All steps succeeded: Android SDK install, unit tests, assembleDebug, artifact upload.
- Artifact: happ-compatible-debug (4,910,349 bytes)
- Artifact ID: 12940918990
- SHA-256: c213705a71354c655fe6398b2a60829ef42c37f6c4456e08628139b5dea84ae8
- Artifact is a scaffold build, not a usable VPN client.
Earlier runs 1–4 failed due obsolete Android SDK setup or related initial CI setup. Run 5 fixed this.

## Changes after the successful build
A subsequent commit added explicit clipboard and manual text import:
- Commit: e926f28831efb15d72a470c6468beb7665a32c6a
- File: android-client/app/src/main/java/org/sokfrut/happclient/MainActivity.kt
- Adds user-triggered clipboard import and manual paste dialog.
- Displays only parser aggregate summary; does not log raw links.
- IMPORTANT: this commit was made after run #5. It has NOT yet been verified by CI in the evidence above. First action for the next engineer/agent: inspect latest branch HEAD and Actions runs, then build/test this exact commit.

## Architecture constraints
1. Official Happ config/subscription cannot inject native Android code or install another VPN engine.
2. Android generally allows only one active VpnService per user/profile. Avoid running Happ and this client VPN simultaneously.
3. This client should own one VpnService and one tunnel engine.
4. Protect upstream sockets with VpnService.protect() (or the exact equivalent in the chosen library) to avoid routing loops.
5. Ask for Android VPN consent via VpnService.prepare(); provide foreground notification and robust stop/revoke cleanup.
6. Never show Connected until the Xray engine confirms a live tunnel.
7. DPI experiments must be opt-in, isolated and measurable. Do not assert carrier compatibility without tests on a real Megafon SIM.

## Key upstream references
- libXray: https://github.com/XTLS/libXray
- Xray-core: https://github.com/XTLS/Xray-core
- Android VpnService API: https://developer.android.com/reference/android/net/VpnService
- Android VPN guide: https://developer.android.com/develop/connectivity/vpn
Pin exact upstream releases/commits. Check licence, provenance, checksum and ABI compatibility before adding native binaries. Do not download arbitrary prebuilt binaries into the repository.

## Immediate next steps
1. Inspect latest branch HEAD and run CI for commit e926f28831efb15d72a470c6468beb7665a32c6a. Fix any Kotlin/Android issues and confirm tests + APK artifact.
2. Review parser correctness against real-world URI formats (including URL-safe/unpadded VMess base64, Shadowsocks SIP002 variants, IPv6 literals, escaped fragments, malformed input). Add tests; never include real user secrets in fixtures.
3. Add clipboard/import size limits and clear user-facing validation. Keep import explicit; do not read clipboard automatically in background.
4. Study current libXray API and choose a pinned stable version. Document exact API calls and Android ABIs before integration.
5. Implement a core adapter behind an interface; keep UI independent from native engine.
6. Implement a single VpnService with consent, foreground notification, socket protection, DNS/routing configuration, stop/revoke cleanup and truthful state reporting.
7. Add configuration conversion only after validating each supported URI type against the pinned Xray version.
8. Run security review: permissions, exported components, cleartext traffic, logging/secrets, dependency provenance, native library integrity, backup policy and APK contents.
9. Test on Android device and real Megafon SIM. CI cannot prove network/DPI bypass.
10. Only then produce and label a release APK as a testable VPN client.

## Handoff rules for other AI agents
- Read this file and android-client/README.md and android-client/SECURITY.md first.
- Inspect Git history and actual Actions logs; do not rely solely on this handoff if newer commits exist.
- Work only on feature/happ-compatible-android-client unless explicitly instructed otherwise.
- Never overwrite production branch/subscription or commit private proxy links, UUIDs, passwords, tokens or certificates.
- Do not claim build, install, VPN, security or carrier success without fresh evidence.
- Before handing work onward, update this file with date, commit SHA, tests, workflow run ID, artifact ID/hash, known defects and exact next step.

## Update 2026-10-30 (независимая проверка)
- Проверен HEAD 15318c1: CI run 41002253188 — success (unit tests, assembleDebug, upload). Артефакт happ-compatible-debug, 4 912 209 байт, срок не истёк.
- Исправлено в 74917b3: старый формат ss:// (вся часть до # в base64) теперь распознаётся; ввод больше 512 КБ и строки больше 8 КБ отклоняются. Добавлены тесты.
- CI run 41002731575 на 74917b3 — success (unit tests, assembleDebug, upload), артефакт happ-compatible-debug, 4 912 968 байт.
- SHA-256 артефакта из сессии не сверял: скачивание блоба недоступно. Сверить вручную, если нужно.
- VPN и Xray по-прежнему не интегрированы; подключение отключено, это честно.

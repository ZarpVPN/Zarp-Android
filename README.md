# Zarp for Android

[![Android](https://github.com/ZarpVPN/Zarp-Android/actions/workflows/android.yml/badge.svg)](https://github.com/ZarpVPN/Zarp-Android/actions/workflows/android.yml)
[![Release](https://img.shields.io/github/v/release/ZarpVPN/Zarp-Android)](https://github.com/ZarpVPN/Zarp-Android/releases/latest)
[![License: GPL-3.0](https://img.shields.io/github/license/ZarpVPN/Zarp-Android)](LICENSE)

Cloudflare WARP or your own proxy server on networks that block them. Android version of [Zarp](https://github.com/ZarpVPN/Zarp): it finds a DPI strategy, checks it twice, remembers the exact connection and connects.

![Zarp for Android: home, strategies and settings](docs/screenshots.png)

## Download

| Platform | Download | Requirements |
|---|---|---|
| **Android** | [**APK**](https://github.com/ZarpVPN/Zarp-Android/releases/latest) · [all releases](https://github.com/ZarpVPN/Zarp-Android/releases) | Android 8.0+, no root, no WARP app needed |
| **Windows** | [**Zarp.exe**](https://github.com/ZarpVPN/Zarp/releases/latest/download/Zarp.exe) · [all releases](https://github.com/ZarpVPN/Zarp/releases) · [source](https://github.com/ZarpVPN/Zarp)| Windows 10/11 x64, administrator rights. [Cloudflare WARP](https://one.one.one.one/) is installed by Zarp if it is missing |
| **macOS** | [**DMG**](https://github.com/ZarpVPN/Zarp-MacOS/releases/latest) · [all releases](https://github.com/ZarpVPN/Zarp-MacOS/releases) · [source](https://github.com/ZarpVPN/Zarp-MacOS)| Apple Silicon (M1 or newer), macOS 14+, an administrator password once. No WARP app needed

[![Android release](https://img.shields.io/github/v/release/ZarpVPN/Zarp-Android?label=Android)](https://github.com/ZarpVPN/Zarp-Android/releases/latest)
[![Windows release](https://img.shields.io/github/v/release/ZarpVPN/Zarp?label=Windows)](https://github.com/ZarpVPN/Zarp/releases/latest)
[![macOS release](https://img.shields.io/github/v/release/ZarpVPN/Zarp-MacOS?label=macOS)](https://github.com/ZarpVPN/Zarp-MacOS/releases/latest)

## 💬 Community & Support
Have questions, ideas, or feedback?
Join our [Zarp Community](https://github.com/orgs/ZarpVPN/discussions)!

- ❓ Ask questions and get help
- 💡 Suggest new features
- 📢 Follow announcements
- 🗳️ Vote on upcoming improvements


## Features

- **One button.** The first tap searches for the fastest working strategy, later taps connect right away.
- **No WARP app needed.** Zarp talks to WARP itself over MASQUE (HTTP/3, with HTTP/2 as a fallback) and registers a free WARP device on first use.
- **WARP+.** Link an existing subscription in Settings → WARP+ or Server and endpoints → WARP+. Check the account type, apply a masked license key and reconnect. Keys are never stored in settings or logs.
- **Registration on restricted networks.** If direct registration fails with a network error, eligible TLS strategies are tried against the Cloudflare API. Country filters, the selected strategy and confirmed results determine priority. Registration and tunnel verification remain independent; an interrupted enrollment resumes the same device.
- **Socket-compatible DPI strategies.** QUIC fakes use the real connection's UDP socket. TLS split/disorder applies to every server dial; QUIC fakes precede the first datagram of every flow.
- **Honest testing.** Every candidate is checked twice. WARP tests rotate endpoints and require `warp=on` or `warp=plus`; imported servers require a valid HTTPS response through that server.
- **Self-healing.** If the saved strategy stops working, Zarp tries the other verified ones before searching again. After a network change it reconnects and applies the strategy again.
- **No root.** A regular Android VPN. Nine WireGuard/raw injection built-ins are removed; raw custom profiles explain their limitations. TTL strategies are disabled when the device cannot set the required socket option.
- **Per-app proxy.** Settings → Per-app proxy tunnels only selected apps. An empty or uninstalled selection refuses to connect instead of tunneling every app.
- **Custom servers and subscriptions.** Import VLESS, Trojan or Hysteria2 links, including VLESS XHTTP and TLS ECH, or an HTTPS subscription. Choose one server or Automatic. Subscriptions have an offline cache, refresh and delete controls.
- **Strategy/server pairs.** Scans test each strategy against every compatible server, confirm pairs inline, and remember the exact pair. Plain connections require an explicit option and show a yellow "Connection without a strategy" label.
- **Editable routing.** Settings → Routing settings provides LAN/country presets with Direct, Proxy and Block rules. Download GeoIP/GeoSite `.dat` databases from editable HTTPS sources, or use the bundled country IP ranges.
- **Country filters.** A compact filter button selects All or multiple countries (Russia, Iran, China). Filters apply to the list, quick/full scans and automatic fallback. Direct strategies are hidden and excluded when countries are selected.
- **Your language.** English, Русский, Español, Português, 中文, हिन्दी, Français, Deutsch and فارسی. Persian uses right-to-left layouts; connection links, addresses, license input and technical logs retain their direction. Zarp follows the system language, and the globe button switches it on the fly.
- **Licenses.** Settings → Licenses shows the bundled component notices and Zarp license offline.

## Requirements

- Android 8.0 or later (arm64, armv7 or x86_64)

## Usage

1. Download the APK from [Releases](https://github.com/ZarpVPN/Zarp-Android/releases/latest) and install it.
2. Tap the power button. Accept the WARP terms and the VPN request the first time.
3. The first search takes about a minute. After that Zarp connects with the saved strategy.

The Strategies tab shows strategies or strategy/server pairs with search, country filters and their results. Tap one to connect with it or test it again, or tick several and test them together. **Quick scan** stops after 3 independently confirmed strategies/pairs (adjustable in Settings); a failed confirmation continues the search. **Full scan** tests every candidate. WARP retains separate scan and recheck phases. Failures measured through a foreign VPN never overwrite saved WARP results.

A bounded traffic check runs every seven seconds while connected. A failed check starts the normal recovery flow: retry the selected connection, try verified alternatives, then scan again.

Connection and routing settings take effect on the next connection. A changed server clears saved test results. Country tags identify candidates to test, not verified country-wide bypasses; providers and DPI deployments differ. See [connection settings](docs/connection-settings.md) for supported links, routing data and limitations.

> [!NOTE]
> Turn off any other VPN before a search. Android runs one VPN at a time, and a scan through someone else's tunnel measures that tunnel, not your network.

## Strategies

| Strategy | Transport | Android |
|---|---|---|
| fake google ×3 / ×6 / ×10 / ×12, fake vk ×6, fakes google + vk | MASQUE / HTTP3 | yes |
| fake google / vk ttl=4 ×6 | MASQUE / HTTP3 | yes, TTL is lowered for the fakes only |
| split 1,midsld / 1,host / 1,sld / 1,endhost | TLS / TCP | yes |
| disorder 1,midsld | TLS / TCP | yes when TCP TTL is available |
| Direct (no desync) | HTTP3 and HTTP2 | WARP control tests only |

QUIC candidates also pair with Hysteria2 and XHTTP whose ALPN is exactly `h3`.
TLS candidates pair with VLESS/Trojan TLS or Reality and TCP XHTTP. WireGuard,
badsum, TCP MD5, sequence overlap and hostfakesplit require unavailable transports
or raw injection and are excluded from built-in scans. See the complete
[support and migration notes](docs/connection-settings.md).

On one Russian home network the fake google and fake vk strategies connect in 150 to 300 ms, while a direct connection stalls right after the QUIC handshake. Results depend on the network, which is why Zarp tests instead of guessing.

Your own strategies go into Settings in the same format as the desktop `strategies.txt`:

```
# name | transport (h3, h2) | zapret2 profile args
My QUIC | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=8
```

## How it works

```
apps -> VpnService (TUN) -> hev-socks5-tunnel -> SOCKS5 on 127.0.0.1 -> MASQUE core -> Cloudflare WARP
```

The MASQUE core is [usque](https://github.com/Diniboy1123/usque) built with gomobile. Before every QUIC dial the core asks the app for a UDP socket. The app creates it, sends the strategy's fake packets through it and hands the same socket back, and quic-go sends the real Initial from there. Zarp's own traffic is excluded from the VPN, so the tunnel never loops into itself.

Server mode uses sing-box behind the same VPN. XHTTP adds an in-process
Xray-core SOCKS bridge with random loopback port and credentials; the system
dialer applies the selected pair's strategy. UDP is carried inside the XHTTP
stream. Secondary download destinations are refused; matching downloadSettings
must use the paired host, port and outer transport.

A search runs each strategy on its own tunnel and endpoint and fetches `cdn-cgi/trace` through it. Score is `connect time + 4 × ping`, the same as on Windows. The fake packets are the real captures from [zapret2](https://github.com/bol-van/zapret2) (`files/fake`).

### Privacy

Zarp has no telemetry and does not collect personal data. Its connection checks and tunnel setup use:

- `api.cloudflareclient.com`, to register/enroll a WARP device and, on request, read the account or link a WARP+ subscription; protected registration can use Cloudflare's published orchestration IPs with the same verified TLS hostname;
- WARP MASQUE endpoints (`162.159.198.1`, `162.159.198.2`, or your custom endpoints), which carry the WARP tunnel;
- your imported server instead of WARP when that mode is enabled;
- `https://www.cloudflare.com/cdn-cgi/trace`, through the selected tunnel, to check connectivity and measure latency.

Apps use the configured VPN DNS servers. The optional proxy/routing engine uses the system resolver to find the server and the first configured VPN DNS server through the proxy to resolve destinations. Traffic excluded by app selection or a Direct rule goes directly over the underlying network. With routing rules enabled, ordinary app DNS is also handled by that engine. Explicit GeoIP/GeoSite downloads connect to the URLs selected in routing settings (by default, GitHub release downloads).

WARP is covered by the [Cloudflare WARP privacy policy](https://www.cloudflare.com/application/privacypolicy/).

See the [Windows release parity audit](docs/windows-release-parity.md) for the release inventory, platform differences and current verification.

## Building

Needs JDK 17+, Go (version in `core/go.mod`) and the Android SDK with platform `android-37.0`, build-tools 36.1.0 and NDK 29.0.14206865.

```sh
git clone --recursive https://github.com/ZarpVPN/Zarp-Android
cd Zarp-Android
./gradlew test lint assembleDebug   # app/build/outputs/apk/debug/app-debug.apk
```

The Go core is built into `app/libs/zarpcore.aar` by the `buildGoCore` task; its own tests run with `cd core && go test -tags=with_quic,with_utls,http2legacy ./zarpcore`. Set `ZARP_TEST_XRAY` to the official v26.9.30 server binary to run all XHTTP traffic tests. CI uses `scripts/fetch-test-xray.sh` and verifies the pinned release SHA-256. Kotlin tests assert 24 outbound golden files that Go feeds to the real engines. The `http2legacy` tag retains the x/net/http2 implementation required by sing-box 1.13 on Go 1.27+. If `dl.google.com` is blocked for you, add `zarp.googleMirror=https://maven.aliyun.com/repository/google` to `local.properties`.

Debug builds install next to the release as "Zarp debug" and accept commands over adb, which is handy for testing strategies without tapping:

```sh
adb shell am broadcast -a io.github.feg55.zarp.DEBUG -n io.github.feg55.zarp.debug/io.github.feg55.zarp.DebugCommandReceiver --es cmd "'test warp-q-google6,direct'"
# quick | full | connect | disconnect | cancel | test <id,id> | use <id>
```

GitHub Actions builds every push. A `v*` tag builds a release APK signed with the key from the repository secrets and publishes it with its SHA-256.

### Translations

All strings live in [`app/src/main/assets/lang`](app/src/main/assets/lang), one `key = value` file per language with `en.txt` as the reference, in the same format as the desktop Zarp. Strings shared with the desktop app keep its keys and wording. The tests check that every language has the same keys and placeholders as English.

## License

GPL-3.0, see [LICENSE](LICENSE). The Windows Zarp stays under MIT.

Bundled components: [usque](https://github.com/Diniboy1123/usque) (MIT, vendored in `core/third_party/usque`), [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) (MIT), [sing-box](https://github.com/SagerNet/sing-box) (GPL-3.0-or-later), country allocations from [ipverse](https://github.com/ipverse/country-ip-blocks) (CC0), fake packets from [zapret2](https://github.com/bol-van/zapret2) (MIT), plus quic-go, connect-ip-go, wireguard-go and gVisor under their own licenses. License texts are in [`licenses`](licenses).

[Xray-core v26.9.30](https://github.com/XTLS/Xray-core/releases/tag/v26.9.30)
is pinned at `b26a91de4f32` and licensed MPL-2.0. Its source has no attached
Exhibit B notice, so MPL section 3.3 permits combination with this GPL-3.0 app.
The full text and the Android `anet` stand-in note are in
[`licenses/xray-core.txt`](licenses/xray-core.txt).

Cloudflare and WARP are trademarks of Cloudflare, Inc. Zarp is an independent project, not affiliated with or endorsed by Cloudflare.

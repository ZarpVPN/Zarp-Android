# Zarp for Android

[![Android](https://github.com/feg55/Zarp-Android/actions/workflows/android.yml/badge.svg)](https://github.com/feg55/Zarp-Android/actions/workflows/android.yml)
[![Release](https://img.shields.io/github/v/release/feg55/Zarp-Android)](https://github.com/feg55/Zarp-Android/releases/latest)
[![License: GPL-3.0](https://img.shields.io/github/license/feg55/Zarp-Android)](LICENSE)

One-tap Cloudflare WARP for networks that block it. Android version of [Zarp](https://github.com/feg55/Zarp): it finds a strategy that gets the WARP handshake through DPI, checks it twice, remembers it and connects.

![Zarp for Android: home, strategies and settings](docs/screenshots.png)

## Features

- **One button.** The first tap searches for the fastest working strategy, later taps connect right away.
- **No WARP app needed.** Zarp talks to WARP itself over MASQUE (HTTP/3, with HTTP/2 as a fallback) and registers a free WARP device on first use.
- **The same strategies as on Windows.** Fake QUIC Initials of google.com and vk.com are sent from the tunnel's own UDP socket right before the real handshake, so DPI sees them on the same connection.
- **Honest testing.** Every candidate is checked twice. WARP tests rotate endpoints and require `warp=on` or `warp=plus`; imported servers require a valid HTTPS response through that server.
- **Self-healing.** If the saved strategy stops working, Zarp tries the other verified ones before searching again. After a network change it reconnects and applies the strategy again.
- **No root.** A regular Android VPN. Strategies that need raw sockets are shown as unsupported instead of being faked.
- **Per-app proxy.** Settings → Per-app proxy tunnels only selected apps. An empty or uninstalled selection refuses to connect instead of tunneling every app.
- **Custom servers.** Strategies → Endpoints and protocol accepts numeric WARP endpoints or an imported VLESS, Hysteria2 or Trojan link. Imported servers replace WARP and do not require WARP registration.
- **Editable routing.** Settings → Routing settings provides LAN/country presets with Direct, Proxy and Block rules. Download GeoIP/GeoSite `.dat` databases from editable HTTPS sources, or use the bundled country IP ranges.
- **Country filters.** A compact filter button selects All or multiple countries (Russia, Iran, China). Filters apply to the list, quick/full scans and automatic fallback. Direct strategies are hidden and excluded when countries are selected.
- **Your language.** English, Русский, Español, Português, 中文, हिन्दी, Français and Deutsch. Zarp follows the system language (English if it is not on the list), and the globe button switches it on the fly.

## Requirements

- Android 8.0 or later (arm64, armv7 or x86_64)

## Usage

1. Download the APK from [Releases](https://github.com/feg55/Zarp-Android/releases/latest) and install it.
2. Tap the power button. Accept the WARP terms and the VPN request the first time.
3. The first search takes about a minute. After that Zarp connects with the saved strategy.

The Strategies tab shows every strategy with its result. Tap one to connect with it or test it again, or tick several and test them together. **Quick scan** stops after 3 working strategies (adjustable in Settings), **Full scan** tests all of them.

Connection and routing settings take effect on the next connection. A changed server clears saved test results. Country tags identify candidates to test, not verified country-wide bypasses; providers and DPI deployments differ. See [connection settings](docs/connection-settings.md) for supported links, routing data and limitations.

> [!NOTE]
> Turn off any other VPN before a search. Android runs one VPN at a time, and a scan through someone else's tunnel measures that tunnel, not your network.

## Strategies

| Strategy | Transport | Android |
|---|---|---|
| fake google ×3 / ×6 / ×10 / ×12, fake vk ×6, fakes google + vk | MASQUE / HTTP3 | yes |
| fake google / vk ttl=4 ×6 | MASQUE / HTTP3 | yes, TTL is lowered for the fakes only |
| fake google badsum ×6 | MASQUE / HTTP3 | no, needs raw sockets |
| split 1,midsld / 1,host / 1,sld / 1,endhost and disorder 1,midsld | MASQUE / HTTP2 | yes |
| fake md5, seqovl, badseq, hostfakesplit | MASQUE / HTTP2 | no, needs raw sockets |
| WireGuard strategies | WireGuard | not yet |
| Direct (no desync) | HTTP3 and HTTP2 | yes, the control test |

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

A search runs each strategy on its own tunnel and endpoint and fetches `cdn-cgi/trace` through it. Score is `connect time + 4 × ping`, the same as on Windows. The fake packets are the real captures from [zapret2](https://github.com/bol-van/zapret2) (`files/fake`).

### Privacy

Zarp has no telemetry and does not collect personal data. Its connection checks and tunnel setup use:

- `api.cloudflareclient.com`, once, to register a WARP device;
- WARP MASQUE endpoints (`162.159.198.1`, `162.159.198.2`, or your custom endpoints), which carry the WARP tunnel;
- your imported server instead of WARP when that mode is enabled;
- `https://www.cloudflare.com/cdn-cgi/trace`, through the selected tunnel, to check connectivity and measure latency.

Apps use the configured VPN DNS servers. The optional proxy/routing engine uses the system resolver to find the server and the first configured VPN DNS server through the proxy to resolve destinations. Traffic excluded by app selection or a Direct rule goes directly over the underlying network. With routing rules enabled, ordinary app DNS is also handled by that engine. Explicit GeoIP/GeoSite downloads connect to the URLs selected in routing settings (by default, GitHub release downloads).

WARP is covered by the [Cloudflare WARP privacy policy](https://www.cloudflare.com/application/privacypolicy/).

## Building

Needs JDK 17+, Go (version in `core/go.mod`) and the Android SDK with platform `android-37.0`, build-tools 36.1.0 and NDK 29.0.14206865.

```sh
git clone --recursive https://github.com/feg55/Zarp-Android
cd Zarp-Android
./gradlew test lint assembleDebug   # app/build/outputs/apk/debug/app-debug.apk
```

The Go core is built into `app/libs/zarpcore.aar` by the `buildGoCore` task; its own tests run with `cd core && go test -tags=with_quic,with_utls,http2legacy ./zarpcore`. The `http2legacy` tag retains the x/net/http2 implementation required by sing-box 1.13 on Go 1.27+. If `dl.google.com` is blocked for you, add `zarp.googleMirror=https://maven.aliyun.com/repository/google` to `local.properties`.

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

Cloudflare and WARP are trademarks of Cloudflare, Inc. Zarp is an independent project, not affiliated with or endorsed by Cloudflare.

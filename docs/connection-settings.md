# Connection settings

Settings are saved locally and applied on the next connection. A server or endpoint change clears previous results. Release and debug builds have separate settings.

## Per-app proxy

Open **Settings → Per-app proxy**, enable **Proxy selected apps only**, then toggle each app to include. App icons appear beside their names and load as rows become visible. Search accepts names and package IDs. The list contains enabled apps with Internet permission, including system apps and apps without launcher activities.

Zarp itself is always outside its own VPN. Android's allowlist and denylist are never mixed. Empty selections, or selections whose apps have all been uninstalled, refuse to establish the VPN. Changes require reconnecting; they do not interrupt an active session.

## Endpoints and imported servers

Open **Strategies → Endpoints and protocol**.

For WARP, enter one numeric `IP:port` or `[IPv6]:port` per line. Blank lines and `#` comments are accepted. An empty list restores the registered/default WARP endpoints. These must be compatible MASQUE endpoints with the pinned WARP key; this field cannot turn an arbitrary proxy into WARP. A scan rotates through the custom list, including rechecks. With a single address, rechecks use a fresh connection but cannot isolate the server endpoint. Persistent connections use the last successfully tested address from that list.

Enable **Use my server instead of WARP** to import one server link:

| Protocol | Supported parameters |
| --- | --- |
| VLESS | UUID, TCP, WebSocket, gRPC, HTTPUpgrade, TLS, Reality (`pbk`, `sid`), Vision (`flow=xtls-rprx-vision`), uTLS fingerprint |
| Trojan | Password, TLS, TCP, WebSocket, gRPC, HTTPUpgrade |
| Hysteria2 / hy2 | Password, TLS/SNI, ALPN, Salamander obfuscation |

Common parameters include `sni`, `peer`, `alpn`, `insecure`/`allowInsecure`. Transport fields include `type`, `path`, `host` and `serviceName`. Unsupported transports/parameters are rejected rather than silently discarded. Import is for a single link, not subscriptions, XHTTP, port hopping or arbitrary JSON. TLS certificate verification is enabled unless the imported link explicitly disables it. Passwords and UUIDs are not placed in strategy labels or logs; the saved link stays in private app storage with Android backup disabled.

The proxy engine is [sing-box 1.13.14](https://github.com/SagerNet/sing-box/tree/v1.13.14), GPL-3.0-or-later; its license is in `licenses/sing-box.txt`. Imported servers do not register a WARP account or show WARP terms. Their check requires a valid HTTPS trace response, while WARP still requires `warp=on` or `warp=plus`.

For an imported server, connection time includes the first successful HTTPS response. If your server has no IPv6 Internet access, disable **IPv6** in Settings before connecting.

## Routing presets and GeoIP/GeoSite

Open **Settings → Routing settings**, enable rules, and select one preset. The built-in LAN, Russia, Iran and China presets send the listed private/country IP ranges directly; everything else uses the proxy. Existing LAN/country exclusions migrate into **My rules**, preserving the exact previous selection. Routing presets are independent of the DPI strategy country filter.

The pencil beside every preset opens **Direct / Proxy / Block**. Edit one rule per line and save. You can create and delete your own presets, and reset built-in presets. Rules take effect on the next connection. Priority is **Block, then Proxy, then Direct**; nonmatching traffic goes through the proxy. All routing runs in the proxy core, including LAN, so a block/proxy rule cannot be skipped by an Android LAN route exclusion.

Supported rules:

| Rule | Matches |
| --- | --- |
| `geoip:cn`, `geoip:private` | GeoIP category; private/local IPv4 and IPv6 ranges are built in |
| `geosite:youtube` | GeoSite category |
| `geosite:google@cn` | Category entries with the specified attribute; `@!cn` excludes it |
| `domain:example.com` or `example.com` | Domain and subdomains |
| `full:example.com` | Exact domain |
| `keyword:example` | Domain substring |
| `regexp:pattern` | RE2 domain expression |
| `1.2.3.4`, `2001:db8::/32` | IPv4/IPv6 address or CIDR |

Blank lines and lines starting with `#` are ignored. Use punycode for international domain names. Unknown categories and unavailable databases cause a connection error instead of silently ignoring a rule. Syntax is validated when saving; category availability is checked on connection.

**GeoIP and GeoSite** opens the download settings. Each database has an editable HTTPS URL and a Download/Update button. The defaults are the same V2Ray/Xray `.dat` sources described in [Happ's routing documentation](https://github.com/HappDev/happ_su/blob/main/dev-docs/routing.md), from [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat). The `.dat` protobuf records are converted into native sing-box rules, without using its removed legacy GeoIP/GeoSite options. Formats `.db`, `.srs` and MMDB are not accepted here.

Downloads are explicit, up to 64 MiB per file, with a three-minute deadline and HTTPS-only redirects. Every record is validated before an atomic file replacement. Failed/cancelled downloads preserve the last valid database. Download state survives navigation within the app; process termination requires retrying the download. Changing a URL uses a separate cache and never reuses data from the previous URL. Downloading both files is independent; rules currently in use remain unchanged until reconnection.

Before the first GeoIP download, the default source can use bundled Russia/Iran/China allocations from [ipverse/country-ip-blocks](https://github.com/ipverse/country-ip-blocks), licensed CC0. A custom source requires its own download; GeoSite always requires a download. The bundled country files have a pinned revision and SHA-256 checksums in `app/src/main/assets/routes/manifest.json`. Update before a release with:

```powershell
./scripts/update-country-routes.ps1
```

IP lists describe allocations, not guaranteed physical server location. With routing rules enabled, normal DNS (port 53) uses the first configured VPN DNS server through the proxy, with reverse mapping for domain rules. HTTP/TLS/QUIC sniffing also detects domains when visible. Apps using their own encrypted DNS and encrypted client hello can hide a domain; IP rules still work. Health checks are forced through the proxy and cannot report a direct bypass as a working tunnel.

## Strategy countries

The filter button shows the selected countries to the left of its icon. Tap it to select multiple countries; the visible list is their union. **All** clears the filter. This also controls automatic connection, quick/full scans, rechecks, and cached fallback candidates. Neither direct strategy participates while any country is selected. Previously checked rows are cleared when the filter changes.

Country tags are suggested candidates, not claims of verified effectiveness in Iran or China. Generic Google QUIC fake and TLS split candidates are offered in all three countries; VK-specific candidates are offered for Russia. The additional `1,host`, `1,sld`, `1,endhost` TLS splits and QUIC repeat variant use the supported primitives documented by [zapret2](https://github.com/bol-van/zapret2/blob/master/docs/manual.en.md). They still need testing on each actual ISP. No strategy can promise a permanent DPI bypass.

Custom strategies may have an optional fourth column:

```text
My TLS | h2 | --payload=tls_client_hello --lua-desync=multisplit:pos=1,sld | ru,ir,cn
```

Existing three-column lines remain valid and appear under All. An imported proxy profile is separate from WARP DPI strategy filtering.

## Verification

Core tests start local VLESS, Trojan and Hysteria2 servers with generated TLS certificates and exchange real TCP and UDP payloads through each one. Routing tests verify CIDR/private bypass and that unmatched traffic never silently falls back to direct. Kotlin tests cover endpoint parsing, link validation, LAN route complements, country filtering, exclusion of cached/direct strategies, custom endpoints in rechecks and persistent connections, and empty app selections.

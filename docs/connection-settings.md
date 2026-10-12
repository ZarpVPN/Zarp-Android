# Connection settings

Settings are saved locally and applied on the next connection. A server or endpoint change clears previous results. Release and debug builds have separate settings.

## Per-app proxy

Open **Settings → Per-app proxy**, enable **Proxy selected apps only**, then toggle each app to include. App icons appear beside their names and load as rows become visible. Search accepts names and package IDs. The list contains enabled apps with Internet permission, including system apps and apps without launcher activities.

Zarp itself is always outside its own VPN. Android's allowlist and denylist are never mixed. Empty selections, or selections whose apps have all been uninstalled, refuse to establish the VPN. Changes require reconnecting; they do not interrupt an active session.

## Endpoints and imported servers

Open **Strategies → Endpoints and protocol**.

For WARP, enter one numeric `IP:port` or `[IPv6]:port` per line. Blank lines and `#` comments are accepted. An empty list restores the registered/default WARP endpoints. These must be compatible MASQUE endpoints with the pinned WARP key; this field cannot turn an arbitrary proxy into WARP. A scan rotates through the custom list, including rechecks. With a single address, rechecks use a fresh connection but cannot isolate the server endpoint. Persistent connections use the last successfully tested address from that list.

Enable **Use my server instead of WARP** to import a server link or HTTPS subscription.

| Protocol | Supported parameters |
| --- | --- |
| VLESS | UUID, TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP, TLS/ECH, Reality (`pbk`, `sid`), Vision on TCP, uTLS fingerprint |
| Trojan | Password, TLS/ECH, TCP, WebSocket, gRPC, HTTPUpgrade |
| Hysteria2 / hy2 | Password, TLS/ECH/SNI, ALPN, Salamander obfuscation |

Common parameters include `sni`, `peer` and `alpn`. Transport fields include
`type`, `path`, `host` and `serviceName`. Unknown parameters, invalid values
and inapplicable combinations produce errors naming the field, never its value.
`insecure`/`allowInsecure` are supported for sing-box transports; XHTTP refuses
them when enabled because Xray v26.9.30 removed that feature. Use `pcs` to pin
an XHTTP certificate instead. Links and subscription tokens stay in private app
storage, with Android backup disabled. Native diagnostic text is classified
before display; server logs use opaque identities rather than destinations.

### XHTTP and ECH

XHTTP is VLESS only: `type=xhttp`, `encryption=none`, empty `flow`.
`security` is `none`, `tls` or `reality`. The default path is `/`; mode is
`auto`, `packet-up`, `stream-up` or `stream-one`. A nonempty `extra` JSON
object wins over `x_padding_bytes`, which accepts a positive number or an
ascending range. Empty optional fields act like absence.

TLS supports `sni`, ALPN, `fp`, `pcs` (up to eight SHA-256 certificate pins,
hex with optional colons), `vcn` (up to eight certificate names) and `ech`.
Reality supports `pbk`, `sid`, `spx` and `pqv`, with the default `chrome`
fingerprint. `support-x25519mlkem768` is accepted for Reality as a documented
no-op: Xray selects the key exchange through its fingerprint.

`ech` accepts standard or URL-safe base64, padded or unpadded, and validates
the two-byte ECHConfigList length. It is allowed only with TLS, including Trojan
and Hysteria2, and refused for Reality or `security=none`. ECH suppresses
sing-box uTLS. An ECH failure never falls back to ordinary TLS.

ALPN exactly `h3` selects QUIC XHTTP. Any other ALPN list selects TCP/TLS.
XHTTP ALPN is accepted only for TLS; Reality always uses TCP and plaintext has
no QUIC handshake. A fingerprint without TLS/Reality is also refused.
UDP destinations travel inside XHTTP streams; they do not receive separate
outer UDP strategies. The server adds another network hop, so measured latency
includes that hop. XHTTP without TLS/Reality is parseable, but has no handshake
for a DPI strategy. Xray additionally refuses unencrypted VLESS to a public
destination, including when the explicit plain option is enabled.

`extra.downloadSettings` is permitted only with an explicit address equal to
the paired host, the same port, `network=xhttp`, a TLS/Reality handshake when
the primary has one, and matching
TCP/QUIC transport. It needs complete stream settings, including matching ALPN.
Different destinations are refused because the native secondary dialer would
not apply the pair's strategy. Xray forbids downloadSettings with
`mode=stream-one`; Android rejects this combination at import.

Unsupported: XHTTP on Trojan/Hysteria2, legacy `splithttp`, KCP, `fm`, VLESS
encryption other than `none`, nonempty XHTTP flow, port hopping (`mport`),
ECH without TLS, malformed extra/pins/names, enabled XHTTP allowInsecure, and
secondary download destinations. Arbitrary client JSON is not a subscription.

### Subscriptions and server selection

Paste an HTTPS URL without credentials or a fragment. Save downloads the list;
Refresh updates it and Delete removes the source/cache/selection. Limits:
200 distinct servers, 2 MiB response after gzip decoding, five HTTPS-only
redirects and a 25-second deadline covering both client-name attempts.
Plain lists and standard/URL-safe base64 lists are supported. Unsupported,
refused and excess entries are counted. JSON and HTML responses are named.
Zarp first requests as `Zarp/1.0`, then retries once as `v2rayN/7.0` if the
first response is not a usable list. Download failures do not trigger that retry.
Certificates are always verified.

The last valid list is cached atomically with the source hash in the private
DataStore file under filesDir. It works offline and refreshes on connection
after twelve hours. An empty/failed refresh keeps the previous list and explains
that choice. A refresh never switches an active connection.

**Automatic (all servers)** is the default. Explicit selection persists the
stable server id. If that entry disappears or becomes unsupported, the selection
remains unavailable and connection is refused until another entry or Automatic
is selected. Duplicate labels add `[host:port]`, then `#n`.

### Strategy/server pairs

Each candidate has an id `strategyId@serverId` and name `strategy + server`.
TLS split candidates pair with TLS/Reality TCP transports; QUIC fake candidates
pair with Hysteria2 and XHTTP whose ALPN is exactly `h3`. WireGuard, raw-only
and no-desync WARP profiles never pair. Custom profiles use the same transport
rules and optional country tags.

Scans run strategy by strategy against every compatible server. A failed first
HTTPS request drops that pair immediately; successful pairs receive latency
measurements and a fresh inline confirmation. Quick Scan counts confirmed pairs.
Score is `connect + 4 * ping`. Connect tries the saved pair, then verified pairs
by score, then searches. A lone failed saved candidate is not searched again.
Server DNS successes and failures are cached once per operation. The proxy is
checked after VPN startup; failure closes both the proxy and VPN.

Results are pruned against the full pair universe, not country/server-filtered
lists. Removing or changing a server invalidates only its exact pair identities.
Changing the source, connection mode or WARP endpoints clears saved results.
Old single-link settings still parse, but their old plain result/selection cannot
certify a strategy/server pair and are removed. Removed built-in ids are also
dropped without crashing. Other preferences, routing and app selections remain.

Custom WARP endpoints and test isolation are ignored in server mode and the UI
explains that limitation. Long scans use a foreground connectivity-check service.
The active pair belongs to the running engine and survives activity recreation.

The default requires a real strategy. **Allow a connection without a strategy**
is an explicit opt-in under Settings. Plain candidates display a yellow
**Connection without a strategy** label. This owner-requested option also permits
`security=none` candidates, subject to the protocol engine's own restrictions;
it is never presented as DPI bypass.

An empty `sni` or `peer` defaults to the link's host. Hostnames containing
underscores are accepted, matching Windows. Invalid hosts and ports produce
parameter-specific errors without echoing their values.

Server mode refuses another active VPN. WARP keeps its existing warning and
the UI asks for confirmation before continuing through, or replacing, that VPN.
Auto-connect waits until no foreign VPN is detected. Detection checks the
[active default network](https://developer.android.com/reference/android/net/ConnectivityManager#getActiveNetwork()),
so an inactive network left over from a stopped VPN is ignored.

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
| `192.0.2.1`, `2001:db8::/32` | IPv4/IPv6 address or CIDR |

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

Existing three-column lines remain valid and appear under All. Server pairs
inherit their strategy's country tags, so the same filter applies in server mode.

## Removed and device-dependent strategies

| Built-in id | Outcome and reason |
| --- | --- |
| `warp-wg-google6` | Removed; Android WARP implements MASQUE, not WireGuard |
| `warp-wg-stun` | Removed; needs a second WARP device and custom WireGuard bind |
| `warp-wg-vk10` | Removed; same unavailable WireGuard transport |
| `warp-wg-google-ttl` | Removed; same unavailable WireGuard transport |
| `warp-q-google-bad` | Removed; normal UDP sockets cannot send invalid checksums |
| `warp-t-google-md5` | Removed; requires raw TCP MD5 option injection |
| `warp-t-seqovl` | Removed; requires raw TCP sequence overlap |
| `warp-t-vk-seq` | Removed; requires raw sequence-number injection |
| `warp-t-hostfake` | Removed; requires raw TCP hostfakesplit injection |

Custom WireGuard lines are skipped with a reason. Raw-only custom lines stay
listed as unsupported. `warp-q-google-ttl` and `warp-q-vk-ttl` require UDP
TTL support; `warp-t-disorder` requires TCP TTL support. The core probes these
capabilities on the device and disables affected strategies and pairs specifically.

## Verification

Core tests start local VLESS, Trojan, Hysteria2 and official Xray servers with generated TLS certificates and exchange real payloads. Kotlin tests cover imports, subscription limits and refresh, offline cache, pair ordering and fallback, cancellation, migration, routing, selection and privacy. Twenty-four Kotlin JSON contracts are also loaded by the real native protocol engines.

A connected Android 10 phone passed HTTPS traffic through TLS XHTTP and Hysteria2 with Salamander, including per-app selection and Direct/Proxy/Block routing. Native counters confirmed TCP splits and UDP fakes. A wrong XHTTP certificate pin failed, closed the VPN and left direct HTTPS working. See [verification results and limits](android-server-parity.md) for evidence, unsupported combinations and differences from Windows. These local tests do not establish effectiveness against an ISP's DPI.

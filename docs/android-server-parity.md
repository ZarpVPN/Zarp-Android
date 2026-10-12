# Android server parity and verification

Verified on 2026-10-12. All changes remain uncommitted. Nothing was pushed or
released. The completed native implementation was retained; Kotlin, UI,
persistence, localization, documentation, licenses and CI are implemented.

The owner's later decisions take precedence over the original continuation
text: plain connections require an explicit option, off by default, with a
yellow "Connection without a strategy" label. XHTTP downloadSettings may use the paired
server only. Other destinations, ports or outer transports are rejected.

These choices are recorded in the owner's replies in the task thread. The
plain-mode reply requested a yellow connection-without-a-strategy status;
the download reply was "Reject secondary destinations; allow downloadSettings
on the paired server". Neither restriction was inferred during the review fixes.

## Review corrections

Blank `sni` and `peer` values now default to the link host. The parser accepts
underscore hostnames without losing credentials or ports; invalid hosts and
ports receive named errors. Kotlin honors exact native error classes, including
`other`. Both Kotlin's fallback and Go's classifier match whole error words,
so "technical failure" no longer becomes an ECH error.

WARP operations again warn when another VPN is active, with explicit UI consent
before proceeding. Server operations still refuse another VPN. Detection uses
only the active default network to avoid inactive VPN network entries. The
vendored hev-socks5-tunnel README was restored and its submodule is clean.

Seven regression tests were added. The complete suites and APK builds below
were rerun after these fixes. The updated VPN dialog was not exercised on a
device in this follow-up; the earlier phone evidence below remains historical.

## Parity matrix

| Windows behavior | Android implementation | Verification |
| --- | --- | --- |
| Concrete strategy/server pairs | Exact ids, strategy-major scan, first-request rejection, inline confirmation and scored fallback | Fake DPI model and real phone connections |
| VLESS XHTTP and ECH | In-process Xray v26.9.30, strict imports and canonical ECH | 24 Kotlin/native JSON contracts; local Xray traffic; TLS XHTTP on phone |
| HTTPS subscriptions and offline cache | Bounded downloader and atomic private DataStore cache | Redirect, retry, gzip, size, deadline, cancellation and restart tests |
| Automatic server choice | Automatic plus persisted explicit server selection | Unavailable selection and active-pair preservation tests |
| Saved results and selected strategy | Full-universe pruning and legacy plain-result migration | Migration, server-change, filtering and fallback tests |
| WARP catalog | Fifteen built-ins; nine unavailable profiles removed; injectable TTL capabilities | Catalog/capability tests; both TTL probes passed on the phone |
| Country filters, routing and app selection | Existing behavior retained; filters inherited by pairs | JVM tests and real phone Direct/Proxy/Block and app-selection checks |
| Long scans | Foreground specialUse service, cancellation and work off the main thread | Lint/build; service ran and stopped on Android 10; newer FGS enforcement needs another device |
| Import and pair UI | Source controls, status, radio selection, chips, search and lazy lists | Build/lint; localization key, placeholder and dash checks |
| Native core | Existing server dialer and pinned engines retained; all three ABIs rebuilt | Full Go tests, vet and clean gofmt output |

## What was implemented

Imports support VLESS, Trojan and Hysteria2, plus VLESS XHTTP with all four
modes, TLS/ECH, Reality, certificate pins/names, padding and extra JSON.
Errors distinguish malformed input, missing fields, unsupported schemes,
transports, parameters and combinations, refused settings and invalid values.
Messages name fields or recognized protocol names and never reproduce values.
Native diagnostic text is classified and discarded before display; server logs
use opaque identities. See [supported links](connection-settings.md#xhttp-and-ech).

Subscriptions accept plain lists and standard/URL-safe base64 with optional
padding. Limits are 200 servers, 2 MiB, five HTTPS-only redirects and one
25-second deadline across both user-agent attempts. TLS verification stays
enabled. Unsupported/refused/excess entries are counted. Save, Refresh,
Delete, stale-on-connect refresh, offline use and unavailable explicit selection
are implemented. Refresh never replaces a running connection.

Pair search preserves strategy order, rejects a failed first request without
latency sampling, confirms passing pairs inline, counts confirmed pairs for
Quick Scan, and uses connect time plus four times ping for fallback. DNS
successes and failures are cached per operation. A post-VPN proxy check tears
down both layers on failure. The engine exposes the actual active pair across
activity recreation. Server mode ignores WARP endpoints and test isolation;
their controls explain the limitation. Routing and app-selection preferences
remain shared with the existing VPN.

All eight languages have the new strings and matching placeholders. LangTest
forbids both Unicode dash characters. README and connection settings describe
actual limits. Xray's full MPL-2.0 text, pinned source and independent anet
stand-in note are in [licenses/xray-core.txt](../licenses/xray-core.txt).
Both workflows download the official pinned Xray release and check SHA-256
before native integration tests.

## Real connections and evidence

A physical Android 10/API 29 phone was connected through adb. No foreign VPN
was active before testing. The debug APK was updated with adb install -r;
the verification engine used isolated in-memory settings/results. No app was
uninstalled and no app data was cleared.

The development machine ran official Xray v26.9.30 for VLESS XHTTP, real
sing-box Hysteria2 with Salamander, and a controlled HTTPS endpoint. TCP reached
Xray through adb reverse; UDP and direct HTTPS used the local network.
Credentials and runtime addresses were confined to ignored temporary configs.
The HTTPS probe verified the generated test CA and hostname. XHTTP also pinned
its outer certificate. The temporary Hysteria2 outer connection used insecure=1
for its self-signed certificate; that phone check does not prove Hysteria2
outer certificate validation.

| Scenario | Selected probe app | Excluded probe app | Native evidence |
| --- | --- | --- | --- |
| TLS XHTTP, packet-up, TCP split | VPN visible; proxied HTTPS succeeded; Block failed; Direct succeeded | VPN absent; proxy-only test target unreachable; Direct succeeded | 3 server connections, 3 splits, 0 foreign connections |
| Hysteria2/Salamander, QUIC google fake x6 | Same four checks passed | Same exclusion and direct checks passed | 1 server flow, 1 fake flow, 6 fake packets, 0 foreign connections |
| Wrong XHTTP certificate pin | server.err.certificate; no active pair or VPN service | After failure, VPN absent and direct HTTPS succeeded | Certificate failure classified; no foreign connections |

The Hysteria2 counter snapshot was taken after its automatic cleanup deadline,
so its recorded state is Idle. Probe results were collected while the VPN was
active. The controlled HTTPS server answered 22 requests in total, including
eight requests to the direct test path and engine health checks.

Sanitized local evidence is in ignored build/device-xhttp-result.json,
build/device-hysteria2-result.json and build/device-failure-result.json.
The reusable adb-only harness is in
[DebugServerVerifier.kt](../app/src/debug/java/io/github/feg55/zarp/DebugServerVerifier.kt),
[device_verification_test.go](../core/zarpcore/device_verification_test.go) and
[scripts/device-probe](../scripts/device-probe).
Temporary reverse rules and phone configuration files were removed; no test
VPN or scan service remained. The debug app and two probe apps remain installed
under the no-uninstall constraint.

Desktop native tests also exchanged real payloads with local VLESS, Trojan,
Hysteria2 and official Xray servers. They cover TCP and UDP, Salamander on/off,
ECH on supported TLS protocols, wrong ECH lists without plain fallback, all
XHTTP modes, pinned TLS with splits, H3/QUIC with fakes, Reality, extra/xmux and
downloadSettings. These local checks do not establish ISP DPI bypass.

## Verified by tests and builds

- Baseline Go tests passed in 5.200 seconds and the original Gradle suite passed
  before Kotlin changes. The original release APK was 75,105,293 bytes.
- Final Go suite: 38 top-level tests and 38 subtests passed in 6.036 seconds.
  The manual adb server harness is the one skipped test in this automated run;
  it was separately run successfully for the phone checks.
- Go vet with with_quic,with_utls,http2legacy passed.
  gofmt -l zarpcore third_party/usque/pub printed nothing.
- JVM suite: 92 tests, zero failures and zero errors. Table-driven cases include
  desktop import vectors, ECH rules, subscriptions, cache/selection preservation,
  pair compatibility, filtering, first-failure rejection, confirmation, fallback,
  persistence, DNS resolve-once, cancellation, capability gates and privacy.
- Twenty-four checked-in Kotlin outbound contracts matched generated JSON and
  were accepted by the real sing-box and linked Xray engines.
- ./gradlew test lint assembleDebug assembleRelease :app:buildGoCore passed.
  Lint has zero errors and six warnings about the existing target SDK,
  dependency updates, ChromeOS ABI support and an obsolete API-level check.
  The AAR contains arm64-v8a, armeabi-v7a and x86_64 and is 52,930,144 bytes.
- The Windows download script ran successfully and verified SHA-256
  b17a619343c11b89d8faf36278298856749b15c52277d875d32051b33dcda617.
  The Linux digest was fetched from the official release .dgst:
  f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e.
  Workflow and shell syntax were checked locally; Linux CI was not run.

A final native run exposed a test-only issue: a TCP-chosen port can be reserved
for UDP on Windows. The helper now probes both protocols. Twenty repeated
protocol-suite runs and the subsequent full suite passed. This correction did
not change production Go behavior.

## Not verified

Actual ISP bypass, public Internet/CDN reachability through the throwaway
servers, provider subscriptions, cellular transitions, Doze and long background
scans were not verified. Android 14+ foreground-service enforcement needs
another device. The other two ABIs were built, not run on physical devices.
Phone traffic covered TLS XHTTP packet-up and Hysteria2/Salamander. ECH, Reality,
XHTTP H3, other modes and extra/downloadSettings were checked on desktop,
not the phone. Subscription HTTP checks used injected connections, not a public
provider. Offline cache/restart and active-pair preservation were checked by
JVM tests and code paths; activity recreation and every translated screen were
not exercised visually on-device.

## Unsupported combinations and reasons

| Import or connection | Reason |
| --- | --- |
| VMess, Shadowsocks, TUIC and other schemes; arbitrary client JSON | Outside the supported link/subscription protocol set |
| XHTTP on Trojan/Hysteria2; legacy splithttp, KCP and other unknown transports | Only VLESS XHTTP is integrated |
| Unknown parameters including fm and mport | Finalmask and port hopping are not implemented |
| VLESS encryption other than none; nonempty XHTTP flow | Unsupported VLESS/XHTTP combination |
| Enabled insecure/allowInsecure in XHTTP, including download TLS | Removed Xray feature; use certificate pins |
| ECH with Reality/plaintext; malformed or oversized ECH list | ECH requires TLS and a valid list length |
| XHTTP ALPN with Reality/plaintext; fingerprint with plaintext | No applicable TLS ALPN/fingerprint handshake; Reality uses TCP |
| Invalid mode, nonobject extra, padding, pins/names or Reality fields | Rejected by field name before connection |
| Misplaced pcs/vcn, spx/pqv and transport-specific fields | Inapplicable security/transport setting |
| downloadSettings with another/absent destination, another port or different outer transport | Secondary dial would not receive the pair's strategy |
| downloadSettings without network=xhttp; plaintext download with a TLS/Reality primary | Would bypass the selected transport/handshake strategy |
| stream-one with downloadSettings | Xray rejects that combination |
| XHTTP ALPN containing h3 plus another item | Supported as TCP/TLS; only exactly [h3] selects QUIC |
| security=none without explicit plain option | No TLS handshake exists to modify |
| Public unencrypted VLESS in Xray, even with the plain option | Xray itself refuses it |
| TTL profiles when the relevant capability probe fails | Device does not permit the required socket option |

An empty optional field acts like absence. Nonempty extra wins over flat
padding. support-x25519mlkem768 is accepted for Reality as a no-op because
Xray selects key exchange from the fingerprint. UDP travels inside XHTTP
streams; latency includes the second hop. Same-server downloadSettings is
allowed only with compatible outer transport and security.

## Previously unsupported WARP strategies

| Id | Outcome |
| --- | --- |
| warp-wg-google6 | Removed; MASQUE-only Android has no WireGuard transport |
| warp-wg-stun | Removed; WireGuard needs a second WARP device and custom bind |
| warp-wg-vk10 | Removed; same missing WireGuard transport |
| warp-wg-google-ttl | Removed; same missing WireGuard transport |
| warp-q-google-bad | Removed; normal UDP sockets always produce a valid checksum |
| warp-t-google-md5 | Removed; needs raw TCP MD5 option injection |
| warp-t-seqovl | Removed; needs raw sequence overlap injection |
| warp-t-vk-seq | Removed; needs raw sequence-number injection |
| warp-t-hostfake | Removed; needs raw hostfakesplit injection |

Windows has also removed the four WireGuard profiles. The retained H3
built-ins are warp-q-google6/3/10/12, warp-q-vk6, warp-q-google-vk,
warp-q-google-ttl and warp-q-vk-ttl. Retained H2 built-ins are warp-t-split,
warp-t-disorder, warp-t-split-host, warp-t-split-sld and warp-t-split-endhost.
Direct and direct-h2 remain WARP controls. The two QUIC TTL profiles and TCP
disorder are capability-gated; other retained profiles use implemented socket
primitives. Custom wg lines are skipped with a reason. Raw-only custom lines
remain visible as unsupported.

## Differences from Windows

| Android behavior | Reason |
| --- | --- |
| Default rejects security=none at pairing | No ClientHello exists for a real strategy |
| Explicit plain option, off by default, with yellow label | Owner's later decision; Windows refuses when no strategy applies |
| Fakes precede Salamander flows unconditionally | Owner's decision; effectiveness must be measured |
| Persisted explicit server selection plus Automatic | Required per-connection choice; unavailable selection cannot silently change |
| Reject secondary downloadSettings destinations | Owner's decision; secondary dials would be outside the strategy |
| Strict downloadSettings network/security/outer-transport checks and stream-one rejection | Keep accepted downloads on the paired transport and follow Xray restrictions |
| Reject inapplicable ALPN/plaintext fingerprint and misplaced fields | Avoid silently ignored settings; official Xray selects QUIC only for exactly [h3] |
| Cache, source hash and selection in one private DataStore file | Atomic Android persistence instead of a separate Windows cache; URL hash uses the 96-bit opaque-id helper |
| One 25-second subscription deadline across both attempts | Owner's total deadline; Windows starts a deadline for each download |
| Safe localized native-error classes and logs without values/endpoints | Privacy and actionable Android errors |
| In-process Xray and independent anet stand-in | gomobile requires Android linking; Windows launches an executable |
| Nine unavailable built-ins removed; per-device TTL gates | No raw packet injection or implemented WARP WireGuard transport |
| WARP retains Android's original two-phase scan | Explicit preservation requirement; current Windows rechecks inline in both modes |
| Server mode refuses a foreign VPN; WARP warns and asks before continuing | Preserve Android's WARP warning behavior and require explicit consent before replacing a VPN; inspect only the active network |
| Post-VPN proxy check and foreground scan service | Android VPN lifecycle and background execution requirements |
| Invalid imported enum values and native details are never echoed | Prevent leakage even in malformed links |

Server pairs recheck inline and count confirmed pairs, matching the current
Windows Engine reference. This changes Android's original WARP flow; it is
not a difference from the current Windows server scan. Both implementations
refuse enabled XHTTP allowInsecure, unsupported VLESS encryption and fm;
those are shared limits. Windows files were read-only behavior/test references,
and their code was not copied.

## Settings and result migration

Existing single-link source settings continue to parse. Schema 2 removes old
proxy-* results and selected ids: those were plain connections, not verified
strategy/server pairs. Unknown/removed built-in ids are pruned against the
full catalog. Pair ids include the server's fragment-independent link hash.
Changing a server invalidates its pairs; changing only its fragment label
preserves identity. Source/mode/WARP-endpoint changes clear results and the
selected pair. Country/explicit-server filtering does not prune other results.
An unavailable explicit server id stays saved until the user chooses another
server or Automatic. Refresh cannot replace an active pair. Routing, app lists,
language, account and other preferences remain. Numeric settings are bounded,
corrupt cache/results cannot crash startup, and plain connections stay disabled
until explicitly enabled.

## APK size

| Build | Bytes | Decimal MB |
| --- | ---: | ---: |
| Original unsigned release before continuation | 75,105,293 | 75.11 |
| Xray-enabled comparison build, uncompressed libraries | 147,274,497 | 147.27 |
| Final unsigned release, useLegacyPackaging=true | 52,077,213 | 52.08 |

The new AAR is 52.88 MB versus the original 27.6 MB. Compression keeps the
universal release APK below the original size despite Xray. The final release
artifact is unsigned. No release was published.

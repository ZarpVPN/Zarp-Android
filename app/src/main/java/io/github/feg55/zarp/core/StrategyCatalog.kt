package io.github.feg55.zarp.core

/**
 * Built-in strategies, ported one-to-one from Zarp's StrategyCatalog (Strategy.cs):
 * same ids, names, transports and zapret2 arguments, same order (the search goes
 * top to bottom, most likely first). Strategies that need raw sockets stay in the
 * list and are reported as unsupported instead of being replaced by something else.
 *
 * Android additions are HTTP/2 split/disorder variants that work from a normal TCP socket.
 */
object StrategyCatalog {
    val builtIn: List<Strategy> = listOf(
        // ---------- MASQUE / HTTP3 (default protocol of the WARP client) ----------
        s("warp-q-google6", "WARP QUIC: fake google ×6", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=6"),
        s("warp-q-google3", "WARP QUIC: fake google ×3", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3"),
        s("warp-q-vk6", "WARP QUIC: fake vk ×6", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_vk:repeats=6"),
        s("warp-q-google-vk", "WARP QUIC: fakes google + vk", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=3 --lua-desync=fake:blob=quic_vk:repeats=3"),
        s("warp-q-google10", "WARP QUIC: fake google ×10", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=10"),
        s("warp-q-google-ttl", "WARP QUIC: fake google ttl=4 ×6", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_google:ip_ttl=4:ip6_ttl=4:repeats=6"),
        s("warp-q-vk-ttl", "WARP QUIC: fake vk ttl=4 ×6", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_vk:ip_ttl=4:ip6_ttl=4:repeats=6"),
        s("warp-q-google-bad", "WARP QUIC: fake google badsum ×6", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_google:badsum:repeats=6"),

        // ---------- WireGuard (fallback, not implemented on Android yet) ----------
        s("warp-wg-google6", "WARP WireGuard: fake QUIC google ×6", Transport.WireGuard,
            "--payload=wireguard_initiation --lua-desync=fake:blob=quic_google:repeats=6"),
        s("warp-wg-stun", "WARP WireGuard: fake STUN ×6", Transport.WireGuard,
            "--payload=wireguard_initiation --lua-desync=fake:blob=stun_fake:repeats=6"),
        s("warp-wg-vk10", "WARP WireGuard: fake QUIC vk ×10", Transport.WireGuard,
            "--payload=wireguard_initiation --lua-desync=fake:blob=quic_vk:repeats=10"),
        s("warp-wg-google-ttl", "WARP WireGuard: fake google ttl=4", Transport.WireGuard,
            "--payload=wireguard_initiation --lua-desync=fake:blob=quic_google:ip_ttl=4:ip6_ttl=4:repeats=6"),

        // ---------- MASQUE / HTTP2 (TLS over TCP) ----------
        s("warp-t-google-md5", "WARP TLS: fake google md5 + split", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=fake:blob=tls_google:tcp_md5:repeats=6 --lua-desync=multisplit:pos=1,midsld"),
        s("warp-t-seqovl", "WARP TLS: seqovl google", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=multisplit:pos=2:seqovl=681:seqovl_pattern=tls_google"),
        s("warp-t-vk-seq", "WARP TLS: fake vk badseq + disorder", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=fake:blob=tls_vk:tcp_seq=-3000:repeats=6 --lua-desync=multidisorder:pos=1,midsld"),
        s("warp-t-hostfake", "WARP TLS: hostfakesplit vk.com", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=hostfakesplit:host=vk.com:tcp_md5"),
        // Android: no raw sockets, but segmentation of the ClientHello works from a normal socket
        s("warp-t-split", "WARP TLS: split 1,midsld", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=multisplit:pos=1,midsld"),
        s("warp-t-disorder", "WARP TLS: disorder 1,midsld", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=multidisorder:pos=1,midsld"),
        // Additional socket-compatible candidates from zapret2's documented split markers.
        s("warp-t-split-host", "WARP TLS: split 1,host", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=multisplit:pos=1,host"),
        s("warp-t-split-sld", "WARP TLS: split 1,sld", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=multisplit:pos=1,sld"),
        s("warp-t-split-endhost", "WARP TLS: split 1,endhost", Transport.MasqueH2,
            "--payload=tls_client_hello --lua-desync=multisplit:pos=1,endhost"),
        s("warp-q-google12", "WARP QUIC: fake google ×12", Transport.MasqueH3,
            "--payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=12"),

        // ---------- Control: maybe WARP already works on this network ----------
        Strategy(DIRECT_ID, "Direct (no desync)", Transport.MasqueH3, "", nameKey = "strategy.direct"),
        Strategy(DIRECT_H2_ID, "Direct over HTTP/2 (no desync)", Transport.MasqueH2, "", nameKey = "strategy.directH2"),
    )

    const val DIRECT_ID = "direct"
    const val DIRECT_H2_ID = "direct-h2"

    private fun s(id: String, name: String, t: Transport, args: String) = Strategy(
        id, name, t, args,
        countries = if ("vk" in args) setOf("ru") else setOf("ru", "ir", "cn"),
    )

    fun forSettings(settings: AppSettings): List<Strategy> = if (settings.useProxy) {
        listOf(ProxyProfile.parse(settings.proxyUri).strategy())
    } else load(settings.customStrategies)

    /** Built-in + custom strategies (Zarp's strategies.txt format: `Name | transport | args`). */
    fun load(customText: String, onSkipped: (String) -> Unit = {}): List<Strategy> =
        builtIn + parseCustom(customText, onSkipped)

    fun parseCustom(text: String, onSkipped: (String) -> Unit = {}): List<Strategy> {
        val out = mutableListOf<Strategy>()
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val parts = line.split("|", limit = 4)
            val t = parts.getOrNull(1)?.let { Transport.parse(it) }
            if (parts.size < 3 || t == null || parts[0].isBlank()) {
                onSkipped(line)
                continue
            }
            val name = parts[0].trim()
            out += Strategy(
                id = "custom-" + name.lowercase().replace(' ', '-'),
                title = "★ $name",
                transport = t,
                args = parts[2].trim(),
                custom = true,
                countries = parts.getOrNull(3)?.split(',')?.map { it.trim().lowercase() }
                    ?.filter { it in StrategyFilter.countries && it != "all" }?.toSet() ?: emptySet(),
            )
        }
        return out.distinctBy { it.id }
    }

    const val CUSTOM_TEMPLATE = """# Custom Zarp strategies. One line = one strategy:
#   Name | transport | zapret2 profile arguments
# transport: h3 (MASQUE/QUIC), h2 (MASQUE/TLS)
# Optional fourth column: ru,ir,cn (country filters)
# h3: --payload=quic_initial --lua-desync=fake:blob=<blob>:repeats=N[:ip_ttl=N:ip6_ttl=N]
# h2: --payload=tls_client_hello --lua-desync=multisplit|multidisorder:pos=1,midsld
# Blobs: quic_google, quic_vk, tls_google, tls_vk, stun_fake, zero64
#
# Example:
# My QUIC | h3 | --payload=quic_initial --lua-desync=fake:blob=quic_google:repeats=8
"""
}

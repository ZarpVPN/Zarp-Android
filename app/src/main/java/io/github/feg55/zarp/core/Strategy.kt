package io.github.feg55.zarp.core

/** How the WARP tunnel is carried. Port of Zarp's WarpTransport. */
enum class Transport(val title: String, val shortName: String) {
    /** MASQUE over HTTP/3 (QUIC, UDP). Primary transport. */
    MasqueH3("MASQUE / HTTP3", "h3"),

    /** MASQUE over HTTP/2 (TLS, TCP). Secondary transport. */
    MasqueH2("MASQUE / HTTP2", "h2"),

    /** Classic WireGuard (UDP). Fallback only; not implemented on Android yet. */
    WireGuard("WireGuard", "wg"),
    Vless("VLESS", "vless"),
    Hysteria2("Hysteria2", "hysteria2"),
    Trojan("Trojan", "trojan");

    val isWarp: Boolean get() = this in setOf(MasqueH3, MasqueH2, WireGuard)

    companion object {
        /** Same aliases as Zarp's Strategy.TryParseTransport. */
        fun parse(s: String): Transport? = when (s.trim().lowercase()) {
            "h3", "masque", "masque-h3" -> MasqueH3
            "h2", "masque-h2" -> MasqueH2
            "wg", "wireguard" -> WireGuard
            else -> null
        }
    }
}

/**
 * Strategy = tunnel transport + zapret2 profile arguments, exactly as in Zarp.
 * Empty [args] means "no desync": WARP connects directly.
 *
 * On Android the arguments are not handed to winws2; [plan] translates them into
 * what can be done from a normal socket (see [ZapretArgs]).
 */
data class Strategy(
    val id: String,
    /** Technical names are the same in every language, as in Zarp. */
    val title: String,
    val transport: Transport,
    val args: String,
    val custom: Boolean = false,
    /** Translation key for names that are translated (the direct strategies). */
    val nameKey: String? = null,
    /** Candidate regions, not a claim that a strategy works on every ISP there. */
    val countries: Set<String> = emptySet(),
) {
    val name: String get() = nameKey?.let { L.t(it) } ?: title

    val usesDesync: Boolean get() = args.isNotBlank()

    /** Parsed once; unsupported parts are reported, never silently dropped. */
    val plan: DesyncPlan by lazy { ZapretArgs.parse(transport, args) }

    val supported: Boolean get() = plan.unsupported == null

    override fun toString(): String = name
}

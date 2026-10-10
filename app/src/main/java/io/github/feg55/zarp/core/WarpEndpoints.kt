package io.github.feg55.zarp.core

/**
 * WARP endpoints for isolated tests. Port of Zarp's Warp.NextEndpoint: every test
 * goes to an endpoint (IP:port) not used by the previous one, so a strategy cannot
 * inherit DPI state from an earlier successful connection.
 */
class WarpEndpoints {
    private var seq = 0

    @Synchronized
    fun next(t: Transport, custom: List<String> = emptyList()): String {
        val n = seq
        seq = if (seq == Int.MAX_VALUE) 0 else seq + 1
        if (custom.isNotEmpty()) return custom[n % custom.size]
        return when (t) {
            Transport.WireGuard ->
                WIREGUARD_IPS[n % WIREGUARD_IPS.size] + ":" + WIREGUARD_PORTS[n / WIREGUARD_IPS.size % WIREGUARD_PORTS.size]
            // HTTP/2 runs over TCP 443, and only one endpoint presents the pinned key
            Transport.MasqueH2 -> MASQUE_H2_IPS[n % MASQUE_H2_IPS.size] + ":443"
            Transport.MasqueH3 ->
                MASQUE_IPS[n % MASQUE_IPS.size] + ":" + MASQUE_PORTS[n / MASQUE_IPS.size % MASQUE_PORTS.size]
            else -> error("Not a WARP transport")
        }
    }

    companion object {
        val MASQUE_IPS = listOf("162.159.198.1", "162.159.198.2")
        val MASQUE_PORTS = listOf(443, 500, 1701, 4500, 4443, 8443)

        /** Tested on a real network: 162.159.198.1:443 over TLS answers with a different key. */
        val MASQUE_H2_IPS = listOf("162.159.198.2")
        val WIREGUARD_IPS = (1..10).map { "162.159.192.$it" } + (1..10).map { "162.159.193.$it" }
        val WIREGUARD_PORTS = listOf(2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894)
    }
}

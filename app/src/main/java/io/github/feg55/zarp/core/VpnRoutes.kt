package io.github.feg55.zarp.core

import java.math.BigInteger
import java.net.InetAddress

/** Complement routes also work on Android 8-12, before Builder.excludeRoute. */
object VpnRoutes {
    data class Route(val address: String, val prefix: Int)

    private val lan4 = listOf("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
    private val lan6 = listOf("::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")

    fun internet(ipv6: Boolean, bypassLan: Boolean): List<Route> {
        if (!bypassLan) return listOf(Route(if (ipv6) "::" else "0.0.0.0", 0))
        val bits = if (ipv6) 128 else 32
        val excluded = (if (ipv6) lan6 else lan4).map {
            val (address, prefix) = it.split('/')
            val start = BigInteger(1, InetAddress.getByName(address).address)
            start to start.add(BigInteger.ONE.shiftLeft(bits - prefix.toInt())).subtract(BigInteger.ONE)
        }
        val result = mutableListOf<Route>()
        fun walk(start: BigInteger, prefix: Int) {
            val end = start.add(BigInteger.ONE.shiftLeft(bits - prefix)).subtract(BigInteger.ONE)
            if (excluded.any { (lo, hi) -> start >= lo && end <= hi }) return
            if (excluded.none { (lo, hi) -> start <= hi && end >= lo }) {
                val raw = start.toByteArray()
                val bytes = ByteArray(bits / 8)
                val count = minOf(raw.size, bytes.size)
                raw.copyInto(bytes, bytes.size - count, raw.size - count)
                result += Route(InetAddress.getByAddress(bytes).hostAddress!!, prefix)
                return
            }
            walk(start, prefix + 1)
            walk(start.add(BigInteger.ONE.shiftLeft(bits - prefix - 1)), prefix + 1)
        }
        walk(BigInteger.ZERO, 0)
        return result
    }
}

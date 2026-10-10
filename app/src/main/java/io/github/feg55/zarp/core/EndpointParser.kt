package io.github.feg55.zarp.core

import java.net.InetAddress

/** Numeric addresses only: validation must never perform DNS from the UI. */
object EndpointParser {
    fun parse(text: String): List<String> = text.lineSequence()
        .map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }
        .map { line ->
            val ipv6 = line.startsWith('[')
            val host = if (ipv6) line.substringAfter('[').substringBefore(']') else line.substringBefore(':')
            val portText = if (ipv6) line.substringAfter("]:", "") else line.substringAfter(':', "")
            val port = portText.toIntOrNull()
            require(port != null && port in 1..65535) { "endpoint.invalid" }
            if (ipv6) {
                require(host.contains(':') && host.all { it in "0123456789abcdefABCDEF:." }) { "endpoint.invalid" }
                require(runCatching { InetAddress.getByName(host) }.isSuccess) { "endpoint.invalid" }
            } else {
                val parts = host.split('.')
                require(parts.size == 4 && parts.all { p ->
                    p.isNotEmpty() && p.all(Char::isDigit) && p.toIntOrNull() in 0..255 && (p == "0" || !p.startsWith('0'))
                }) { "endpoint.invalid" }
            }
            if (ipv6) "[$host]:$port" else "$host:$port"
        }.distinct().toList()
}

package io.github.feg55.zarp.core

import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** One imported server. Credentials never appear in strategy names, endpoints or logs. */
class ProxyProfile private constructor(
    val transport: Transport,
    val endpoint: String,
    val outbound: JsonObject,
    private val id: String,
) {
    fun strategy() = Strategy(id, "${transport.title}: $endpoint", transport, "", custom = true)

    companion object {
        fun parse(text: String): ProxyProfile {
            try {
                return parseUri(text.trim())
            } catch (_: Exception) {
                // URI parser errors may contain the password. Do not propagate them.
                throw IllegalArgumentException("proxy.invalid")
            }
        }

        private fun decode(s: String) = URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")

        private fun parseUri(text: String): ProxyProfile {
            require(text.length in 1..8192)
            val uri = URI(text)
            val transport = when (uri.scheme?.lowercase()) {
                "vless" -> Transport.Vless
                "hy2", "hysteria2" -> Transport.Hysteria2
                "trojan" -> Transport.Trojan
                else -> error("scheme")
            }
            val host = requireNotNull(uri.host).removePrefix("[").removeSuffix("]")
            require(host.isNotBlank() && '%' !in host)
            val port = if (uri.port == -1 && transport == Transport.Hysteria2) 443 else uri.port
            require(port in 1..65535)
            require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")
            val credential = decode(requireNotNull(uri.rawUserInfo))
            require(credential.isNotEmpty() && credential.none { it.isISOControl() })
            val params = linkedMapOf<String, String>()
            uri.rawQuery?.split('&')?.filter { it.isNotEmpty() }?.forEach {
                val parts = it.split('=', limit = 2)
                require(params.put(decode(parts[0]), decode(parts.getOrElse(1) { "" })) == null)
            }
            val known = setOf("security", "sni", "peer", "insecure", "allowInsecure", "alpn", "fp", "pbk", "sid",
                "flow", "encryption", "type", "path", "host", "serviceName", "obfs", "obfs-password")
            require(params.keys.all { it in known })
            require(params["encryption"] in listOf(null, "", "none"))
            val security = params["security"] ?: if (transport == Transport.Vless) "none" else "tls"
            require(security in setOf("none", "tls", "reality"))
            require(transport == Transport.Vless || security == "tls")
            val network = params["type"] ?: "tcp"
            require(network in setOf("tcp", "ws", "grpc", "httpupgrade"))
            require(transport != Transport.Hysteria2 || network == "tcp")
            val flow = params["flow"].orEmpty()
            require(flow in setOf("", "xtls-rprx-vision"))
            require(flow.isEmpty() || (transport == Transport.Vless && network == "tcp" && security != "none"))
            if (transport == Transport.Vless) require(credential.matches(Regex("[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}")))
            for (key in listOf("insecure", "allowInsecure")) require(params[key] in listOf(null, "0", "1", "true", "false"))
            val outbound = buildJsonObject {
                put("type", transport.shortName)
                put("tag", "proxy")
                put("server", host)
                put("server_port", port)
                put("domain_resolver", "bootstrap")
                put("connect_timeout", "15s")
                if (transport == Transport.Vless) {
                    put("uuid", credential)
                    put("flow", flow)
                    put("packet_encoding", "xudp")
                } else put("password", credential)
                if (security != "none") put("tls", buildJsonObject {
                    put("enabled", true)
                    put("server_name", params["sni"] ?: params["peer"] ?: host)
                    put("insecure", listOf(params["insecure"], params["allowInsecure"]).any { it == "1" || it == "true" })
                    params["alpn"]?.takeIf { it.isNotBlank() }?.let { alpn ->
                        put("alpn", buildJsonArray { alpn.split(',').forEach { add(JsonPrimitive(it)) } })
                    }
                    if (transport != Transport.Hysteria2 && (params["fp"] != null || security == "reality")) {
                        put("utls", buildJsonObject {
                            put("enabled", true)
                            put("fingerprint", params["fp"] ?: "chrome")
                        })
                    }
                    if (security == "reality") put("reality", buildJsonObject {
                        val publicKey = requireNotNull(params["pbk"])
                        require(publicKey.matches(Regex("[A-Za-z0-9_-]{43}")))
                        val shortId = params["sid"].orEmpty()
                        require(shortId.length <= 16 && shortId.length % 2 == 0 && shortId.all { it in "0123456789abcdefABCDEF" })
                        put("enabled", true)
                        put("public_key", publicKey)
                        put("short_id", shortId)
                    })
                })
                if (network != "tcp") put("transport", buildJsonObject {
                    put("type", network)
                    if (network == "grpc") put("service_name", params["serviceName"].orEmpty())
                    else {
                        put("path", params["path"] ?: "/")
                        params["host"]?.let { hostHeader ->
                            if (network == "ws") put("headers", buildJsonObject { put("Host", hostHeader) })
                            else put("host", hostHeader)
                        }
                    }
                })
                params["obfs"]?.let { obfs ->
                    require(transport == Transport.Hysteria2 && obfs == "salamander")
                    val password = requireNotNull(params["obfs-password"])
                    require(password.isNotEmpty())
                    put("obfs", buildJsonObject { put("type", obfs); put("password", password) })
                }
            }
            val hash = MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).take(12)
                .joinToString("") { "%02x".format(it) }
            return ProxyProfile(transport, if (':' in host) "[$host]:$port" else "$host:$port", outbound, "proxy-$hash")
        }
    }
}

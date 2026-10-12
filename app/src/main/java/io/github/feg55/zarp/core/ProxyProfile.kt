package io.github.feg55.zarp.core

import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.*

enum class LinkIssueKind { Malformed, MissingParameter, UnsupportedScheme, UnsupportedTransport, UnsupportedParameter, UnsupportedCombination, RefusedSetting, InvalidValue }
data class LinkIssue(val kind: LinkIssueKind, val parameter: String = "")

/** Parser failures contain only a reason and a safe parameter name, never link values. */
class ProxyLinkException(val reason: String, val parameter: String = "") : IllegalArgumentException("proxy.invalid") {
    val issue = LinkIssue(when (reason) {
        "missing" -> LinkIssueKind.MissingParameter
        "scheme" -> LinkIssueKind.UnsupportedScheme
        "transport" -> LinkIssueKind.UnsupportedTransport
        "param" -> LinkIssueKind.UnsupportedParameter
        "security", "combination" -> LinkIssueKind.UnsupportedCombination
        "insecure", "secondary" -> LinkIssueKind.RefusedSetting
        "value", "extra" -> LinkIssueKind.InvalidValue
        else -> LinkIssueKind.Malformed
    }, parameter)
    val msg: Msg get() = when (reason) {
        "scheme" -> Msg("proxy.scheme", parameter)
        "extra" -> Msg("proxy.extra")
        "insecure" -> Msg("proxy.insecure")
        "secondary" -> Msg("proxy.secondary")
        "missing", "value", "combination" -> Msg("proxy.$reason", parameter)
        "param", "transport", "security" -> Msg("proxy.$reason", parameter)
        else -> Msg("proxy.invalid")
    }
}

/** One imported server. No generated credential-bearing toString. */
class ProxyProfile private constructor(
    val transport: Transport,
    val host: String,
    val port: Int,
    val outbound: JsonObject,
    val xrayOutbound: JsonObject?,
    val outerTransport: Transport,
    val label: String?,
    val id: String,
    val hasTls: Boolean,
    val hasEch: Boolean,
    val obfuscated: Boolean,
) {
    val endpoint: String get() = if (':' in host) "[$host]:$port" else "$host:$port"
    val protocolTitle: String get() = transport.title + if (xrayOutbound != null) " / XHTTP" else ""
    val displayName: String get() = label ?: "$protocolTitle: $endpoint"
    val security: String get() = xrayOutbound?.get("streamSettings")?.jsonObject?.get("security")?.jsonPrimitive?.content
        ?: if (!hasTls) "none" else if (outbound["tls"]?.jsonObject?.containsKey("reality") == true) "reality" else "tls"
    fun strategy() = Strategy(id, displayName, transport, "", custom = true, profile = this)

    fun buildXrayOutbound(address: String): JsonObject {
        val original = requireNotNull(xrayOutbound)
        val settings = original.getValue("settings").jsonObject
        val server = settings.getValue("vnext").jsonArray.single().jsonObject
        return JsonObject(original + ("settings" to JsonObject(settings + ("vnext" to JsonArray(listOf(
            JsonObject(server + ("address" to JsonPrimitive(address))),
        ))))))
    }

    companion object {
        private val known = setOf("security", "sni", "peer", "insecure", "allowInsecure", "alpn", "fp", "pbk", "sid",
            "flow", "encryption", "type", "path", "host", "serviceName", "obfs", "obfs-password",
            "mode", "extra", "spx", "pqv", "pcs", "vcn", "x_padding_bytes", "ech", "support-x25519mlkem768")
        private val uuid = Regex("[a-fA-F0-9]{8}(-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}")
        private val name = Regex("[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")
        private fun token(value: String) = if (value.matches(Regex("[A-Za-z0-9_.-]{1,24}"))) value else "?"
        private fun transportName(value: String) = value.takeIf {
            it in setOf("tcp", "ws", "grpc", "httpupgrade", "xhttp", "splithttp", "kcp", "mkcp", "quic", "h2", "h3", "http", "http2", "http3")
        } ?: "type"
        private fun securityName(value: String) = value.takeIf { it in setOf("none", "tls", "reality", "xtls") } ?: "security"
        private fun check(ok: Boolean, reason: String = "format", field: String = "") {
            if (!ok) throw ProxyLinkException(reason, field)
        }
        private fun decode(value: String) = URLDecoder.decode(value.replace("+", "%2B"), "UTF-8")

        fun explain(text: String): Msg? = try { parse(text); null } catch (e: ProxyLinkException) { e.msg }

        fun parse(text: String): ProxyProfile = try { parseUri(text.trim()) }
        catch (e: ProxyLinkException) { throw e }
        catch (_: Exception) { throw ProxyLinkException("format") }

        private fun parseUri(text: String): ProxyProfile {
            check(text.length in 1..8192)
            // A malformed label must not make a valid connection link unusable.
            val link = text.substringBefore('#')
            val uri = URI(link)
            val transport = when (uri.scheme?.lowercase()) {
                "vless" -> Transport.Vless
                "trojan" -> Transport.Trojan
                "hy2", "hysteria2" -> Transport.Hysteria2
                else -> throw ProxyLinkException("scheme", uri.scheme?.lowercase()?.takeIf {
                    it in setOf("vmess", "ss", "ssr", "tuic", "wireguard", "socks", "socks5", "http", "https")
                } ?: "scheme")
            }
            // URI treats underscore hostnames as registry authorities, losing host, port and user info.
            val authority = uri.rawAuthority ?: throw ProxyLinkException("missing", "host")
            val address = authority.substringAfterLast('@')
            val host = (uri.host ?: address.substringBefore(':')).removePrefix("[").removeSuffix("]")
            check(host.isNotEmpty(), "missing", "host")
            check(host.length <= 253 && '%' !in host && (':' in host || name.matches(host)), "value", "host")
            val rawPort = if (uri.host != null) uri.port.takeIf { it != -1 }?.toString()
                else address.substringAfter(':', "").takeIf { ':' in address }
            val port = if (rawPort == null && transport == Transport.Hysteria2) 443 else {
                check(rawPort != null, "missing", "port")
                check(rawPort!!.matches(Regex("[0-9]+")), "value", "port")
                rawPort.toIntOrNull() ?: throw ProxyLinkException("value", "port")
            }
            check(port in 1..65535, "value", "port")
            check(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/")
            val credential = decode(uri.rawUserInfo ?: authority.substringBeforeLast('@').takeIf { '@' in authority }
                ?: throw ProxyLinkException("missing", "credentials"))
            check(credential.isNotEmpty() && credential.none(Char::isISOControl))
            if (transport == Transport.Vless) check(uuid.matches(credential), "value", "uuid")
            val params = linkedMapOf<String, String>()
            uri.rawQuery?.split('&')?.filter(String::isNotEmpty)?.forEach { piece ->
                val parts = piece.split('=', limit = 2)
                check(params.put(decode(parts[0]), decode(parts.getOrElse(1) { "" })) == null)
            }
            params.keys.forEach { check(it in known, "param", token(it)) }
            fun filled(key: String) = params[key]?.takeIf(String::isNotBlank)
            fun only(key: String, allowed: Boolean) = check(allowed || filled(key) == null, "combination", key)
            check(params["encryption"] in listOf(null, "", "none"), "value", "encryption")
            val security = params["security"] ?: if (transport == Transport.Vless) "none" else "tls"
            check(security in setOf("none", "tls", "reality"), "security", securityName(security))
            check(transport == Transport.Vless || security == "tls", "security", securityName(security))
            val network = params["type"] ?: "tcp"
            val xhttp = network == "xhttp"
            check(network in setOf("tcp", "ws", "grpc", "httpupgrade", "xhttp"), "transport", transportName(network))
            check(transport != Transport.Hysteria2 || network == "tcp", "transport", transportName(network))
            check(!xhttp || transport == Transport.Vless, "transport", "xhttp")
            listOf("mode", "extra", "x_padding_bytes").forEach { only(it, xhttp) }
            listOf("spx", "pqv").forEach { only(it, xhttp && security == "reality") }
            listOf("pcs", "vcn").forEach { only(it, xhttp && security == "tls") }
            only("ech", security == "tls")
            only("support-x25519mlkem768", security == "reality")
            only("alpn", !xhttp || security == "tls")
            only("fp", !xhttp || security != "none")
            only("obfs", transport == Transport.Hysteria2)
            only("obfs-password", transport == Transport.Hysteria2 && filled("obfs") != null)
            listOf("pbk", "sid").forEach { only(it, security == "reality") }
            only("serviceName", network == "grpc")
            listOf("path", "host").forEach { only(it, network in setOf("ws", "httpupgrade", "xhttp")) }
            val flow = params["flow"].orEmpty()
            check(flow in setOf("", "xtls-rprx-vision"), "value", "flow")
            check(flow.isEmpty() || (transport == Transport.Vless && network == "tcp" && security != "none"), "combination", "flow")
            listOf("insecure", "allowInsecure", "support-x25519mlkem768").forEach {
                check(params[it] in listOf(null, "", "0", "1", "true", "false"), "value", it)
            }
            val insecure = listOf(params["insecure"], params["allowInsecure"]).any { it == "1" || it == "true" }
            check(!xhttp || !insecure, "insecure")
            val ech = filled("ech")?.let(::normalizeEch)
            val alpn = filled("alpn")?.split(',')?.map(String::trim)?.filter(String::isNotEmpty).orEmpty()
            val sniParameter = if ("sni" in params) "sni" else "peer"
            val sni = (params["sni"] ?: params["peer"])?.takeIf(String::isNotBlank) ?: host
            check(sni.none(Char::isISOControl), "value", sniParameter)
            val fp = filled("fp")
            val publicKey = if (security == "reality") (params["pbk"] ?: throw ProxyLinkException("missing", "pbk")).also {
                check(it.matches(Regex("[A-Za-z0-9_-]{43}")), "value", "pbk")
            } else null
            val shortId = params["sid"].orEmpty()
            check(shortId.length <= 16 && shortId.length % 2 == 0 && shortId.all { it in "0123456789abcdefABCDEF" }, "value", "sid")
            val obfs = filled("obfs")
            check(obfs == null || obfs == "salamander", "value", "obfs")
            check(obfs == null || !params["obfs-password"].isNullOrEmpty(), "missing", "obfs-password")
            val outbound = if (xhttp) buildJsonObject {
                // The native bridge fills in its own random port and credentials.
                put("type", "socks"); put("tag", "proxy"); put("server", "127.0.0.1"); put("server_port", 1); put("version", "5")
            } else buildJsonObject {
                put("type", transport.shortName); put("tag", "proxy"); put("server", host); put("server_port", port)
                put("detour", "server-dial"); put("connect_timeout", "15s")
                if (transport == Transport.Vless) {
                    put("uuid", credential); put("flow", flow); put("packet_encoding", "xudp")
                } else put("password", credential)
                if (security != "none") put("tls", buildJsonObject {
                    put("enabled", true); put("server_name", sni); put("insecure", insecure)
                    if (alpn.isNotEmpty()) put("alpn", strings(alpn))
                    if (ech != null) put("ech", buildJsonObject {
                        put("enabled", true)
                        put("config", strings(listOf("-----BEGIN ECH CONFIGS-----") + ech.chunked(64) + "-----END ECH CONFIGS-----"))
                    })
                    if (transport != Transport.Hysteria2 && ech == null && (fp != null || security == "reality")) {
                        put("utls", buildJsonObject { put("enabled", true); put("fingerprint", fp ?: "chrome") })
                    }
                    if (security == "reality") put("reality", buildJsonObject {
                        put("enabled", true); put("public_key", publicKey); put("short_id", shortId)
                    })
                })
                if (network != "tcp") put("transport", buildJsonObject {
                    put("type", network)
                    if (network == "grpc") put("service_name", params["serviceName"].orEmpty())
                    else {
                        put("path", params["path"] ?: "/")
                        params["host"]?.let {
                            if (network == "ws") put("headers", buildJsonObject { put("Host", it) }) else put("host", it)
                        }
                    }
                })
                if (obfs != null) put("obfs", buildJsonObject { put("type", obfs); put("password", params["obfs-password"]) })
            }
            val xray = if (!xhttp) null else buildJsonObject {
                put("tag", "server"); put("protocol", "vless")
                put("settings", buildJsonObject { put("vnext", buildJsonArray { add(buildJsonObject {
                    put("address", host); put("port", port)
                    put("users", buildJsonArray { add(buildJsonObject { put("id", credential); put("encryption", "none"); put("flow", "") }) })
                }) }) })
                put("streamSettings", buildJsonObject {
                    put("network", "xhttp"); put("security", security)
                    put("xhttpSettings", buildJsonObject {
                        put("path", filled("path") ?: "/")
                        val mode = filled("mode") ?: "auto"
                        check(mode in setOf("auto", "packet-up", "stream-up", "stream-one"), "value", "mode")
                        put("mode", mode)
                        if (filled("host") != null) put("host", filled("host"))
                        else if (security == "none") put("host", host)
                        val extra = filled("extra")?.let {
                            val parsed = runCatching { Json.parseToJsonElement(it) }.getOrNull()
                            check(parsed is JsonObject, "extra")
                            parsed as JsonObject
                        }
                        // A pair owns one address and port. The native foreign dialer has no strategy.
                        extra?.get("downloadSettings")?.takeUnless { it is JsonNull }?.let { download ->
                            check(download is JsonObject, "value", "downloadSettings")
                            val d = download.jsonObject
                            val destination = d["address"]?.jsonPrimitive?.contentOrNull
                            val downloadPort = d["port"]?.jsonPrimitive?.intOrNull
                            check(destination?.trim('[', ']')?.equals(host, true) == true, "secondary")
                            check(downloadPort == port, "secondary")
                            check(d["network"]?.jsonPrimitive?.contentOrNull == "xhttp", "combination", "downloadSettings.network")
                            val downloadSecurity = d["security"]?.jsonPrimitive?.contentOrNull.orEmpty().ifEmpty { "none" }
                            check(downloadSecurity in setOf("none", "tls", "reality"), "value", "downloadSettings.security")
                            check(security == "none" || downloadSecurity != "none", "combination", "downloadSettings.security")
                            check(mode != "stream-one", "combination", "downloadSettings")
                            val downloadTls = d["tlsSettings"]?.jsonObject
                            check(downloadTls?.get("allowInsecure")?.jsonPrimitive?.booleanOrNull != true, "insecure")
                            val downloadAlpn = downloadTls?.get("alpn")?.jsonArray
                                ?.map { it.jsonPrimitive.content.trim() }?.filter(String::isNotEmpty)
                            check((downloadSecurity == "tls" && downloadAlpn == listOf("h3")) == (alpn == listOf("h3")), "secondary")
                        }
                        val padding = filled("x_padding_bytes")?.let(::validatePadding)
                        if (extra != null && extra.isNotEmpty()) put("extra", extra)
                        else if (padding != null) put("xPaddingBytes", padding)
                    })
                    if (security == "tls") put("tlsSettings", buildJsonObject {
                        put("serverName", sni)
                        if (alpn.isNotEmpty()) put("alpn", strings(alpn))
                        fp?.let { put("fingerprint", it) }
                        ech?.let { put("echConfigList", it) }
                        filled("pcs")?.let { pins ->
                            val list = pins.split(',').map { it.trim().replace(":", "") }.filter(String::isNotEmpty)
                            check(list.size in 1..8 && list.all { it.matches(Regex("[a-fA-F0-9]{64}")) }, "value", "pcs")
                            put("pinnedPeerCertSha256", list.joinToString(",").lowercase())
                        }
                        filled("vcn")?.let { names ->
                            val list = names.split(',').map(String::trim).filter(String::isNotEmpty)
                            check(list.size in 1..8 && list.all { it.length <= 253 && name.matches(it.removePrefix("*.")) }, "value", "vcn")
                            put("verifyPeerCertByName", list.joinToString(","))
                        }
                    })
                    if (security == "reality") put("realitySettings", buildJsonObject {
                        put("serverName", sni); put("fingerprint", fp ?: "chrome"); put("publicKey", publicKey); put("shortId", shortId)
                        filled("spx")?.let { check(it.length <= 256 && it.startsWith('/') && it.none(Char::isISOControl), "value", "spx"); put("spiderX", it) }
                        filled("pqv")?.let { check(it.matches(Regex("[A-Za-z0-9_-]{2603}")), "value", "pqv"); put("mldsa65Verify", it) }
                    })
                })
            }
            val label = text.substringAfter('#', "").let { raw ->
                val decoded = runCatching { decode(raw) }.getOrDefault(raw)
                decoded.filterNot(Char::isISOControl).replace(Regex("\\s+"), " ")
                    .replace('\u2014', '-').replace('\u2013', '-').replace(credential, "*").trim().take(64).ifEmpty { null }
            }
            val outer = if (transport == Transport.Hysteria2 || (xhttp && alpn == listOf("h3"))) Transport.MasqueH3 else Transport.MasqueH2
            return ProxyProfile(transport, host, port, outbound, xray, outer, label, identity(link), security != "none", ech != null, obfs != null)
        }

        internal fun identity(text: String): String = "proxy-" + MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8)).take(12).joinToString("") { "%02x".format(it) }

        private fun strings(values: List<String>) = JsonArray(values.map(::JsonPrimitive))

        private fun normalizeEch(value: String): String {
            val compact = value.replace(Regex("\\s+"), "").trimEnd('=').replace('-', '+').replace('_', '/')
            check(compact.length <= 4096 && compact.matches(Regex("[A-Za-z0-9+/]+")) && compact.length % 4 != 1, "value", "ech")
            val bytes = Base64.getDecoder().decode(compact)
            check(bytes.size >= 6 && (((bytes[0].toInt() and 255) shl 8) or (bytes[1].toInt() and 255)) == bytes.size - 2, "value", "ech")
            return Base64.getEncoder().encodeToString(bytes)
        }

        private fun validatePadding(value: String): String {
            val clean = value.trim()
            check(clean.matches(Regex("[1-9][0-9]{0,5}(-[1-9][0-9]{0,5})?")), "value", "x_padding_bytes")
            val bounds = clean.split('-').map(String::toInt)
            check(bounds.size == 1 || bounds[0] <= bounds[1], "value", "x_padding_bytes")
            return clean
        }
    }
}

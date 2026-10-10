package io.github.feg55.zarp.masque

import io.github.feg55.zarp.core.*
import io.github.feg55.zarpcore.Zarpcore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*

/** The same local SOCKS interface serves WARP and imported server profiles. */
class ProxyTunnelFactory(
    private val warp: TunnelFactory,
    private val settings: suspend () -> AppSettings,
    private val routingRules: suspend (RoutingSettings) -> JsonArray,
) : TunnelFactory {
    override suspend fun open(
        strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Boolean,
        onStatus: (Boolean, String) -> Unit,
    ): TunnelHandle {
        val s = settings()
        val base = if (strategy.transport.isWarp) warp.open(strategy, endpoint, timeoutMs, persistent, onStatus) else null
        if (base != null && (!persistent || !s.routing.enabled)) return base
        var native: io.github.feg55.zarpcore.Proxy? = null
        try {
            val profile = if (base == null) ProxyProfile.parse(s.proxyUri) else null
            val outbound = profile?.outbound ?: buildJsonObject {
                put("type", "socks"); put("tag", "proxy")
                put("server", "127.0.0.1"); put("server_port", base!!.socksPort)
                put("version", "5")
            }
            val rules = if (persistent) routingRules(s.routing) else JsonArray(emptyList())
            val config = ProxyConfig.build(outbound, s.tunnelIpv6, rules, s.dns)
            // Keep creation and ownership transfer in one context; cancellation must close native resources.
            return withContext(Dispatchers.IO) {
                val proxy = Zarpcore.newProxy(config)
                native = proxy
                object : TunnelHandle {
                    override val connectMs = base?.connectMs ?: 0
                    override val socksPort = proxy.socksPort().toInt()
                    override val endpoint = base?.endpoint ?: profile!!.endpoint
                    override fun close() { proxy.close(); base?.close() }
                }
            }
        } catch (e: Throwable) {
            native?.close()
            base?.close()
            throw e
        }
    }
}

object ProxyConfig {
    fun build(outbound: JsonObject, ipv6: Boolean, rules: JsonArray = JsonArray(emptyList()), dns: String = "1.1.1.1"): String = buildJsonObject {
        // Disable destination logging: URLs, IPs and credentials do not belong in the app log.
        put("log", buildJsonObject { put("disabled", true) })
        put("inbounds", buildJsonArray { add(buildJsonObject {
            put("type", "socks"); put("tag", "in")
            put("listen", "127.0.0.1"); put("listen_port", 0)
        }) })
        put("outbounds", buildJsonArray {
            add(outbound)
            add(buildJsonObject { put("type", "direct"); put("tag", "direct"); put("domain_resolver", "bootstrap") })
        })
        put("dns", buildJsonObject {
            put("servers", buildJsonArray {
                add(buildJsonObject { put("type", "local"); put("tag", "bootstrap") })
                add(buildJsonObject { put("type", "udp"); put("tag", "remote"); put("server", dns.split(',').firstOrNull { it.isNotBlank() }?.trim() ?: "1.1.1.1"); put("detour", "proxy") })
            })
            put("final", "remote")
            put("strategy", if (ipv6) "prefer_ipv4" else "ipv4_only")
            put("reverse_mapping", rules.isNotEmpty())
        })
        put("route", buildJsonObject {
            put("final", "proxy")
            put("default_domain_resolver", "remote")
            put("rules", buildJsonArray {
                if (rules.isNotEmpty()) add(buildJsonObject {
                    put("action", "sniff")
                    put("sniffer", buildJsonArray { add(JsonPrimitive("http")); add(JsonPrimitive("tls")); add(JsonPrimitive("quic")) })
                    put("timeout", "300ms")
                })
                // Health checks must measure the proxy, even if a country bypass matches Cloudflare.
                add(buildJsonObject { put("domain", buildJsonArray { add(JsonPrimitive("www.cloudflare.com")) }); put("outbound", "proxy") })
                if (rules.isNotEmpty()) {
                    add(buildJsonObject { put("port", 53); put("action", "hijack-dns") })
                    add(buildJsonObject { put("action", "resolve"); put("strategy", if (ipv6) "prefer_ipv4" else "ipv4_only") })
                    rules.forEach(::add)
                }
            })
        })
    }.toString()
}

package io.github.feg55.zarp.masque

import io.github.feg55.zarp.core.*
import io.github.feg55.zarpcore.Zarpcore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import io.github.feg55.zarp.net.OperationResolver
import io.github.feg55.zarp.strategy.BlobSource
import io.github.feg55.zarpcore.SocketFactory

/** The same local SOCKS interface serves WARP and imported server profiles. */
class ProxyTunnelFactory(
    private val warp: TunnelFactory,
    private val settings: suspend () -> AppSettings,
    private val routingRules: suspend (RoutingSettings) -> JsonArray,
    private val blobs: BlobSource,
    private val protector: SocketProtector,
    private val resolver: OperationResolver = OperationResolver(),
) : TunnelFactory {
    private var operationSettings: AppSettings? = null
    override fun beginOperation(settings: AppSettings) {
        operationSettings = settings
        resolver.clear()
        warp.beginOperation(settings)
    }
    override suspend fun open(
        strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Boolean,
        onStatus: (Boolean, String) -> Unit,
    ): TunnelHandle {
        val s = operationSettings ?: settings()
        val base = if (strategy.isWarp) warp.open(strategy, endpoint, timeoutMs, persistent, onStatus) else null
        if (base != null && (!persistent || !s.routing.enabled)) return base
        var native: io.github.feg55.zarpcore.Proxy? = null
        try {
            val profile = if (base == null) requireNotNull(strategy.profile) else null
            strategy.unsupported?.let { throw ZarpException(it) }
            val address = profile?.let { resolver.resolve(it.host) }
            val outbound = profile?.outbound ?: buildJsonObject {
                put("type", "socks"); put("tag", "proxy")
                put("server", "127.0.0.1"); put("server_port", base!!.socksPort)
                put("version", "5")
            }
            val rules = if (persistent) routingRules(s.routing) else JsonArray(emptyList())
            val dial = profile?.takeIf { it.xrayOutbound == null }?.let { buildJsonObject {
                put("type", "zarp-dial"); put("tag", "server-dial"); put("server", it.host); put("server_port", it.port)
            } }
            val config = ProxyConfig.build(outbound, s.tunnelIpv6, rules, s.dns, dial)
            // Keep creation and ownership transfer in one context; cancellation must close native resources.
            return withContext(Dispatchers.IO) {
                val proxy = if (profile == null) Zarpcore.newProxy(config) else {
                    val options = Zarpcore.newServerOptions().apply {
                        setServer(profile.host, address!!, profile.port.toLong())
                        setQUIC(profile.outerTransport == Transport.MasqueH3)
                        setConnectTimeoutMs(timeoutMs.toLong())
                        setTCPDesync(strategy.plan.tcpDesync.orEmpty())
                        strategy.plan.fakes.forEach { fake ->
                            addBlob(fake.blob.key, blobs.bytes(fake.blob))
                            addFake(fake.blob.key, fake.repeats.toLong(), (fake.ipTtl ?: 0).toLong(), (fake.ip6Ttl ?: 0).toLong())
                        }
                        profile.xrayOutbound?.let { setXrayOutbound(profile.buildXrayOutbound(address).toString()) }
                    }
                    val sockets = object : SocketFactory {
                        override fun openUDP(host: String, port: Long): Long = error("server sockets are owned by the core")
                        override fun protect(fd: Long) = protector.protect(fd.toInt())
                    }
                    try { Zarpcore.newServerProxy(config, options, sockets) }
                    catch (e: Exception) { throw ZarpException(ServerErrors.describe("", e.message.orEmpty())) }
                }
                native = proxy
                object : TunnelHandle {
                    override val connectMs = base?.connectMs ?: 0
                    override val socksPort = proxy.socksPort().toInt()
                    override val endpoint = base?.endpoint ?: profile!!.endpoint
                    override fun failure(): Msg? = if (profile == null) null else ServerErrors.describe(proxy.lastError(), proxy.lastDetail())
                    override fun strategyApplied(): Boolean = profile == null || strategy.plain ||
                        if (profile.outerTransport == Transport.MasqueH3) proxy.fakeFlowCount() > 0 && proxy.fakeFlowCount() == proxy.serverConnections()
                        else proxy.splitCount() > 0 && proxy.splitCount() == proxy.serverConnections()
                    override fun metrics() = if (profile == null) null else TunnelMetrics(proxy.serverConnections(), proxy.splitCount(),
                        proxy.fakeFlowCount(), proxy.fakePacketCount(), proxy.foreignConnections())
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
    fun build(outbound: JsonObject, ipv6: Boolean, rules: JsonArray = JsonArray(emptyList()), dns: String = "1.1.1.1", serverDial: JsonObject? = null): String = buildJsonObject {
        // Disable destination logging: URLs, IPs and credentials do not belong in the app log.
        put("log", buildJsonObject { put("disabled", true) })
        put("inbounds", buildJsonArray { add(buildJsonObject {
            put("type", "socks"); put("tag", "in")
            put("listen", "127.0.0.1"); put("listen_port", 0)
        }) })
        put("outbounds", buildJsonArray {
            add(outbound)
            serverDial?.let(::add)
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

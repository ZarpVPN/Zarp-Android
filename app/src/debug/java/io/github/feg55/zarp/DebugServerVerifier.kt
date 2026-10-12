package io.github.feg55.zarp

import io.github.feg55.zarp.core.*
import io.github.feg55.zarp.masque.ProxyTunnelFactory
import io.github.feg55.zarp.net.*
import io.github.feg55.zarp.strategy.BlobStore
import io.github.feg55.zarp.vpn.AndroidOperationLifetime
import io.github.feg55.zarp.vpn.VpnServiceController
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.coroutines.*
import kotlinx.serialization.json.*

/** adb-only verification: isolated settings/results, a throwaway server and a pinned test CA. */
object DebugServerVerifier {
    private var engine: ZarpEngine? = null
    private var handle: TunnelHandle? = null
    private var deadline: Job? = null

    fun start(app: ZarpApp): Boolean {
        if (engine != null || app.engine.status.value.state.busy || app.engine.activePair.value != null ||
            AndroidNetworkInspector(app).foreignVpnActive()) return false
        app.appScope.launch {
            try {
                app.privateServerDiagnostics = true
                val input = Json.parseToJsonElement(File(app.cacheDir, "verification-config.json").readText()).jsonObject
                val profile = ProxyProfile.parse(input.getValue("link").jsonPrimitive.content)
                val directHost = input.getValue("directHost").jsonPrimitive.content
                val settings = AppSettings(useProxy = true, proxyUri = input.getValue("link").jsonPrimitive.content,
                    perAppProxy = true, proxyApps = setOf("io.github.feg55.zarp.trafficprobe"), tunnelIpv6 = false,
                    customEndpoints = "deliberately invalid WARP endpoint",
                    routing = RoutingSettings(enabled = true, selectedPreset = "verification", presets = listOf(
                        RoutingPreset("verification", direct = directHost + "/32", proxy = "192.0.2.20/32", block = "198.51.100.20/32"))))
                val store = object : ZarpStore {
                    var results = emptyMap<String, TestResult>()
                    var selected: String? = null
                    override suspend fun settings() = settings
                    override suspend fun results() = results
                    override suspend fun saveResults(results: Map<String, TestResult>) { this.results = results }
                    override suspend fun selectedStrategyId() = selected
                    override suspend fun setSelectedStrategyId(id: String?) { selected = id }
                }
                val vpn = VpnServiceController(app) { settings }
                val noWarp = object : TunnelFactory {
                    override suspend fun open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Boolean, onStatus: (Boolean, String) -> Unit): TunnelHandle =
                        error("WARP is not part of the device verification")
                }
                val real = ProxyTunnelFactory(noWarp, { settings }, app.geoData::compile, BlobStore { app.assets.open(it) }, vpn)
                val recording = object : TunnelFactory {
                    override fun beginOperation(settings: AppSettings) = real.beginOperation(settings)
                    override suspend fun open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Boolean, onStatus: (Boolean, String) -> Unit): TunnelHandle =
                        real.open(strategy, endpoint, timeoutMs, persistent, onStatus).also { handle = it }
                }
                val verifier = ZarpEngine(app.appScope, store, recording, testProbe(input.getValue("certificate").jsonPrimitive.content), vpn,
                    object : WarpAccount {
                        override val registered = true
                        override suspend fun ensureRegistered() = error("unexpected WARP registration")
                    }, AndroidNetworkInspector(app), LogBus(),
                    capabilities = CapabilitySnapshot(io.github.feg55.zarpcore.Zarpcore.canSetUDPTTL(), io.github.feg55.zarpcore.Zarpcore.canSetTCPTTL()),
                    lifetime = AndroidOperationLifetime(app))
                engine = verifier
                verifier.load()
                val strategy = verifier.strategies.value.single { it.id == input.getValue("strategy").jsonPrimitive.content + "@" + profile.id }
                verifier.useStrategy(strategy)
                while (verifier.status.value.state.busy || verifier.status.value.state == EngineState.Idle) delay(50)
                snapshot(app)
                // A forgotten test session cannot leave a VPN running indefinitely.
                deadline = app.appScope.launch { delay(180_000); stop(app) }
            } catch (_: Exception) {
                File(app.cacheDir, "verification-result.json").writeText("""{"state":"SetupError"}""")
                stop(app)
            }
        }
        return true
    }

    fun snapshot(app: ZarpApp): Boolean {
        val current = engine ?: return false
        val m = handle?.metrics()
        File(app.cacheDir, "verification-result.json").writeText(buildJsonObject {
            put("state", current.status.value.state.name)
            put("errorKey", current.status.value.detail.key)
            put("activePair", current.activePair.value?.id.orEmpty())
            put("connections", m?.connections ?: 0); put("splits", m?.splits ?: 0)
            put("fakeFlows", m?.fakeFlows ?: 0); put("fakePackets", m?.fakePackets ?: 0)
            put("foreignConnections", m?.foreignConnections ?: 0)
            put("nativeFailure", handle?.failure()?.key.orEmpty())
            put("vpnService", io.github.feg55.zarp.vpn.ZarpVpnService.instance != null)
            put("udpTtl", io.github.feg55.zarpcore.Zarpcore.canSetUDPTTL())
            put("tcpTtl", io.github.feg55.zarpcore.Zarpcore.canSetTCPTTL())
        }.toString())
        return true
    }

    fun stop(app: ZarpApp): Boolean {
        val current = engine ?: return false
        deadline?.cancel()
        current.cancel()
        app.appScope.launch {
            while (current.status.value.state.busy) delay(50)
            current.disconnect()
            while (current.status.value.state != EngineState.Idle && current.status.value.state != EngineState.Error) delay(50)
            snapshot(app)
            engine = null
            handle = null
            app.privateServerDiagnostics = false
        }
        return true
    }

    private fun testProbe(pem: String): WarpProbe {
        val ca = CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream())
        val keys = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("verification-ca", ca) }
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(keys) }
        val tlsContext = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
        return object : WarpProbe {
            override suspend fun measure(socksPort: Int, samples: Int) = measureProxy(socksPort, samples)
            override suspend fun measureProxy(socksPort: Int, samples: Int): Measurement =
                TraceClient.measureWith(samples, System::nanoTime, requireWarp = false) {
                    withContext(Dispatchers.IO) {
                        Socket().use { raw ->
                            raw.soTimeout = 5000
                            raw.connect(InetSocketAddress("127.0.0.1", socksPort), 5000)
                            Socks5.connect(raw.getInputStream(), raw.getOutputStream(), "192.0.2.20", 443)
                            (tlsContext.socketFactory.createSocket(raw, "probe.example.com", 443, true) as SSLSocket).use { tls ->
                                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                                tls.startHandshake()
                                tls.outputStream.write("GET /cdn-cgi/trace HTTP/1.1\r\nHost: probe.example.com\r\nConnection: close\r\n\r\n".toByteArray())
                                tls.outputStream.flush()
                                TraceClient.parseHttp(tls.inputStream.bufferedReader().readText())
                            }
                        }
                    }
                }
        }
    }
}

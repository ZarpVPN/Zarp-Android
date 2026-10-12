package io.github.feg55.zarp.core

import io.github.feg55.zarp.data.DataStoreZarpStore
import io.github.feg55.zarp.net.Measurement
import io.github.feg55.zarp.net.OperationResolver
import io.github.feg55.zarp.net.WarpProbe
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ServerEngineTest {
    private val firstLink = "vless://00000000-0000-4000-8000-000000000001@first.example.com:443?security=tls#First"
    private val secondLink = firstLink.replace("first.example.com", "second.example.com").replace("#First", "#Second")
    private val source = "https://subscription.example.com/list?token=test-token"
    private fun settings(links: List<String> = listOf(firstLink, secondLink)) = AppSettings(
        useProxy = true, proxyUri = source, subscription = SubscriptionSnapshot(Subscription.sourceId(source), links, 1000),
        stopAfterWorking = 1, customEndpoints = "invalid WARP endpoint", isolateTests = true,
    )
    private fun pair(strategy: String, link: String = firstLink) = strategy + "@" + ProxyProfile.parse(link).id
    @Before fun language() = TestLang.english()

    private data class Dpi(
        val firstPass: Boolean = true, val samplesPass: Boolean = true, val applied: Boolean = true,
        val connect: Int = 40, val ping: Int = 10, val wait: Boolean = false,
        val rawFailure: Boolean = false,
    )
    private class Memory(var value: AppSettings) : ZarpStore {
        var saved = emptyMap<String, TestResult>()
        var selected: String? = null
        override suspend fun settings() = value
        override suspend fun results() = saved
        override suspend fun saveResults(results: Map<String, TestResult>) { saved = results.toMap() }
        override suspend fun selectedStrategyId() = selected
        override suspend fun setSelectedStrategyId(id: String?) { selected = id }
    }
    private class Env(
        scope: TestScope, settings: AppSettings, val script: Map<String, List<Dpi>> = emptyMap(),
        capabilities: StrategyCapabilities = CapabilitySnapshot(),
        refresh: suspend (AppSettings) -> AppSettings = { it },
        foreignVpn: Boolean = false,
    ) {
        val store = Memory(settings)
        val logs = LogBus()
        val opened = mutableListOf<Pair<String, Boolean>>()
        val probed = mutableListOf<Pair<String, Int>>()
        var closed = 0
        var started = 0
        var stopped = 0
        var lifetimeStarted = 0
        var lifetimeStopped = 0
        var postVpnWorks = true
        private var nextPort = 10000
        private val ports = mutableMapOf<Int, Pair<String, Dpi>>()
        private val uses = mutableMapOf<String, Int>()
        val resolverCalls = mutableMapOf<String, Int>()
        val resolver = OperationResolver { host ->
            resolverCalls[host] = resolverCalls.getOrDefault(host, 0) + 1
            "192.0.2.1"
        }
        val tunnels = object : TunnelFactory {
            override fun beginOperation(settings: AppSettings) { resolver.clear() }
            override suspend fun open(strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Boolean, onStatus: (Boolean, String) -> Unit): TunnelHandle {
                opened += strategy.id to persistent
                assertNull(endpoint)
                resolver.resolve(strategy.profile!!.host)
                val n = uses.getOrDefault(strategy.id, 0)
                uses[strategy.id] = n + 1
                val steps = script[strategy.id].orEmpty()
                val dpi = steps.getOrElse(n) { steps.lastOrNull() ?: Dpi(firstPass = false, samplesPass = false) }
                if (dpi.rawFailure) throw TunnelException("refused first.example.com test-token test-password")
                val port = nextPort++
                ports[port] = strategy.id to dpi
                return object : TunnelHandle {
                    override val connectMs = dpi.connect
                    override val socksPort = port
                    override val endpoint = "192.0.2.1:443"
                    override fun failure() = Msg("server.err.refused")
                    override fun strategyApplied() = dpi.applied
                    override fun close() { closed++ }
                }
            }
        }
        val probe = object : WarpProbe {
            override suspend fun measure(socksPort: Int, samples: Int): Measurement = error("WARP must not be probed")
            override suspend fun measureProxy(socksPort: Int, samples: Int): Measurement {
                val (id, dpi) = ports.getValue(socksPort)
                probed += id to samples
                if (dpi.wait) awaitCancellation()
                val pass = if (started > 0 && samples == 0) postVpnWorks else if (samples == 0) dpi.firstPass else dpi.samplesPass
                return if (pass) Measurement.Ok(dpi.ping, "off", dpi.connect) else Measurement.NoTraffic("secret diagnostic")
            }
        }
        val engine = ZarpEngine(scope, store, tunnels, probe, object : VpnController {
            override suspend fun start(socksPort: Int, sessionName: String) { started++ }
            override suspend fun stop() { stopped++ }
        }, object : WarpAccount {
            override val registered = false
            override suspend fun ensureRegistered() = error("WARP registration in server mode")
        }, { foreignVpn }, logs, clock = { 2000 }, refreshServers = refresh, capabilities = capabilities,
            lifetime = object : OperationLifetime {
                override suspend fun start() { lifetimeStarted++ }
                override suspend fun stop() { lifetimeStopped++ }
            })
    }

    @Test fun anotherVpnStillRefusesServerOperationsBeforeOpeningTunnels() = runTest {
        val env = Env(this, settings(), foreignVpn = true)
        env.engine.load()
        env.engine.search(full = false)
        advanceUntilIdle()
        assertEquals(EngineState.Error, env.engine.status.value.state)
        assertEquals("server.otherVpn", env.engine.status.value.detail.key)
        assertTrue(env.opened.isEmpty())
        assertEquals(0, env.started)
        assertNull(env.engine.activePair.value)
    }

    @Test fun pairsAreStrategyMajorAndOnlyMatchOuterTransport() {
        val tcp = ProxyProfile.parse(firstLink)
        val udp = ProxyProfile.parse("hy2://test-password@quic.example.com:443?obfs=salamander&obfs-password=test-obfs")
        val raw = Strategy("raw", "Raw", Transport.MasqueH3, "--lua-desync=fake:blob=quic_google:badsum")
        val wg = Strategy("wg", "WG", Transport.WireGuard, "--lua-desync=fake:blob=zero64")
        val custom = Strategy("custom", "Custom", Transport.MasqueH2, "--lua-desync=multisplit:pos=1")
        val pairs = ServerPairs.build(StrategyCatalog.builtIn + raw + wg + custom, listOf(tcp, udp))
        assertEquals(pair("warp-q-google6", "hy2://test-password@quic.example.com:443?obfs=salamander&obfs-password=test-obfs"), pairs.first().id)
        assertTrue(pairs.all { it.usesDesync && it.profile != null && it.transport == it.profile.outerTransport })
        assertTrue(pairs.none { it.id.startsWith("direct") || it.id.startsWith("raw") || it.id.startsWith("wg") })
        assertTrue(pairs.any { it.id == pair("custom") })
        assertTrue(pairs.all { !it.name.startsWith("WARP ") })
        val plain = ProxyProfile.parse(firstLink.replace("security=tls", "security=none"))
        assertTrue(ServerPairs.build(StrategyCatalog.builtIn, listOf(plain)).isEmpty())
        val explicit = ServerPairs.build(StrategyCatalog.builtIn, listOf(plain), allowPlain = true).single()
        assertTrue(explicit.plain && explicit.supported)
    }

    @Test fun firstFailureSkipsMeasurementsAndQuickCountsConfirmedPairs() = runTest {
        val split1 = pair("warp-t-split")
        val split2 = pair("warp-t-split", secondLink)
        val disorder1 = pair("warp-t-disorder")
        val env = Env(this, settings(), mapOf(split2 to listOf(Dpi(), Dpi(firstPass = false)),
            disorder1 to listOf(Dpi(connect = 70, ping = 20))))
        env.engine.load()
        env.engine.search(full = false)
        advanceUntilIdle()
        assertEquals(listOf(split1, split2, split2, disorder1, disorder1, disorder1), env.opened.map { it.first })
        assertEquals(listOf(0), env.probed.filter { it.first == split1 }.map { it.second })
        assertFalse(env.store.saved.getValue(split2).ok)
        assertTrue(env.store.saved.getValue(disorder1).confirmed)
        assertEquals(150, env.store.saved.getValue(disorder1).score)
        assertEquals(disorder1, env.store.selected)
        assertEquals(disorder1, env.engine.activePair.value!!.id)
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        assertEquals(mapOf("first.example.com" to 1, "second.example.com" to 1), env.resolverCalls)
        assertEquals(1, env.lifetimeStarted)
        assertEquals(1, env.lifetimeStopped)
    }

    @Test fun fullScanTestsEntireUniverseAndAppliesBestScore() = runTest {
        val a = pair("warp-t-split")
        val b = pair("warp-t-split", secondLink)
        val env = Env(this, settings(), mapOf(a to listOf(Dpi(connect = 100, ping = 30)),
            b to listOf(Dpi(connect = 60, ping = 10))))
        env.engine.load()
        val expected = env.engine.strategies.value.map { it.id }
        env.engine.search(full = true)
        advanceUntilIdle()
        val tests = env.opened.filter { !it.second }.map { it.first }
        assertEquals(expected, tests.distinct())
        assertEquals(2, tests.count { it == a })
        assertEquals(2, tests.count { it == b })
        assertEquals(b, env.store.selected)
    }

    @Test fun savedPairThenVerifiedPairsByScoreWithoutNewScan() = runTest {
        val saved = pair("warp-t-split")
        val next = pair("warp-t-split", secondLink)
        val slow = pair("warp-t-disorder")
        val env = Env(this, settings(), mapOf(next to listOf(Dpi())))
        env.store.selected = saved
        env.store.saved = listOf(saved to 5, next to 20, slow to 50).associate { (id, ping) ->
            id to TestResult(id, ok = true, confirmed = true, connectMs = 10, pingMs = ping)
        }
        env.engine.load()
        env.engine.connect()
        advanceUntilIdle()
        assertEquals(listOf(saved, next), env.opened.map { it.first })
        assertTrue(env.opened.all { it.second })
        assertEquals(next, env.store.selected)
        assertFalse(env.store.saved.getValue(saved).ok)
    }

    @Test fun filtersNeverPruneOtherServerResultsAndRefreshNeverSwitchesActivePair() = runTest {
        val a = pair("warp-t-split")
        val b = pair("warp-t-split", secondLink)
        val env = Env(this, settings().copy(serverSelectionId = ProxyProfile.parse(firstLink).id), mapOf(a to listOf(Dpi())))
        env.store.saved = mapOf(b to TestResult(b, ok = true, confirmed = true, connectMs = 20, pingMs = 10))
        env.engine.load()
        env.engine.useStrategy(env.engine.strategies.value.single { it.id == a })
        advanceUntilIdle()
        assertTrue(b in env.store.saved)
        val active = env.engine.activePair.value
        env.store.value = settings(listOf(secondLink)).copy(strategyCountry = "cn", serverSelectionId = ProxyProfile.parse(firstLink).id)
        env.engine.refreshSavedState()
        assertSame(active, env.engine.activePair.value)
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        assertFalse(a in env.store.saved)
        env.engine.connect()
        advanceUntilIdle()
        assertEquals("server.unavailable", env.engine.status.value.detail.key)
        assertNull(env.engine.activePair.value)
        assertEquals(ProxyProfile.parse(firstLink).id, env.store.value.serverSelectionId)
    }

    @Test fun removedResultsAndOldPlainSelectionCannotCertifyPairs() = runTest {
        val old = ProxyProfile.parse(firstLink).id
        val env = Env(this, settings())
        env.store.selected = old
        env.store.saved = mapOf(old to TestResult(old, ok = true, confirmed = true),
            "warp-wg-google6" to TestResult("warp-wg-google6", ok = true))
        env.engine.load()
        assertTrue(env.store.saved.isEmpty())
        assertNull(env.store.selected)
        assertTrue(DataStoreZarpStore.migrateLegacyResults(DataStoreZarpStore.encodeResults(mapOf(old to TestResult(old)))).isEmpty())
    }

    @Test fun nativeStrategyProofAndPostVpnFailureTearDownEverything() = runTest {
        val id = pair("warp-t-split")
        val noSplit = Env(this, settings(), mapOf(id to listOf(Dpi(applied = false))))
        noSplit.engine.load()
        noSplit.engine.testStrategies(noSplit.engine.strategies.value.filter { it.id == id })
        advanceUntilIdle()
        assertEquals("proxy.noHandshake", noSplit.store.saved.getValue(id).errorKey)
        assertEquals(0, noSplit.started)
        val afterVpn = Env(this, settings(), mapOf(id to listOf(Dpi())))
        afterVpn.postVpnWorks = false
        afterVpn.engine.load()
        afterVpn.engine.useStrategy(afterVpn.engine.strategies.value.single { it.id == id })
        advanceUntilIdle()
        assertEquals(1, afterVpn.started)
        assertEquals(1, afterVpn.closed)
        assertTrue(afterVpn.stopped >= 2)
        assertNull(afterVpn.engine.activePair.value)
        assertEquals(EngineState.Error, afterVpn.engine.status.value.state)
    }

    @Test fun capabilitiesGateOnlyTtlStrategiesAndCancellationClosesProbe() = runTest {
        val id = pair("warp-t-split")
        val env = Env(this, settings(), mapOf(id to listOf(Dpi(wait = true))), CapabilitySnapshot(false, false))
        env.engine.load()
        assertEquals("unsup.tcpTtl", env.engine.strategies.value.single { it.id == pair("warp-t-disorder") }.unsupported!!.key)
        env.engine.search(full = false)
        runCurrent()
        assertEquals(1, env.opened.size)
        env.engine.cancel()
        advanceUntilIdle()
        assertEquals(1, env.closed)
        assertEquals(EngineState.Idle, env.engine.status.value.state)
        assertEquals(1, env.lifetimeStopped)
        assertTrue(env.engine.search(full = false))
        runCurrent()
        env.engine.cancel()
        advanceUntilIdle()
    }

    @Test fun resolveOnceCachesSuccessAndFailureAndResetsPerOperation() = runTest {
        var count = 0
        val resolver = OperationResolver { host -> count++; if (host.startsWith("bad")) error("secret endpoint") else "192.0.2.3" }
        repeat(3) { assertEquals("192.0.2.3", resolver.resolve("good.example.com")) }
        repeat(3) { assertEquals("server.err.dns", (runCatching { resolver.resolve("bad.example.com") }.exceptionOrNull() as ZarpException).msg.key) }
        assertEquals(2, count)
        resolver.clear()
        resolver.resolve("good.example.com")
        assertEquals(3, count)
    }

    @Test fun aLoneSavedPlainCandidateIsNeverScannedAgainAndNoTlsNeedsExplicitChoice() = runTest {
        val plain = firstLink.replace("security=tls", "security=none")
        val refused = Env(this, settings(listOf(plain)))
        refused.engine.load()
        refused.engine.connect()
        advanceUntilIdle()
        assertEquals("proxy.noHandshake", refused.engine.status.value.detail.key)
        assertTrue(refused.opened.isEmpty())
        val explicit = Env(this, settings(listOf(plain)).copy(allowPlainServer = true))
        val id = "server-plain@" + ProxyProfile.parse(plain).id
        explicit.store.selected = id
        explicit.engine.load()
        explicit.engine.connect()
        advanceUntilIdle()
        assertEquals(listOf(id), explicit.opened.map { it.first })
        assertTrue(explicit.opened.single().second)
    }

    @Test fun udpCapabilityFailuresRemainVisibleButNeverOpenTunnels() = runTest {
        val hy2 = "hy2://test-password@quic.example.com:443"
        val env = Env(this, settings(listOf(hy2)), capabilities = CapabilitySnapshot(false, true))
        env.engine.load()
        val ttl = env.engine.strategies.value.filter { it.id.startsWith("warp-q-google-ttl@") || it.id.startsWith("warp-q-vk-ttl@") }
        assertEquals(2, ttl.size)
        assertTrue(ttl.all { it.unsupported?.key == "unsup.udpTtl" })
        env.engine.testStrategies(ttl)
        advanceUntilIdle()
        assertTrue(env.opened.isEmpty())
        assertTrue(ttl.all { env.store.saved.getValue(it.id).unsupported })
    }

    @Test fun serverDiagnosticsAndLogsNeverCarryLinkSecrets() = runTest {
        val id = pair("warp-t-split")
        val env = Env(this, settings(), mapOf(id to listOf(Dpi(rawFailure = true))))
        env.engine.load()
        env.engine.testStrategies(env.engine.strategies.value.filter { it.id == id })
        advanceUntilIdle()
        assertEquals("server.err.refused", env.store.saved.getValue(id).errorKey)
        val text = env.logs.lines.value.joinToString() + env.store.saved.values.joinToString { it.logError }
        for (secret in listOf("first.example.com", "second.example.com", "test-token", "test-password", "vless://")) assertFalse(text.contains(secret))
        for (kind in listOf("refused", "timeout", "unreachable", "reset", "certificate", "ech", "reality", "status", "ttl", "protect", "blocked", "other")) {
            val msg = ServerErrors.describe(kind, "test-password first.example.com")
            assertEquals("server.err." + kind, msg.key)
            assertFalse(msg.toString().contains("test-password"))
        }
    }
}

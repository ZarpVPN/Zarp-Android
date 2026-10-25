package io.github.feg55.zarp.core

import io.github.feg55.zarp.net.Measurement
import io.github.feg55.zarp.net.WarpProbe
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The Zarp algorithm (quick/full scan, re-check, scoring, saved strategy first)
 * against scripted tunnels. Each strategy's behaviour is a queue of outcomes, one
 * per tunnel opened with it.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class ZarpEngineTest {
    private class InMemoryStore(private val settings: AppSettings) : ZarpStore {
        var saved: Map<String, TestResult> = emptyMap()
        var selected: String? = null
        override suspend fun settings() = settings
        override suspend fun results() = saved
        override suspend fun saveResults(results: Map<String, TestResult>) { saved = results }
        override suspend fun selectedStrategyId() = selected
        override suspend fun setSelectedStrategyId(id: String?) { selected = id }
    }

    private sealed interface Outcome {
        data class Works(val connectMs: Int, val pingMs: Int, val warp: String = "on") : Outcome
        data object Timeout : Outcome
    }

    private class Opened(val strategyId: String, val endpoint: String?, val persistent: Boolean, val transport: Transport)

    private class Env(scope: TestScope, private val script: Map<String, List<Outcome>>, settings: AppSettings = AppSettings(tosAccepted = true), foreignVpn: Boolean = false) {
        val opened = mutableListOf<Opened>()
        val vpnStarts = mutableListOf<Int>()
        var vpnStops = 0
        private val uses = mutableMapOf<String, Int>()
        private val portOutcome = mutableMapOf<Int, Outcome.Works>()
        private var nextPort = 20000
        var closed = 0
        var accountStrategies = emptyList<Strategy>()
        var protectedRegistration = false
        var accountFailure = false
        var accountType = WarpAccountType.Free
        var trafficHealthy = true
        var online = true
        var pendingProbe: CompletableDeferred<Unit>? = null

        val store = InMemoryStore(settings)

        private fun outcome(id: String): Outcome {
            val list = script[id] ?: return Outcome.Timeout
            val n = uses.getOrDefault(id, 0)
            uses[id] = n + 1
            return list.getOrElse(n) { list.last() }
        }

        val tunnels = object : TunnelFactory {
            override suspend fun open(
                strategy: Strategy, endpoint: String?, timeoutMs: Int, persistent: Boolean,
                onStatus: (Boolean, String) -> Unit,
            ): TunnelHandle {
                opened += Opened(strategy.id, endpoint, persistent, strategy.transport)
                when (val o = outcome(strategy.id)) {
                    Outcome.Timeout -> throw TunnelException("timeout after $timeoutMs ms", timeout = true)
                    is Outcome.Works -> {
                        val port = nextPort++
                        portOutcome[port] = o
                        return object : TunnelHandle {
                            override val connectMs = o.connectMs
                            override val socksPort = port
                            override val endpoint = endpoint ?: "162.159.198.1:443"
                            override fun close() { closed++ }
                        }
                    }
                }
            }
        }

        val probe = object : WarpProbe {
            override suspend fun measure(socksPort: Int, samples: Int): Measurement {
                pendingProbe?.await()
                if (!trafficHealthy) return Measurement.NoTraffic(null)
                val o = portOutcome.getValue(socksPort)
                return if (o.warp == "on" || o.warp == "plus") Measurement.Ok(o.pingMs, o.warp) else Measurement.NotWarp(o.warp)
            }
        }

        val vpn = object : VpnController {
            override suspend fun start(socksPort: Int, sessionName: String) { vpnStarts += socksPort }
            override suspend fun stop() { vpnStops++ }
        }

        val account = object : WarpAccount {
            override var registered = true
            override suspend fun ensureRegistered() = Unit
            override suspend fun ensureRegistered(strategies: List<Strategy>, allowProtected: Boolean, progress: (Int, Int, Strategy) -> Unit) {
                accountStrategies = strategies
                protectedRegistration = allowProtected
                if (accountFailure) throw WarpAccountException("network")
            }
            override suspend fun readAccount() = accountType
            override suspend fun applyLicense(license: String, strategies: List<Strategy>, allowProtected: Boolean,
                progress: (Int, Int, Strategy) -> Unit): WarpAccountType {
                accountStrategies = strategies
                protectedRegistration = allowProtected
                return accountType
            }
        }

        val logs = LogBus()
        val engine = ZarpEngine(scope, store, tunnels, probe, vpn, account, object : NetworkInspector {
            override fun foreignVpnActive() = foreignVpn
            override fun internetAvailable() = online
        }, logs, clock = { 1000L })
    }

    private val ids = StrategyCatalog.builtIn.map { it.id }

    @Test fun `another VPN warns without refusing WARP scan or connection`() = runTest {
        val env = Env(this, mapOf("warp-q-google6" to listOf(Outcome.Works(100, 20))),
            AppSettings(stopAfterWorking = 1), foreignVpn = true)
        env.engine.load()
        env.engine.search(full = false)
        advanceUntilIdle()
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        assertTrue(env.opened.any { !it.persistent })
        assertEquals(1, env.vpnStarts.size)
        assertTrue(env.logs.lines.value.any { it.contains(L.t("log.otherVpnActive")) })
        env.engine.disconnect()
        advanceUntilIdle()
        env.engine.connect()
        advanceUntilIdle()
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        assertEquals(2, env.vpnStarts.size)
    }

    @Test
    fun `country filter applies to saved strategies quick scan and confirmed fallback`() = runTest {
        val env = Env(this, mapOf(
            "direct" to listOf(Outcome.Works(1, 1)),
            "warp-q-vk6" to listOf(Outcome.Works(1, 1)),
            "warp-t-split" to listOf(Outcome.Works(100, 20)),
        ), AppSettings(strategyCountry = "cn", stopAfterWorking = 1))
        env.store.selected = "direct"
        env.store.saved = listOf("direct", "warp-q-vk6").associateWith {
            TestResult(it, ok = true, confirmed = true, connectMs = 1, pingMs = 1)
        }
        env.engine.load()
        env.engine.connect()
        advanceUntilIdle()
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        assertEquals("warp-t-split", env.store.selected)
        assertTrue(env.opened.none { it.strategyId == "direct" || it.strategyId == "warp-q-vk6" })
    }

    @Test
    fun `full and selected scans never apply cached results outside their filter`() = runTest {
        val env = Env(this, mapOf("direct" to listOf(Outcome.Works(1, 1))), AppSettings(strategyCountry = "ir"))
        env.store.saved = mapOf("direct" to TestResult("direct", ok = true, confirmed = true, connectMs = 1, pingMs = 1))
        env.engine.load()
        env.engine.search(full = true)
        advanceUntilIdle()
        assertTrue(env.opened.none { it.strategyId == "direct" })
        assertTrue(env.vpnStarts.isEmpty())
        env.engine.testStrategies(listOf(StrategyCatalog.builtIn.single { it.id == "direct" }))
        advanceUntilIdle()
        assertTrue(env.vpnStarts.isEmpty())
    }

    @Test
    fun `custom endpoints are used in tests rechecks and the persistent connection`() = runTest {
        val env = Env(this, mapOf("warp-q-google6" to listOf(Outcome.Works(100, 20))),
            AppSettings(customEndpoints = "1.2.3.4:8443\n5.6.7.8:443", stopAfterWorking = 1))
        env.engine.load()
        env.engine.search(full = false)
        advanceUntilIdle()
        assertEquals(listOf("1.2.3.4:8443", "5.6.7.8:443", "5.6.7.8:443"), env.opened.map { it.endpoint })
        assertEquals(EngineState.Connected, env.engine.status.value.state)
    }

    @Test
    fun `empty per-app selection refuses connection before opening any tunnel`() = runTest {
        val env = Env(this, emptyMap(), AppSettings(perAppProxy = true))
        env.engine.load()
        env.engine.connect()
        advanceUntilIdle()
        assertEquals(EngineState.Error, env.engine.status.value.state)
        assertTrue(env.opened.isEmpty())
        assertTrue(env.vpnStarts.isEmpty())
    }

    @Before
    fun setUp() = TestLang.english()

    @Test
    fun `quick scan stops after N working, rechecks them and connects with the best`() = runTest {
        val env = Env(
            this,
            mapOf(
                "warp-q-google6" to listOf(Outcome.Works(900, 100), Outcome.Works(1000, 80)),
                "warp-q-google3" to listOf(Outcome.Timeout),
                "warp-q-vk6" to listOf(Outcome.Works(300, 50), Outcome.Works(400, 70)),
                "warp-q-google-vk" to listOf(Outcome.Works(500, 60), Outcome.Works(500, 60)),
                "warp-q-google10" to listOf(Outcome.Works(100, 10)),
            ),
            AppSettings(tosAccepted = true, stopAfterWorking = 3),
        )
        env.engine.load()
        assertTrue(env.engine.search(full = false))
        advanceUntilIdle()

        // phase 1 stopped after the third working one; google10 was never tried
        val phase1 = env.opened.filter { !it.persistent }.map { it.strategyId }
        assertFalse("warp-q-google10" in phase1)
        assertEquals(listOf("warp-q-google6", "warp-q-google3", "warp-q-vk6", "warp-q-google-vk"), phase1.take(4))
        // phase 2 rechecks candidates in score order: vk6 (500), google-vk (740), google6 (1300)
        assertEquals(listOf("warp-q-vk6", "warp-q-google-vk", "warp-q-google6"), phase1.drop(4))

        val r = env.engine.results.value
        assertEquals(TestResult("warp-q-vk6", ok = true, confirmed = true, connectMs = 400, pingMs = 60, endpoint = r["warp-q-vk6"]!!.endpoint, timestamp = 1000), r["warp-q-vk6"])
        assertTrue(r["warp-q-google6"]!!.confirmed)
        assertFalse(r["warp-q-google3"]!!.ok)

        // best confirmed = vk6 (400 + 4*60 = 640) is applied, remembered and the VPN started
        val applied = env.opened.last()
        assertTrue(applied.persistent)
        assertEquals("warp-q-vk6", applied.strategyId)
        assertNull(applied.endpoint)
        assertEquals("warp-q-vk6", env.engine.selectedId.value)
        assertEquals("warp-q-vk6", env.store.selected)
        assertEquals(1, env.vpnStarts.size)
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        assertEquals(400, env.engine.status.value.connectMs)
        assertEquals(env.engine.results.value, env.store.saved)
    }

    @Test
    fun `every test goes to its own endpoint`() = runTest {
        val env = Env(this, mapOf("direct" to listOf(Outcome.Works(100, 10))))
        env.engine.load()
        env.engine.search(full = true)
        advanceUntilIdle()
        val tested = env.opened.filter { !it.persistent && it.transport == Transport.MasqueH3 }.map { it.endpoint!! }
        assertTrue(tested.size > 2)
        // like Zarp's NextEndpoint: an HTTP/3 test never reuses the previous test's endpoint
        tested.zipWithNext().forEach { (a, b) -> assertTrue("$a then $b", a != b) }
        // the recheck of "direct" runs on a different endpoint than its first test
        val direct = env.opened.filter { !it.persistent && it.strategyId == "direct" }.map { it.endpoint }
        assertEquals(2, direct.size)
        assertTrue(direct[0] != direct[1])
    }

    @Test
    fun `candidate failing the recheck is not confirmed and not used`() = runTest {
        val env = Env(this, mapOf("warp-q-google6" to listOf(Outcome.Works(300, 30), Outcome.Timeout)))
        env.engine.load()
        env.engine.search(full = true)
        advanceUntilIdle()
        val r = env.engine.results.value.getValue("warp-q-google6")
        assertFalse(r.ok)
        assertTrue(r.rechecked)
        assertEquals("not confirmed: no connection within 15 s", r.displayError)
        assertTrue(env.vpnStarts.isEmpty())
        assertEquals(EngineState.Error, env.engine.status.value.state)
        assertNull(env.engine.selectedId.value)
    }

    @Test fun `quick scan continues until N candidates pass independent confirmation`() = runTest {
        val env = Env(this, mapOf(
            "warp-q-google6" to listOf(Outcome.Works(100, 10), Outcome.Timeout),
            "warp-q-google3" to listOf(Outcome.Works(200, 20)),
        ), AppSettings(stopAfterWorking = 1, tosAccepted = true))
        env.engine.load()
        env.engine.search(full = false)
        advanceUntilIdle()
        assertFalse(env.engine.results.value.getValue("warp-q-google6").confirmed)
        assertTrue(env.engine.results.value.getValue("warp-q-google3").confirmed)
        assertEquals("warp-q-google3", env.store.selected)
        assertEquals(listOf("warp-q-google6", "warp-q-google6", "warp-q-google3", "warp-q-google3"),
            env.opened.filter { !it.persistent }.map { it.strategyId })
    }

    @Test fun `failures through a foreign VPN never overwrite verified WARP results`() = runTest {
        val env = Env(this, emptyMap(), foreignVpn = true)
        val good = TestResult("warp-q-google6", ok = true, confirmed = true, connectMs = 100, pingMs = 10)
        env.store.saved = mapOf(good.strategyId to good)
        env.store.selected = good.strategyId
        env.engine.load()
        env.engine.search(full = true)
        advanceUntilIdle()
        assertEquals(good, env.store.saved[good.strategyId])
        assertEquals(mapOf(good.strategyId to good), env.engine.results.value)
        assertEquals(good.strategyId, env.store.selected)
    }

    @Test fun `an unconfirmed pass through a foreign VPN cannot replace a verified result`() = runTest {
        val env = Env(this, mapOf("warp-q-google6" to listOf(Outcome.Works(100, 10), Outcome.Timeout)), foreignVpn = true)
        val good = TestResult("warp-q-google6", ok = true, confirmed = true, connectMs = 200, pingMs = 20)
        env.store.saved = mapOf(good.strategyId to good)
        env.store.selected = good.strategyId
        env.engine.load()
        env.engine.search(full = true)
        advanceUntilIdle()
        assertEquals(mapOf(good.strategyId to good), env.store.saved)
        assertEquals(env.store.saved, env.engine.results.value)
    }

    @Test
    fun `warp off through the tunnel is a failure`() = runTest {
        val env = Env(this, mapOf("direct" to listOf(Outcome.Works(100, 10, warp = "off"))))
        env.engine.load()
        env.engine.testStrategies(listOf(StrategyCatalog.builtIn.single { it.id == "direct" }))
        advanceUntilIdle()
        val r = env.engine.results.value.getValue("direct")
        assertFalse(r.ok)
        assertEquals("err.notWarp", r.errorKey)
        assertTrue(r.displayError.contains("warp=off"))
    }

    @Test
    fun `unsupported strategies never open a tunnel`() = runTest {
        val env = Env(this, emptyMap(), AppSettings(customStrategies = "Raw | h3 | --lua-desync=fake:blob=quic_google:badsum"))
        env.engine.load()
        env.engine.search(full = true)
        advanceUntilIdle()
        val unsupported = env.engine.strategies.value.filter { !it.supported }.map { it.id }.toSet()
        assertTrue(unsupported.isNotEmpty())
        assertTrue(env.opened.none { it.strategyId in unsupported })
        unsupported.forEach { assertTrue(env.engine.results.value.getValue(it).unsupported) }
        assertEquals(env.engine.strategies.value.size, env.engine.results.value.size)
    }

    @Test
    fun `connect tries the saved strategy first`() = runTest {
        val env = Env(this, mapOf("warp-q-vk6" to listOf(Outcome.Works(200, 20))))
        env.store.selected = "warp-q-vk6"
        env.engine.load()
        env.engine.connect()
        advanceUntilIdle()
        assertEquals(listOf("warp-q-vk6"), env.opened.map { it.strategyId })
        assertEquals(EngineState.Connected, env.engine.status.value.state)
    }

    @Test
    fun `saved strategy fails - other confirmed ones are tried by score`() = runTest {
        val env = Env(
            this,
            mapOf(
                "warp-q-vk6" to listOf(Outcome.Timeout),
                "warp-q-google3" to listOf(Outcome.Timeout),
                "warp-q-google6" to listOf(Outcome.Works(500, 50)),
            ),
        )
        env.store.selected = "warp-q-vk6"
        env.store.saved = mapOf(
            "warp-q-vk6" to TestResult("warp-q-vk6", ok = true, confirmed = true, connectMs = 100, pingMs = 10),
            "warp-q-google3" to TestResult("warp-q-google3", ok = true, confirmed = true, connectMs = 200, pingMs = 10),
            "warp-q-google6" to TestResult("warp-q-google6", ok = true, confirmed = true, connectMs = 300, pingMs = 10),
            "warp-q-google10" to TestResult("warp-q-google10", ok = true, confirmed = false, connectMs = 1, pingMs = 1),
        )
        env.engine.load()
        env.engine.connect()
        advanceUntilIdle()
        assertEquals(listOf("warp-q-vk6", "warp-q-google3", "warp-q-google6"), env.opened.map { it.strategyId })
        assertEquals("warp-q-google6", env.store.selected)
        assertFalse(env.engine.results.value.getValue("warp-q-vk6").ok)
        assertEquals("failed to connect when applied", env.engine.results.value.getValue("warp-q-vk6").displayError)
        assertEquals(EngineState.Connected, env.engine.status.value.state)
    }

    @Test
    fun `no confirmed strategy works - a new quick scan starts`() = runTest {
        val env = Env(this, mapOf("warp-q-google6" to listOf(Outcome.Timeout, Outcome.Works(300, 30))))
        env.store.selected = "warp-q-google6"
        env.engine.load()
        env.engine.connect()
        advanceUntilIdle()
        val order = env.opened.map { it.strategyId }
        assertEquals("warp-q-google6", order[0]) // saved, failed
        assertTrue(order.size > 1 && !env.opened[1].persistent) // then scanning
        assertEquals(ids.filter { StrategyCatalog.builtIn.single { s -> s.id == it }.supported }.size, env.opened.count { !it.persistent } - 1)
    }

    @Test
    fun `second operation while busy is refused and disconnect stops everything`() = runTest {
        val env = Env(this, mapOf("direct" to listOf(Outcome.Works(100, 10))))
        env.store.selected = "direct"
        env.engine.load()
        assertTrue(env.engine.connect())
        assertFalse(env.engine.search(full = true))
        advanceUntilIdle()
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        val closedBefore = env.closed
        env.engine.disconnect()
        advanceUntilIdle()
        assertEquals(EngineState.Idle, env.engine.status.value.state)
        assertEquals(closedBefore + 1, env.closed)
    }

    @Test fun `registration candidates honor country selected confirmed custom and capability filters`() = runTest {
        val env = Env(this, emptyMap(), AppSettings(strategyCountry = "cn", customStrategies =
            "China | h2 | --payload=tls_client_hello --lua-desync=multisplit:pos=1,host | cn\nRussia | h2 | --payload=tls_client_hello --lua-desync=multisplit:pos=1,host | ru"))
        env.store.selected = "warp-t-split-host"
        env.store.saved = mapOf("warp-t-split-endhost" to TestResult("warp-t-split-endhost", ok = true, confirmed = true))
        env.accountFailure = true
        env.engine.load()
        val before = env.store.saved
        env.engine.connect()
        advanceUntilIdle()
        val ids = env.accountStrategies.map { it.id }
        assertEquals(listOf("warp-t-split-host", "warp-t-split-endhost"), ids.take(2))
        assertTrue("custom-china" in ids)
        assertFalse("custom-russia" in ids)
        assertTrue(env.accountStrategies.all { it.transport == Transport.MasqueH2 && it.supported && it.usesDesync })
        assertEquals(before, env.store.saved)
        assertTrue(env.protectedRegistration)
    }

    @Test fun `account commands preserve an active connection selection and results`() = runTest {
        val env = Env(this, mapOf("direct" to listOf(Outcome.Works(100, 10))))
        env.store.selected = "direct"
        env.engine.load()
        env.engine.connect()
        advanceUntilIdle()
        val before = env.engine.status.value
        val closed = env.closed
        val results = env.store.saved
        assertEquals(WarpAccountType.Free, env.engine.warpAccount())
        env.accountType = WarpAccountType.Unlimited
        assertEquals(WarpAccountType.Unlimited, env.engine.warpAccount("12345678-abcdefgh-ABCD1234"))
        assertFalse(env.protectedRegistration)
        assertEquals(before, env.engine.status.value)
        assertEquals(closed, env.closed)
        assertEquals(results, env.store.saved)
        assertEquals("direct", env.store.selected)
        assertFalse(env.engine.accountBusy.value)
    }

    @Test fun `traffic loss triggers regular reconnect without abandoning the saved strategy`() = runTest {
        val env = Env(this, mapOf("direct" to listOf(Outcome.Works(100, 10))))
        env.store.selected = "direct"
        env.engine.load()
        env.engine.connect()
        advanceUntilIdle()
        env.trafficHealthy = false
        env.engine.observeConnection()
        assertEquals(EngineState.Connecting, env.engine.status.value.state)
        env.trafficHealthy = true
        advanceUntilIdle()
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        assertEquals("direct", env.store.selected)
        assertEquals(2, env.vpnStarts.size)
        assertEquals(1, env.closed)
    }

    @Test fun `an offline link keeps native recovery and verified results intact`() = runTest {
        val env = Env(this, mapOf("direct" to listOf(Outcome.Works(100, 10))))
        env.store.selected = "direct"
        val good = TestResult("direct", ok = true, confirmed = true)
        env.store.saved = mapOf("direct" to good)
        env.engine.load(); env.engine.connect(); advanceUntilIdle()
        env.trafficHealthy = false
        env.online = false
        env.engine.observeConnection()
        advanceUntilIdle()
        assertEquals(EngineState.Connecting, env.engine.status.value.state)
        assertEquals(0, env.closed)
        assertEquals(mapOf("direct" to good), env.store.saved)
        env.trafficHealthy = true
        env.online = true
        env.engine.observeConnection()
        assertEquals(EngineState.Connected, env.engine.status.value.state)
        assertEquals(1, env.vpnStarts.size)
    }

    @Test fun `a slow monitor cannot block disconnect or restart a disconnected VPN`() = runTest {
        val env = Env(this, mapOf("direct" to listOf(Outcome.Works(100, 10))))
        env.store.selected = "direct"
        env.engine.load(); env.engine.connect(); advanceUntilIdle()
        env.pendingProbe = CompletableDeferred()
        val observation = async { env.engine.observeConnection() }
        runCurrent()
        assertTrue(env.engine.disconnect())
        advanceUntilIdle()
        observation.await()
        assertEquals(EngineState.Idle, env.engine.status.value.state)
        assertEquals(1, env.closed)
        assertEquals(1, env.vpnStarts.size)
    }
}

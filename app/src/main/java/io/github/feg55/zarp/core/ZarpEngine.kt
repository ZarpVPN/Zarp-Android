package io.github.feg55.zarp.core

import io.github.feg55.zarp.net.Measurement
import io.github.feg55.zarp.net.WarpProbe
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.coroutineContext

/** An error with a message in the current language. */
open class ZarpException(val msg: Msg, cause: Throwable? = null) : Exception(msg.toString(), cause)

/** The VPN could not be started; this is not the strategy's fault. */
class VpnStartException(reason: String, cause: Throwable? = null) : ZarpException(Msg("detail.vpnFailed", reason), cause)

/**
 * Port of Zarp's Engine (Engine.cs): strategy search, independent re-check,
 * scoring, remembering the best strategy and connecting with it.
 *
 * Differences from Windows: there is no warp-cli. Each test starts its own MASQUE
 * tunnel ([TunnelFactory]) on its own WARP endpoint, and WARP is verified through
 * that tunnel with cdn-cgi/trace ([WarpProbe]). Connecting keeps the tunnel and puts
 * the Android VPN in front of it ([VpnController]).
 */
class ZarpEngine(
    private val scope: CoroutineScope,
    private val store: ZarpStore,
    private val tunnels: TunnelFactory,
    private val probe: WarpProbe,
    private val vpn: VpnController,
    private val account: WarpAccount,
    private val network: NetworkInspector,
    private val log: LogBus,
    private val endpoints: WarpEndpoints = WarpEndpoints(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val _status = MutableStateFlow(EngineStatus())
    val status: StateFlow<EngineStatus> = _status.asStateFlow()

    private val _results = MutableStateFlow<Map<String, TestResult>>(emptyMap())
    val results: StateFlow<Map<String, TestResult>> = _results.asStateFlow()

    private val _strategies = MutableStateFlow(StrategyCatalog.builtIn)
    val strategies: StateFlow<List<Strategy>> = _strategies.asStateFlow()

    private val _selectedId = MutableStateFlow<String?>(null)
    val selectedId: StateFlow<String?> = _selectedId.asStateFlow()

    private val busy = Mutex()
    private val loaded = CompletableDeferred<Unit>()
    private var job: Job? = null
    private var settings = AppSettings()

    @Volatile
    private var active: TunnelHandle? = null

    val selected: Strategy? get() = candidates().firstOrNull { it.id == _selectedId.value }

    /** Quick scan stops after this many working strategies. */
    val quickStopAfter: Int get() = maxOf(1, settings.stopAfterWorking)

    /** Load persisted state; call once at startup. */
    suspend fun load() {
        settings = store.settings()
        reloadStrategies()
        // results of strategies that no longer exist are dropped, as in Zarp
        val known = _strategies.value.map { it.id }.toSet()
        _results.value = store.results().filterKeys { it in known }
        _selectedId.value = store.selectedStrategyId()
        val s = selected
        set(EngineState.Idle, if (s != null) Msg("detail.strategy", s.name) else Msg("detail.noStrategy"))
        loaded.complete(Unit)
    }

    private fun reloadStrategies() {
        _strategies.value = if (settings.useProxy) StrategyCatalog.forSettings(settings)
        else StrategyCatalog.load(settings.customStrategies) { log.write(L.t("log.customSkippedApp", it)) }
    }

    private fun candidates() = StrategyFilter.apply(_strategies.value, settings.strategyCountry)

    /** Refresh saved results without changing the state of a running VPN. */
    suspend fun refreshSavedState() {
        _results.value = store.results()
        _selectedId.value = store.selectedStrategyId()
        if (active == null && !_status.value.state.busy) {
            set(EngineState.Idle, selected?.let { Msg("detail.strategy", it.name) } ?: Msg("detail.noStrategy"), strategy = null)
        }
    }

    // ------------------------------------------------------------ top-level scenarios

    /** Main button: connect with the saved strategy, then other confirmed ones, else Quick Scan. */
    fun connect(): Boolean = launchOp {
        prepare()
        val s = selected
        if (s != null) {
            if (apply(s)) return@launchOp
            markFailed(s)
            val others = confirmedStrategies(except = s)
            if (others.isNotEmpty()) {
                log.write(L.t("log.savedFailed", s.name))
                if (applyFirstWorking(others)) return@launchOp
            }
            log.write(L.t("log.verifiedFailed"))
        }
        val list = candidates()
        searchAndApply(list, quickStopAfter, L.t("log.searchQuick", list.size, quickStopAfter))
    }

    /** Quick scan stops after [quickStopAfter] working strategies; Full scan tests all of them. */
    fun search(full: Boolean): Boolean = launchOp {
        prepare()
        val list = candidates()
        if (full) searchAndApply(list, 0, L.t("log.searchFull", list.size))
        else searchAndApply(list, quickStopAfter, L.t("log.searchQuick", list.size, quickStopAfter))
    }

    /** Test only the given strategies (all of them, no early stop). */
    fun testStrategies(only: List<Strategy>): Boolean = launchOp {
        prepare()
        val allowed = candidates().map { it.id }.toSet()
        val list = only.filter { it.id in allowed }
        searchAndApply(list, 0, L.t("log.searchSelected", list.size))
    }

    /** Connect with a specific strategy and remember it. */
    fun useStrategy(s: Strategy): Boolean = launchOp {
        require(candidates().any { it.id == s.id }) { L.t("filter.excluded") }
        prepare()
        if (apply(s)) saveSelected(s)
    }

    fun disconnect(): Boolean = launchOp {
        set(EngineState.Disconnecting, Msg("detail.disconnecting"))
        stopAll()
        // the status already says "Disconnected"; the line under it names the strategy to reconnect with
        set(EngineState.Idle, selected?.let { Msg("detail.strategy", it.name) } ?: Msg("detail.disconnected"))
    }

    fun cancel() {
        job?.cancel()
    }

    /** The VPN went away (revoked by the system or another VPN app, or stopped from the notification). */
    fun onVpnStopped(reason: Msg) {
        scope.launch {
            job?.cancelAndJoin()
            busy.withLock {
                val had = active != null
                active?.close()
                active = null
                if (had) {
                    log.write(reason.toString())
                    set(EngineState.Idle, reason)
                }
            }
        }
    }

    private fun launchOp(body: suspend () -> Unit): Boolean {
        if (!busy.tryLock()) return false // already busy
        job = scope.launch {
            try {
                loaded.await()
                settings = store.settings()
                reloadStrategies()
                _results.value = store.results().filterKeys { id -> _strategies.value.any { it.id == id } }
                _selectedId.value = store.selectedStrategyId()
                body()
            } catch (e: CancellationException) {
                log.write(L.t("log.cancelled"))
                withContext(NonCancellable) { stopAll() }
                set(EngineState.Idle, Msg("detail.cancelled"))
            } catch (e: Exception) {
                val msg = (e as? ZarpException)?.msg ?: Msg("detail.error", e.message ?: e.javaClass.simpleName)
                log.write(L.t("log.error", msg.toString()))
                withContext(NonCancellable) { stopAll() }
                set(EngineState.Error, msg)
            } finally {
                _status.update { it.copy(progressDone = 0, progressTotal = 0) }
                busy.unlock()
            }
        }
        return true
    }

    // ------------------------------------------------------------ steps

    private suspend fun prepare() {
        set(EngineState.Preparing, Msg("detail.preparing"))
        // our own tunnel and VPN go first: tests must not run through them
        stopAll()
        if (settings.perAppProxy && settings.proxyApps.isEmpty()) throw VpnStartException(L.t("apps.empty"))
        EndpointParser.parse(settings.customEndpoints)
        if (network.foreignVpnActive()) {
            log.write(L.t("log.otherVpnActive"))
            log.write(L.t("log.vpnAdvice"))
        }
        if (settings.useProxy) return
        if (!account.registered) log.write(L.t("log.warpRegistering"))
        try {
            account.ensureRegistered()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val reason = (e as? ZarpException)?.msg?.toString() ?: e.message.orEmpty()
            log.write(L.t("log.warpRegisterFailed", reason))
            throw ZarpException(Msg("detail.registerFailed"), e)
        }
    }

    /**
     * Test one strategy: new tunnel on its own WARP endpoint, then cdn-cgi/trace through it.
     * Each test uses a different endpoint so it cannot inherit DPI state from the previous connection.
     */
    internal suspend fun test(s: Strategy): TestResult {
        val now = clock()
        s.plan.unsupported?.let { return TestResult.unsupported(s.id, it, now) }
        val custom = EndpointParser.parse(settings.customEndpoints)
        val endpoint = when {
            !s.transport.isWarp -> null
            settings.isolateTests -> endpoints.next(s.transport, custom)
            else -> custom.firstOrNull()
        }
        val tunnel = try {
            tunnels.open(s, endpoint, settings.testTimeoutSec * 1000, persistent = false)
        } catch (e: CancellationException) {
            throw e
        } catch (e: TunnelException) {
            return if (e.timeout) TestResult.failed(s.id, Msg("err.timeout", settings.testTimeoutSec), now, endpoint)
            else TestResult.failedRaw(s.id, e.message.orEmpty(), now, endpoint)
        } catch (e: Exception) {
            return TestResult.failedRaw(s.id, e.message ?: e.javaClass.simpleName, now, endpoint)
        }
        try {
            return when (val m = measure(s, tunnel.socksPort, 3)) {
                is Measurement.Ok -> TestResult(
                    strategyId = s.id, ok = true, connectMs = m.firstResponseMs ?: tunnel.connectMs, pingMs = m.pingMs,
                    endpoint = tunnel.endpoint, timestamp = now,
                )
                is Measurement.NotWarp -> TestResult.failed(s.id, Msg("err.notWarp", m.warp ?: "?"), now, tunnel.endpoint)
                is Measurement.NoTraffic -> TestResult.failed(s.id, Msg("err.noTraffic"), now, tunnel.endpoint)
                    .copy(error = m.lastError)
            }
        } finally {
            tunnel.close()
        }
    }

    /** @param stopAfter stop phase 1 after this many working strategies; 0 = test all. */
    private suspend fun searchAndApply(list: List<Strategy>, stopAfter: Int, title: String) {
        val candidates = mutableListOf<Pair<Strategy, TestResult>>()
        log.write(title)
        setProgress(0, list.size)

        // ---- phase 1: go through the list
        for (s in list) {
            coroutineContext.ensureActive()
            set(EngineState.Searching, Msg("detail.testing", progressDone() + 1, list.size, s.name), strategy = s)
            val r = test(s)
            putResult(r)
            setProgress(progressDone() + 1, list.size)
            log.write("  " + if (r.ok) L.t("log.testOk", s.name, r.connectMs, r.pingMs) else L.t("log.testFail", s.name, r.logError))
            if (r.ok) {
                candidates += s to r
                if (stopAfter > 0 && candidates.size >= stopAfter) break
            }
        }
        saveResults()

        // ---- phase 2: independent re-check of every candidate (another endpoint, fresh tunnel).
        // Weeds out strategies that "passed" only thanks to the previous successful connection.
        if (candidates.isNotEmpty()) {
            log.write(L.t("log.recheck", candidates.size))
            setProgress(0, candidates.size)
            for ((k, pair) in candidates.sortedBy { it.second.score }.withIndex()) {
                val (s, r1) = pair
                coroutineContext.ensureActive()
                set(EngineState.Searching, Msg("detail.rechecking", k + 1, candidates.size, s.name), strategy = s)
                val r2 = test(s)
                setProgress(k + 1, candidates.size)
                if (r2.ok) {
                    val merged = TestResult.confirmed(r1, r2)
                    putResult(merged)
                    log.write("  " + L.t("log.recheckOk", s.name, r2.connectMs, r2.pingMs))
                } else {
                    putResult(r2.copy(rechecked = true))
                    log.write("  " + L.t("log.testFail", s.name, r2.copy(rechecked = true).logError))
                }
                saveResults()
            }
        }

        val scannedIds = list.map { it.id }.toSet()
        val confirmed = confirmedStrategies(except = null).filter { it.id in scannedIds }
        if (confirmed.isEmpty()) {
            stopAll()
            log.write(
                if (candidates.isNotEmpty()) L.t("log.candidatesFailed") else L.t("log.noneWorked")
            )
            set(EngineState.Error, Msg("detail.notFound"))
            return
        }

        setProgress(0, 0)
        val best = confirmed[0]
        val br = _results.value.getValue(best.id)
        log.write(L.t("log.best", best.name, br.connectMs, br.pingMs))
        if (!applyFirstWorking(confirmed)) set(EngineState.Error, Msg("detail.foundButFailed"))
    }

    /** Confirmed strategies, best (lowest score) first. */
    fun confirmedStrategies(except: Strategy?): List<Strategy> {
        val res = _results.value
        return candidates()
            .filter { it != except && res[it.id]?.let { r -> r.ok && r.confirmed } == true }
            .sortedBy { res.getValue(it.id).score }
    }

    /** Connect with the first strategy in the list that really connects; remember it. */
    private suspend fun applyFirstWorking(ordered: List<Strategy>): Boolean {
        for (s in ordered) {
            coroutineContext.ensureActive()
            if (apply(s)) {
                saveSelected(s)
                return true
            }
            markFailed(s)
            log.write(L.t("log.tryNext", s.name))
        }
        return false
    }

    private suspend fun markFailed(s: Strategy) {
        putResult(TestResult.failed(s.id, Msg("result.applyFailed"), clock()))
        saveResults()
    }

    /** Connect with the given strategy: persistent tunnel, WARP check, then the VPN. */
    private suspend fun apply(s: Strategy): Boolean {
        set(EngineState.Connecting, Msg("detail.connectingTo", s.name), strategy = s)
        log.write(L.t("log.connectingWith", s.name))
        stopAll()
        s.plan.unsupported?.let {
            log.write(L.t("log.unsupported", s.name, it.toString()))
            set(EngineState.Error, Msg("detail.connectFailed"))
            return false
        }

        val timeoutMs = maxOf(30, settings.testTimeoutSec * 2) * 1000
        val custom = EndpointParser.parse(settings.customEndpoints)
        val endpoint = if (s.transport.isWarp) _results.value[s.id]?.endpoint?.takeIf { it in custom } ?: custom.firstOrNull() else null
        val tunnel = try {
            tunnels.open(s, endpoint, timeoutMs, persistent = true, onStatus = ::onTunnelStatus)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            log.write(L.t("log.warpNotConnectedReason", e.message.orEmpty()))
            set(EngineState.Error, Msg("detail.connectFailed"))
            return false
        }
        val m = try {
            measure(s, tunnel.socksPort, 1)
        } catch (e: Throwable) {
            tunnel.close()
            throw e
        }
        if (m !is Measurement.Ok) {
            tunnel.close()
            log.write(
                when (m) {
                    is Measurement.NotWarp -> L.t("err.notWarp", m.warp ?: "?")
                    else -> L.t("err.noTraffic")
                }
            )
            set(EngineState.Error, Msg("detail.connectFailed"))
            return false
        }
        try {
            vpn.start(tunnel.socksPort, s.name)
        } catch (e: Throwable) {
            tunnel.close()
            if (e is CancellationException) throw e
            throw if (e is VpnStartException) e else VpnStartException(e.message ?: e.javaClass.simpleName, e)
        }
        active = tunnel
        val connectMs = m.firstResponseMs ?: tunnel.connectMs
        log.write(L.t(if (s.transport.isWarp) "log.warpConnected" else "log.proxyConnected", connectMs, m.pingMs, tunnel.endpoint))
        set(
            EngineState.Connected, Msg("detail.strategy", s.name), strategy = s,
            connectMs = connectMs, pingMs = m.pingMs, endpoint = tunnel.endpoint,
        )
        return true
    }

    private suspend fun measure(strategy: Strategy, port: Int, samples: Int): Measurement =
        if (strategy.transport.isWarp) probe.measure(port, samples) else probe.measureProxy(port, samples)

    private fun onTunnelStatus(connected: Boolean, message: String) {
        if (active == null) return
        _status.update {
            if (connected) it.copy(state = EngineState.Connected, detail = Msg("detail.strategy", it.strategy?.name.orEmpty()))
            else it.copy(state = EngineState.Connecting, detail = Msg("detail.reconnecting"))
        }
    }

    private suspend fun stopAll() {
        val t = active
        active = null
        t?.close()
        vpn.stop()
    }

    // ------------------------------------------------------------ state helpers

    private suspend fun saveSelected(s: Strategy) {
        _selectedId.value = s.id
        store.setSelectedStrategyId(s.id)
    }

    private fun putResult(r: TestResult) {
        _results.update { it + (r.strategyId to r) }
    }

    private suspend fun saveResults() = store.saveResults(_results.value)

    private fun progressDone() = _status.value.progressDone

    private fun setProgress(done: Int, total: Int) {
        _status.update { it.copy(progressDone = done, progressTotal = total) }
    }

    private fun set(
        state: EngineState,
        detail: Msg,
        strategy: Strategy? = _status.value.strategy,
        connectMs: Int? = null,
        pingMs: Int? = null,
        endpoint: String? = null,
    ) {
        _status.update {
            it.copy(state = state, detail = detail, strategy = strategy, connectMs = connectMs, pingMs = pingMs, endpoint = endpoint)
        }
    }
}

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
import kotlinx.coroutines.withTimeoutOrNull
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
    private val refreshServers: suspend (AppSettings) -> AppSettings = { it },
    private val capabilities: StrategyCapabilities = CapabilitySnapshot(),
    private val lifetime: OperationLifetime? = null,
) {
    private val _status = MutableStateFlow(EngineStatus())
    val status: StateFlow<EngineStatus> = _status.asStateFlow()

    private val _results = MutableStateFlow<Map<String, TestResult>>(emptyMap())
    val results: StateFlow<Map<String, TestResult>> = _results.asStateFlow()

    private val _strategies = MutableStateFlow(StrategyCatalog.builtIn)
    val strategies: StateFlow<List<Strategy>> = _strategies.asStateFlow()

    private val _selectedId = MutableStateFlow<String?>(null)
    val selectedId: StateFlow<String?> = _selectedId.asStateFlow()
    private val _activePair = MutableStateFlow<Strategy?>(null)
    val activePair: StateFlow<Strategy?> = _activePair.asStateFlow()

    private val _accountBusy = MutableStateFlow(false)
    val accountBusy: StateFlow<Boolean> = _accountBusy.asStateFlow()

    private val busy = Mutex()
    private val loaded = CompletableDeferred<Unit>()
    private var job: Job? = null
    private var accountJob: Job? = null
    private var preserveWarpFailures = false
    @Volatile private var settings = AppSettings()
    val serverMode: Boolean get() = settings.useProxy || _activePair.value?.profile != null

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
        _selectedId.value = store.selectedStrategyId()?.takeIf { it in known }
        store.saveResults(_results.value)
        store.setSelectedStrategyId(_selectedId.value)
        val s = selected
        set(EngineState.Idle, if (s != null) Msg("detail.strategy", s.name) else Msg("detail.noStrategy"))
        loaded.complete(Unit)
    }

    private fun reloadStrategies() {
        val catalog = StrategyCatalog.load(settings.customStrategies) { log.write(L.t("log.customSkippedApp", it)) }
        _strategies.value = (if (settings.useProxy) ServerPairs.build(catalog, ServerPairs.profiles(settings), settings.allowPlainServer) else catalog)
            .map(::withCapabilities)
    }

    fun withCapabilities(strategy: Strategy): Strategy {
        val issue = when {
            !capabilities.udpTtl && strategy.plan.fakes.any { it.ipTtl != null || it.ip6Ttl != null } -> Msg("unsup.udpTtl")
            !capabilities.tcpTtl && strategy.plan.tcpDesync?.startsWith("disorder:") == true -> Msg("unsup.tcpTtl")
            else -> null
        }
        return strategy.copy(deviceIssue = issue)
    }

    private fun candidates() = StrategyFilter.apply(_strategies.value, settings.strategyCountry).filter {
        !settings.useProxy || settings.serverSelectionId == null || it.profile?.id == settings.serverSelectionId
    }

    private suspend fun pruneSavedState() {
        val known = _strategies.value.map { it.id }.toSet()
        _results.value = store.results().filterKeys { it in known }
        _selectedId.value = store.selectedStrategyId()?.takeIf { it in known }
        store.saveResults(_results.value)
        store.setSelectedStrategyId(_selectedId.value)
    }

    /** Refresh saved results without changing the state of a running VPN. */
    suspend fun refreshSavedState() {
        if (busy.isLocked) return
        settings = store.settings()
        reloadStrategies()
        pruneSavedState()
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
                log.write(L.t("log.savedFailed", s.logName))
                if (applyFirstWorking(others)) return@launchOp
            }
            log.write(L.t("log.verifiedFailed"))
            if (settings.useProxy && candidates().size <= 1) return@launchOp
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
        prepare()
        val current = candidates().firstOrNull { it.id == s.id } ?: throw ZarpException(Msg("filter.excluded"))
        if (apply(current)) saveSelected(current)
    }

    fun disconnect(): Boolean = launchOp {
        set(EngineState.Disconnecting, Msg("detail.disconnecting"))
        stopAll()
        // the status already says "Disconnected"; the line under it names the strategy to reconnect with
        set(EngineState.Idle, selected?.let { Msg("detail.strategy", it.name) } ?: Msg("detail.disconnected"))
    }

    fun cancel() {
        job?.cancel()
        accountJob?.cancel()
    }

    /** One bounded traffic check; the application schedules it every seven seconds. */
    suspend fun observeConnection() {
        if (busy.isLocked) return
        val tunnel = active ?: return
        val strategy = _activePair.value ?: return
        // A slow network must not block the user's Disconnect or account commands.
        val observation = withTimeoutOrNull(8_000) {
            try { measure(strategy, tunnel.socksPort, 0) }
            catch (e: CancellationException) { throw e }
            catch (_: Exception) { Measurement.NoTraffic(null) }
        }
        if (!busy.tryLock()) return
        var reconnect = false
        try {
            if (active !== tunnel || _activePair.value != strategy) return
            if (observation is Measurement.Ok && tunnel.strategyApplied()) {
                _status.update { it.copy(state = EngineState.Connected, detail = Msg("detail.strategy", strategy.name), pingMs = observation.pingMs) }
            } else {
                set(EngineState.Connecting, Msg("detail.reconnecting"), strategy)
                // Keep the native reconnect loop alive while the underlying link
                // is offline; a scan at that point would only discard good results.
                reconnect = network.internetAvailable()
            }
        } finally { busy.unlock() }
        // The regular flow retries the selected strategy, verified alternatives,
        // then a fresh scan. Cancellation/disconnection still use the same lock.
        if (reconnect) connect()
    }

    /** Account commands share the operation lock and keep an active tunnel intact. */
    suspend fun warpAccount(license: String? = null): WarpAccountType {
        if (license != null && !WarpAccountType.validLicense(license)) throw WarpAccountException("invalid")
        if (!busy.tryLock()) throw ZarpException(Msg("warpPlus.busy"))
        _accountBusy.value = true
        accountJob = coroutineContext[Job]
        try {
            loaded.await()
            settings = store.settings()
            lifetime?.start()
            return if (license == null) account.readAccount() else account.applyLicense(
                license, registrationStrategies(), active == null && !network.foreignVpnActive(),
            ) { _, _, _ -> }
        } finally {
            withContext(NonCancellable) { runCatching { lifetime?.stop() } }
            _accountBusy.value = false
            accountJob = null
            busy.unlock()
        }
    }

    /** API candidates are never server pairs and never become verified tunnel results. */
    private fun registrationStrategies(): List<Strategy> =
        StrategyFilter.apply(StrategyCatalog.load(settings.customStrategies).map(::withCapabilities), settings.strategyCountry)
            .filter { it.isWarp && it.supported && it.transport == Transport.MasqueH2 && !it.plan.tcpDesync.isNullOrEmpty() }
            .sortedWith(compareByDescending<Strategy> { it.id == _selectedId.value }
                .thenByDescending { _results.value[it.id]?.let { r -> r.ok && r.confirmed } == true })

    /** The VPN went away (revoked by the system or another VPN app, or stopped from the notification). */
    fun onVpnStopped(reason: Msg) {
        scope.launch {
            job?.cancelAndJoin()
            busy.withLock {
                val had = active != null
                active?.close()
                active = null
                _activePair.value = null
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
                pruneSavedState()
                lifetime?.start()
                body()
            } catch (e: CancellationException) {
                log.write(L.t("log.cancelled"))
                withContext(NonCancellable) { saveResults(); stopAll() }
                set(EngineState.Idle, Msg("detail.cancelled"))
            } catch (e: Exception) {
                val msg = (e as? ZarpException)?.msg ?: if (settings.useProxy) ServerErrors.describe("", e.message.orEmpty())
                    else Msg("detail.error", e.message ?: e.javaClass.simpleName)
                log.write(L.t("log.error", msg.toString()))
                withContext(NonCancellable) { stopAll() }
                set(EngineState.Error, msg)
            } finally {
                withContext(NonCancellable) { runCatching { lifetime?.stop() } }
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
        if (network.foreignVpnActive()) {
            if (settings.useProxy) throw ZarpException(Msg("server.otherVpn"))
            log.write(L.t("log.otherVpnActive"))
        }
        preserveWarpFailures = !settings.useProxy && network.foreignVpnActive()
        if (settings.useProxy) {
            Subscription.explainSource(settings.proxyUri)?.let { throw ZarpException(it) }
            settings = refreshServers(settings)
            reloadStrategies()
            pruneSavedState()
            val profiles = ServerPairs.profiles(settings)
            if (settings.serverSelectionId != null && profiles.none { it.id == settings.serverSelectionId }) {
                throw ZarpException(Msg("server.unavailable"))
            }
            val chosen = profiles.filter { settings.serverSelectionId == null || it.id == settings.serverSelectionId }
            if (candidates().none { it.supported }) {
                throw ZarpException(if (chosen.isNotEmpty() && chosen.all { !it.hasTls }) Msg("proxy.noHandshake") else Msg("server.noStrategy"))
            }
            tunnels.beginOperation(settings)
            return
        }
        tunnels.beginOperation(settings)
        EndpointParser.parse(settings.customEndpoints)
        if (!account.registered) log.write(L.t("log.warpRegistering"))
        try {
            account.ensureRegistered(registrationStrategies(), !network.foreignVpnActive()) { done, total, strategy ->
                set(EngineState.Preparing, Msg("detail.warpRegistrationStrategy", done, total, strategy.name))
            }
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
        s.unsupported?.let { return TestResult.unsupported(s.id, it, now) }
        val custom = if (s.isWarp) EndpointParser.parse(settings.customEndpoints) else emptyList()
        val endpoint = when {
            !s.isWarp -> null
            settings.isolateTests -> endpoints.next(s.transport, custom)
            else -> custom.firstOrNull()
        }
        val tunnel = try {
            tunnels.open(s, endpoint, settings.testTimeoutSec * 1000, persistent = false)
        } catch (e: CancellationException) {
            throw e
        } catch (e: TunnelException) {
            if (!s.isWarp) return TestResult.failed(s.id, ServerErrors.describe(if (e.timeout) "timeout" else "", e.message.orEmpty()), now)
            return if (e.timeout) TestResult.failed(s.id, Msg("err.timeout", settings.testTimeoutSec), now, endpoint)
            else TestResult.failedRaw(s.id, e.message.orEmpty(), now, endpoint)
        } catch (e: Exception) {
            return if (!s.isWarp) TestResult.failed(s.id, (e as? ZarpException)?.msg ?: ServerErrors.describe("", e.message.orEmpty()), now)
                else TestResult.failedRaw(s.id, e.message ?: e.javaClass.simpleName, now, endpoint)
        }
        try {
            var first: Measurement.Ok? = null
            if (!s.isWarp) {
                val initial = probe.probeProxy(tunnel.socksPort)
                if (initial !is Measurement.Ok) return TestResult.failed(s.id, tunnel.failure() ?: Msg("server.err.other"), now, tunnel.endpoint)
                first = initial
            }
            return when (val m = measure(s, tunnel.socksPort, 3)) {
                is Measurement.Ok -> if (!tunnel.strategyApplied()) TestResult.failed(s.id, Msg("proxy.noHandshake"), now, tunnel.endpoint)
                else TestResult(
                    strategyId = s.id, ok = true, connectMs = first?.firstResponseMs ?: m.firstResponseMs ?: tunnel.connectMs,
                    pingMs = m.pingMs, endpoint = tunnel.endpoint, timestamp = now,
                )
                is Measurement.NotWarp -> TestResult.failed(s.id, Msg("err.notWarp", m.warp ?: "?"), now, tunnel.endpoint)
                is Measurement.NoTraffic -> if (s.isWarp) TestResult.failed(s.id, Msg("err.noTraffic"), now, tunnel.endpoint).copy(error = m.lastError)
                    else TestResult.failed(s.id, tunnel.failure() ?: Msg("server.err.other"), now, tunnel.endpoint)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return if (s.isWarp) TestResult.failedRaw(s.id, e.message ?: e.javaClass.simpleName, now, tunnel.endpoint)
                else TestResult.failed(s.id, (e as? ZarpException)?.msg ?: tunnel.failure() ?: ServerErrors.describe("", e.message.orEmpty()), now)
        } finally {
            tunnel.close()
        }
    }

    /** @param stopAfter stop phase 1 after this many working strategies; 0 = test all. */
    private suspend fun searchAndApply(list: List<Strategy>, stopAfter: Int, title: String) {
        if (settings.useProxy) {
            searchServerPairs(list, stopAfter, title)
            return
        }
        log.write(title)
        var scanned = 0
        var confirmedCount = 0
        var hadCandidates = false
        val scannedIds = list.map { it.id }.toSet()

        do {
            val candidates = mutableListOf<Pair<Strategy, TestResult>>()
            val needed = stopAfter - confirmedCount
            setProgress(scanned, list.size)

            // ---- phase 1: go through the list
            for (s in list.drop(scanned)) {
                coroutineContext.ensureActive()
                set(EngineState.Searching, Msg("detail.testing", progressDone() + 1, list.size, s.name), strategy = s)
                val r = test(s)
                putResult(r)
                scanned++
                setProgress(progressDone() + 1, list.size)
                log.write("  " + if (r.ok) L.t("log.testOk", s.name, r.connectMs, r.pingMs) else L.t("log.testFail", s.name, r.logError))
                if (r.ok) {
                    candidates += s to r
                    hadCandidates = true
                    if (stopAfter > 0 && candidates.size >= needed) break
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
                        confirmedCount++
                        log.write("  " + L.t("log.recheckOk", s.name, r2.connectMs, r2.pingMs))
                    } else {
                        putResult(r2.copy(rechecked = true))
                        log.write("  " + L.t("log.testFail", s.name, r2.copy(rechecked = true).logError))
                    }
                    saveResults()
                }
            }

        // A failed confirmation does not consume Quick Scan's working quota.
        } while (stopAfter > 0 && scanned < list.size && confirmedCount < stopAfter)

        val confirmed = confirmedStrategies(except = null).filter { it.id in scannedIds }
        if (confirmed.isEmpty()) {
            stopAll()
            log.write(
                if (hadCandidates) L.t("log.candidatesFailed") else L.t("log.noneWorked")
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

    /** Server pairs are confirmed inline; Quick Scan counts confirmed pairs only. */
    private suspend fun searchServerPairs(list: List<Strategy>, stopAfter: Int, title: String) {
        log.write(title)
        setProgress(0, list.size)
        var confirmedCount = 0
        for ((index, s) in list.withIndex()) {
            coroutineContext.ensureActive()
            set(EngineState.Searching, Msg("detail.testing", index + 1, list.size, s.name), strategy = s)
            val first = test(s)
            var result = first
            if (first.ok) {
                set(EngineState.Searching, Msg("detail.confirmingPair", index + 1, list.size, s.name), strategy = s)
                val second = test(s)
                result = if (second.ok) TestResult.confirmed(first, second) else second.copy(rechecked = true)
            }
            putResult(result)
            saveResults()
            setProgress(index + 1, list.size)
            log.write(if (result.ok) L.t("log.recheckOk", s.logName, result.connectMs, result.pingMs)
                else L.t("log.testFail", s.logName, result.logError))
            if (result.ok && ++confirmedCount >= stopAfter && stopAfter > 0) break
        }
        val scanned = list.map { it.id }.toSet()
        val ordered = confirmedStrategies(null).filter { it.id in scanned }
        if (ordered.isEmpty()) {
            stopAll()
            set(EngineState.Error, Msg("detail.notFound"))
        } else if (!applyFirstWorking(ordered)) set(EngineState.Error, Msg("detail.foundButFailed"))
    }

    /** Confirmed strategies, best (lowest score) first. */
    fun confirmedStrategies(except: Strategy?): List<Strategy> {
        val res = _results.value
        return candidates()
            .filter { it.id != except?.id && it.supported && res[it.id]?.let { r -> r.ok && r.confirmed } == true }
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
            log.write(L.t("log.tryNext", s.logName))
        }
        return false
    }

    private suspend fun markFailed(s: Strategy) {
        putResult(TestResult.failed(s.id, if (s.isWarp) Msg("result.applyFailed") else _status.value.detail, clock()))
        saveResults()
    }

    /** Connect with the given strategy: persistent tunnel, WARP check, then the VPN. */
    private suspend fun apply(s: Strategy): Boolean {
        set(EngineState.Connecting, Msg("detail.connectingTo", s.name), strategy = s)
        log.write(L.t("log.connectingWith", s.logName))
        stopAll()
        s.unsupported?.let {
            log.write(L.t("log.unsupported", s.logName, it.toString()))
            set(EngineState.Error, it)
            return false
        }

        val timeoutMs = maxOf(30, settings.testTimeoutSec * 2) * 1000
        val custom = if (s.isWarp) EndpointParser.parse(settings.customEndpoints) else emptyList()
        val endpoint = if (s.isWarp) _results.value[s.id]?.endpoint?.takeIf { it in custom } ?: custom.firstOrNull() else null
        val tunnel = try {
            tunnels.open(s, endpoint, timeoutMs, persistent = true, onStatus = ::onTunnelStatus)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val msg = if (s.isWarp) Msg("detail.connectFailed") else (e as? ZarpException)?.msg ?: ServerErrors.describe("", e.message.orEmpty())
            log.write(if (s.isWarp) L.t("log.warpNotConnectedReason", e.message.orEmpty()) else msg.toString())
            set(EngineState.Error, msg)
            return false
        }
        val m = try {
            measure(s, tunnel.socksPort, 1)
        } catch (e: Throwable) {
            tunnel.close()
            throw e
        }
        if (m !is Measurement.Ok || !tunnel.strategyApplied()) {
            val failure = if (!s.isWarp) {
                if (m is Measurement.Ok) Msg("proxy.noHandshake") else tunnel.failure() ?: Msg("server.err.other")
            } else Msg("detail.connectFailed")
            tunnel.close()
            log.write(
                when (m) {
                    is Measurement.NotWarp -> L.t("err.notWarp", m.warp ?: "?")
                    else -> L.t("err.noTraffic")
                }
            )
            if (s.isWarp && m is Measurement.NoTraffic && !m.lastError.isNullOrBlank()) {
                log.write(L.t("log.warpNotConnectedReason", m.lastError))
            }
            set(EngineState.Error, failure)
            return false
        }
        try {
            vpn.start(tunnel.socksPort, s.name)
            if (!s.isWarp && probe.probeProxy(tunnel.socksPort) !is Measurement.Ok) {
                throw ZarpException(tunnel.failure() ?: Msg("server.err.other"))
            }
        } catch (e: Throwable) {
            tunnel.close()
            withContext(NonCancellable) { vpn.stop() }
            if (e is CancellationException) throw e
            if (e is ZarpException) throw e
            throw if (!s.isWarp) ZarpException(ServerErrors.describe("", e.message.orEmpty()))
                else VpnStartException(e.message ?: e.javaClass.simpleName, e)
        }
        active = tunnel
        _activePair.value = s
        val connectMs = m.firstResponseMs ?: tunnel.connectMs
        log.write(L.t(if (s.isWarp) "log.warpConnected" else "log.proxyConnected", connectMs, m.pingMs,
            if (s.isWarp) tunnel.endpoint else s.logName))
        set(
            EngineState.Connected, Msg("detail.strategy", s.name), strategy = s,
            connectMs = connectMs, pingMs = m.pingMs, endpoint = tunnel.endpoint,
        )
        return true
    }

    private suspend fun measure(strategy: Strategy, port: Int, samples: Int): Measurement =
        if (strategy.isWarp) probe.measure(port, samples) else probe.measureProxy(port, samples)

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
        _activePair.value = null
        t?.close()
        vpn.stop()
    }

    // ------------------------------------------------------------ state helpers

    private suspend fun saveSelected(s: Strategy) {
        _selectedId.value = s.id
        store.setSelectedStrategyId(s.id)
    }

    private fun putResult(r: TestResult) {
        if (preserveWarpFailures && (!r.ok || !r.confirmed)) return
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

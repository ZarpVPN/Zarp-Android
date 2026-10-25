package io.github.feg55.zarp

import io.github.feg55.zarp.core.*
import io.github.feg55.zarp.masque.MasqueAccount
import io.github.feg55.zarp.masque.MasqueTunnelFactory
import io.github.feg55.zarp.net.Measurement
import io.github.feg55.zarp.net.TraceClient
import io.github.feg55.zarp.strategy.BlobStore
import io.github.feg55.zarp.vpn.AndroidOperationLifetime
import io.github.feg55.zarp.vpn.VpnServiceController
import io.github.feg55.zarpcore.AccountProtector
import io.github.feg55.zarpcore.Zarpcore
import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.*
import kotlinx.serialization.json.*

/** ADB-only live API verification; the user's registration is never overwritten. */
object DebugWarpRegistrationVerifier {
    private var job: Job? = null

    fun start(app: ZarpApp): Boolean {
        if (job?.isActive == true || app.privateServerDiagnostics || app.engine.status.value.state.busy ||
            app.engine.activePair.value != null || AndroidNetworkInspector(app).foreignVpnActive()) return false
        job = app.appScope.launch {
            val original = File(app.filesDir, "warp-masque.json")
            val baseline = digest(original)
            val test = File(app.filesDir, "warp-registration-verification.json")
            val report = File(app.cacheDir, "warp-registration-result.json")
            val steps = mutableListOf<JsonObject>()
            val fresh = !test.exists() && !File(test.path + ".pending").exists()
            var phase = "starting"
            var outcome = "running"
            var protectedRegistered = false
            var directRegistered = false
            var warp = "unconfirmed"
            var pingMs: Int? = null
            var connectMs: Int? = null
            val started = System.nanoTime()
            fun save() {
                report.writeText(buildJsonObject {
                    put("outcome", outcome); put("phase", phase)
                    put("freshTestIdentity", fresh)
                    put("directFailureInjected", true)
                    put("protectedRegistered", protectedRegistered)
                    put("directRegistered", directRegistered)
                    put("testConfigPresent", Zarpcore.hasAccount(test.absolutePath))
                    put("pendingEnrollment", File(test.path + ".pending").exists())
                    put("originalAccountUnchanged", baseline.contentEquals(digest(original)))
                    put("warp", warp)
                    pingMs?.let { put("pingMs", it) }
                    connectMs?.let { put("connectMs", it) }
                    put("elapsedMs", (System.nanoTime() - started) / 1_000_000)
                    put("steps", JsonArray(steps.toList()))
                }.toString())
            }
            suspend fun <T> step(name: String, strategy: Strategy?, block: suspend () -> T): T {
                phase = name + ":" + (strategy?.id ?: "direct")
                save()
                val at = System.nanoTime()
                var result = "ok"
                try { return block() }
                catch (e: WarpAccountException) { result = e.code; throw e }
                catch (e: CancellationException) { result = "cancelled"; throw e }
                catch (e: Exception) { result = "other"; throw e }
                finally {
                    steps += buildJsonObject {
                        put("step", name); put("strategy", strategy?.id ?: "direct")
                        put("result", result); put("ms", (System.nanoTime() - at) / 1_000_000)
                    }
                    save()
                }
            }
            val settings = suspend { app.store.settings() }
            val protector = VpnServiceController(app, settings)
            fun session(file: File, strategy: Strategy?) = MasqueAccount.NativeSession(
                Zarpcore.newAccountOperation(file.absolutePath, strategy?.plan?.tcpDesync.orEmpty(), 25_000,
                    AccountProtector { protector.protect(it.toInt()) }))
            val lifetime = AndroidOperationLifetime(app)
            save()
            try {
                require(settings().tosAccepted)
                lifetime.start()
                app.privateServerDiagnostics = true
                withTimeout(360_000) {
                    val candidates = StrategyFilter.apply(StrategyCatalog.load(settings().customStrategies)
                        .map(app.engine::withCapabilities), settings().strategyCountry)
                        .filter { it.isWarp && it.supported && it.transport == Transport.MasqueH2 && !it.plan.tcpDesync.isNullOrEmpty() }
                    val working = mutableSetOf<String>()
                    for (strategy in listOf<Strategy?>(null) + candidates) {
                        val read = session(original, strategy)
                        try {
                            step("existingAccountRead", strategy) { read.read() }
                            strategy?.let { working += it.id }
                        } catch (_: WarpAccountException) { /* All failures are recorded without native text. */ }
                        finally { read.close() }
                    }
                    if (!Zarpcore.hasAccount(test.absolutePath)) {
                        val manager = WarpAccountManager(sessions = { strategy ->
                            if (strategy == null) object : WarpAccountSession {
                                override suspend fun ensureRegistered(): Unit = step("registrationInjectedFailure", null) {
                                    throw WarpAccountException("network")
                                }
                                override suspend fun read(): WarpAccountType = error("unused")
                                override suspend fun apply(license: String): WarpAccountType = error("unused")
                                override fun close() = Unit
                            } else {
                                val native = session(test, strategy)
                                object : WarpAccountSession by native {
                                    override suspend fun ensureRegistered() = step("protectedRegistration", strategy) { native.ensureRegistered() }
                                }
                            }
                        }, registered = { Zarpcore.hasAccount(test.absolutePath) }, log = LogBus())
                        try {
                            manager.ensure(candidates.sortedByDescending { it.id in working }, true)
                            protectedRegistered = true
                        } catch (e: WarpAccountException) {
                            if (!e.retryable) throw e
                            // Complete the same pending identity; no reset and no extra POST after enrollment failed.
                            val direct = session(test, null)
                            try {
                                step("directRegistrationAfterProtectedFailure", null) { direct.ensureRegistered() }
                                directRegistered = true
                            } finally { direct.close() }
                        }
                    }
                    val type = session(test, null)
                    try { step("newAccountRead", null) { type.read() } } finally { type.close() }
                    val factory = MasqueTunnelFactory(test.absolutePath, BlobStore { app.assets.open(it) }, settings, protector, LogBus())
                    val strategy = StrategyCatalog.builtIn.first { it.id == "warp-q-google6" }
                    val tunnel = step("newAccountTunnel", strategy) { factory.open(strategy, null, 20_000, false) }
                    try {
                        connectMs = tunnel.connectMs
                        phase = "newAccountTraffic"
                        save()
                        when (val proof = TraceClient().measure(tunnel.socksPort, 1)) {
                            is Measurement.Ok -> { warp = proof.warp; pingMs = proof.pingMs }
                            is Measurement.NotWarp -> warp = "off"
                            is Measurement.NoTraffic -> warp = "noTraffic"
                        }
                    } finally { tunnel.close() }
                    outcome = if (warp in setOf("on", "plus") && protectedRegistered) "protectedRegistrationVerified"
                        else if (warp in setOf("on", "plus") && directRegistered) "directRegistrationVerifiedProtectedFailed"
                        else if (warp in setOf("on", "plus")) "existingTestIdentityVerified" else "trafficFailed"
                }
            } catch (e: WarpAccountException) { outcome = "account:" + e.code }
            catch (e: CancellationException) { outcome = "cancelled" }
            catch (_: Exception) { outcome = "setupOrTunnelFailed" }
            finally {
                app.privateServerDiagnostics = false
                withContext(NonCancellable) { lifetime.stop() }
                phase = "finished"
                save()
                app.log.write("debug registration verification: $outcome; original account unchanged=" + baseline.contentEquals(digest(original)))
            }
        }
        return true
    }

    fun stop(): Boolean = job?.takeIf { it.isActive }?.let { it.cancel(); true } ?: false

    private fun digest(file: File): ByteArray = if (file.exists()) MessageDigest.getInstance("SHA-256").digest(file.readBytes()) else byteArrayOf()
}

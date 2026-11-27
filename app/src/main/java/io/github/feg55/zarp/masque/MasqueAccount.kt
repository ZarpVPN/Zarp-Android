package io.github.feg55.zarp.masque

import io.github.feg55.zarp.core.AppSettings
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.core.Msg
import io.github.feg55.zarp.core.ZarpException
import io.github.feg55.zarp.core.LogBus
import io.github.feg55.zarp.core.WarpAccount
import io.github.feg55.zarp.core.WarpAccountManager
import io.github.feg55.zarp.core.WarpAccountSession
import io.github.feg55.zarp.core.WarpAccountType
import io.github.feg55.zarp.core.WarpAccountException
import io.github.feg55.zarp.core.Strategy
import io.github.feg55.zarpcore.AccountProtector
import io.github.feg55.zarpcore.AccountOperation
import io.github.feg55.zarpcore.Zarpcore
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.concurrent.thread
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import java.io.File

/** WARP device registration (usque: register + enroll a P-256 MASQUE key). */
class MasqueAccount(
    private val configFile: File,
    private val settings: suspend () -> AppSettings,
    private val log: LogBus,
    private val protector: SocketProtector,
    private val foreignVpnRoute: () -> SocketProtector?,
) : WarpAccount {

    override val registered: Boolean get() = Zarpcore.hasAccount(configFile.absolutePath)

    private val manager = manager(protector)

    private fun manager(route: SocketProtector, viaVpn: Boolean = false) = WarpAccountManager(
        sessions = { strategy ->
            val op = Zarpcore.newAccountOperation(configFile.absolutePath, strategy?.plan?.tcpDesync.orEmpty(), 25_000,
                AccountProtector { fd -> route.protect(fd.toInt()) })
            NativeSession(op, viaVpn)
        },
        registered = { registered },
        log = log,
    )

    override suspend fun ensureRegistered() = ensureRegistered(emptyList(), false) { _, _, _ -> }

    override suspend fun ensureRegistered(strategies: List<Strategy>, allowProtected: Boolean, progress: (Int, Int, Strategy) -> Unit) {
        if (registered) return
        if (!settings().tosAccepted) throw ZarpException(Msg("err.tos"))
        manager.ensure(strategies, allowProtected, progress)
        log.write(L.t("log.warpRegistered"))
    }

    override suspend fun ensureRegisteredViaVpn() {
        if (registered) return
        if (!settings().tosAccepted) throw ZarpException(Msg("err.tos"))
        val route = foreignVpnRoute() ?: throw WarpAccountException("vpnUnavailable")
        manager(route, viaVpn = true).ensure(emptyList(), false)
        log.write(L.t("log.warpRegistered"))
    }

    override suspend fun readAccount() = manager.read()

    override suspend fun applyLicense(license: String, strategies: List<Strategy>, allowProtected: Boolean,
        progress: (Int, Int, Strategy) -> Unit): WarpAccountType {
        if (!registered && !settings().tosAccepted) throw ZarpException(Msg("err.tos"))
        foreignVpnRoute()?.let { return manager(it, viaVpn = true).apply(license, emptyList(), false) }
        return manager.apply(license, strategies, allowProtected, progress)
    }

    /** Drops the registration; the next operation registers a new device. */
    fun reset() {
        configFile.delete()
        File(configFile.path + ".pending").delete()
    }

    internal class NativeSession(private val op: AccountOperation, private val viaVpn: Boolean = false) : WarpAccountSession {
        override suspend fun ensureRegistered() = call { op.ensureRegistered("Zarp Android") }
        override suspend fun read() = WarpAccountType.parse(call { op.readAccount() })
        override suspend fun apply(license: String) = WarpAccountType.parse(call { op.applyLicense(license) })
        override fun close() = op.close()

        private suspend fun <T> call(block: () -> T): T = suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { op.close() }
            thread(name = "zarp-account", isDaemon = true) {
                try {
                    val result = block()
                    if (continuation.isActive) continuation.resume(result)
                } catch (e: Exception) {
                    // gomobile wraps error text; only use known codes and numeric HTTP status.
                    val fields = e.message.orEmpty().substringAfterLast("account:").split(':')
                    val code = when (fields.first()) {
                        "network", "timeout", "rateLimit", "rejected", "invalid", "missing", "config" -> fields.first()
                        "protect" -> if (viaVpn) "vpnUnavailable" else "network"
                        else -> "api"
                    }
                    val stage = fields.getOrNull(1)?.takeIf { it in setOf("register", "enroll", "dns", "tcp", "tls", "save") }
                    val status = fields.getOrNull(2)?.toIntOrNull()?.takeIf { it in 100..599 }
                    if (continuation.isActive) continuation.resumeWithException(WarpAccountException(code, stage, status))
                }
            }
        }
    }
}

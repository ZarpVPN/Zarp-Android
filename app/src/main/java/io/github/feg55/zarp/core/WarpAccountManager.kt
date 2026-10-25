package io.github.feg55.zarp.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

enum class WarpAccountType(val key: String) {
    Unknown("unknown"), Free("free"), Plus("plus"), Unlimited("unlimited"), ZeroTrust("zerotrust");
    companion object {
        fun parse(value: String) = entries.firstOrNull { it.key == value } ?: Unknown
        fun validLicense(value: String) = Regex("[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}").matches(value.trim())
    }
}

/** Safe native error classes. Native diagnostics never reach settings or logs. */
class WarpAccountException(val code: String) : ZarpException(Msg(when (code) {
    "invalid" -> "warpPlus.invalid"
    "missing" -> "warpPlus.noWarp"
    "timeout" -> "warpPlus.timeout"
    "rateLimit" -> "warpPlus.rateLimit"
    "rejected" -> "warpPlus.rejected"
    "config" -> "warpPlus.storageFailed"
    else -> "warpPlus.accountFailed"
})) {
    val retryable: Boolean get() = code == "network" || code == "timeout"
}

/** A private API transport with one strategy. Closing also cancels active requests. */
interface WarpAccountSession {
    suspend fun ensureRegistered()
    suspend fun read(): WarpAccountType
    suspend fun apply(license: String): WarpAccountType
    fun close()
}

fun interface WarpAccountSessions {
    fun open(strategy: Strategy?): WarpAccountSession
}

/** Registration API strategies and tunnel results are deliberately independent. */
class WarpAccountManager(
    private val sessions: WarpAccountSessions,
    private val registered: () -> Boolean,
    private val log: LogBus,
) {
    suspend fun ensure(
        strategies: List<Strategy>,
        allowProtected: Boolean,
        progress: (Int, Int, Strategy) -> Unit = { _, _, _ -> },
    ) {
        if (registered()) return
        withRegistration(strategies, allowProtected, progress) { }
    }

    suspend fun apply(
        license: String,
        strategies: List<Strategy>,
        allowProtected: Boolean,
        progress: (Int, Int, Strategy) -> Unit = { _, _, _ -> },
    ): WarpAccountType {
        if (!WarpAccountType.validLicense(license)) throw WarpAccountException("invalid")
        return withRegistration(strategies, allowProtected, progress) { it.apply(license.trim()) }
    }

    suspend fun read(): WarpAccountType = withSession(null) { it.read() }

    private suspend fun <T> withRegistration(
        strategies: List<Strategy>,
        allowProtected: Boolean,
        progress: (Int, Int, Strategy) -> Unit,
        after: suspend (WarpAccountSession) -> T,
    ): T {
        // Only failed registration may start a strategy search. A license rejection
        // or rate limit never causes another registration or license submission.
        var registrationFailure: WarpAccountException? = null
        val direct = sessions.open(null)
        try {
            try { direct.ensureRegistered() }
            catch (e: WarpAccountException) { registrationFailure = e }
            if (registrationFailure == null) return after(direct)
        } finally { direct.close() }
        val original = registrationFailure
        if (!original.retryable || !allowProtected) throw original
        val eligible = strategies.filter { it.isWarp && it.supported && it.transport == Transport.MasqueH2 && !it.plan.tcpDesync.isNullOrEmpty() }
        if (eligible.isEmpty()) throw original
        log.write(L.t("log.warpRegistrationProtected"))
        var last: WarpAccountException = original
        for ((index, strategy) in eligible.withIndex()) {
            currentCoroutineContext().ensureActive()
            progress(index + 1, eligible.size, strategy)
            log.write(L.t("log.warpRegistrationStrategy", strategy.name))
            val session = sessions.open(strategy)
            try {
                try { session.ensureRegistered() }
                catch (e: WarpAccountException) {
                    last = e
                    if (!e.retryable) throw e
                    continue
                }
                log.write(L.t("log.warpRegistrationProtectedOk", strategy.name))
                // Keep this exact transport for license PUT and account GET.
                return after(session)
            } catch (e: CancellationException) { throw e }
            finally { session.close() }
        }
        log.write(L.t("log.warpRegistrationProtectedFailed"))
        throw last
    }

    private suspend fun <T> withSession(strategy: Strategy?, block: suspend (WarpAccountSession) -> T): T {
        val session = sessions.open(strategy)
        try { return block(session) } finally { session.close() }
    }
}

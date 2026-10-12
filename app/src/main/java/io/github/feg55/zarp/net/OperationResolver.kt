package io.github.feg55.zarp.net

import io.github.feg55.zarp.core.Msg
import io.github.feg55.zarp.core.ZarpException
import java.net.InetAddress
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.thread
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Cache successes and failures for an operation, never across network changes. */
class OperationResolver(
    private val lookup: suspend (String) -> String = { host ->
        suspendCancellableCoroutine { continuation ->
            thread(name = "zarp-resolve", isDaemon = true) {
                try {
                    val addresses = InetAddress.getAllByName(host)
                    val address = (addresses.firstOrNull { it.address.size == 4 } ?: addresses.first()).hostAddress!!
                    if (continuation.isActive) continuation.resume(address)
                } catch (e: Exception) {
                    if (continuation.isActive) continuation.resumeWithException(e)
                }
            }
        }
    },
) {
    private val cache = mutableMapOf<String, Result<String>>()
    fun clear() = cache.clear()
    suspend fun resolve(host: String): String {
        cache[host]?.let { return it.getOrThrow() }
        val result = try {
            Result.success(withTimeout(15_000) { lookup(host) })
        } catch (_: TimeoutCancellationException) { Result.failure<String>(ZarpException(Msg("server.err.dns"))) }
        catch (e: CancellationException) { throw e }
        catch (_: Exception) { Result.failure<String>(ZarpException(Msg("server.err.dns"))) }
        cache[host] = result
        return result.getOrThrow()
    }
}

package io.github.feg55.zarp.net

import io.github.feg55.zarp.core.Subscription
import io.github.feg55.zarp.core.SubscriptionException
import io.github.feg55.zarp.core.SubscriptionResult
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URI
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.GZIPInputStream
import javax.net.ssl.SSLException
import kotlin.concurrent.thread
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout

/** One deadline covers redirects, decompression and the optional client-name retry. */
class SubscriptionDownloader(
    private val connect: (URI) -> HttpURLConnection = { it.toURL().openConnection() as HttpURLConnection },
    private val deadlineMs: Long = 25_000,
) {
    suspend fun load(url: String): SubscriptionResult {
        if (!Subscription.isUrl(url)) throw SubscriptionException("redirect")
        try {
            return withTimeout(deadlineMs) {
                val first = Subscription.parse(fetch(url, "Zarp/1.0"))
                if (first.links.isNotEmpty()) first else {
                    try { Subscription.parse(fetch(url, "v2rayN/7.0")).takeIf { it.links.isNotEmpty() } ?: first }
                    catch (_: SubscriptionException) { first }
                }
            }
        } catch (_: TimeoutCancellationException) { throw SubscriptionException("timeout") }
    }

    private suspend fun fetch(source: String, agent: String): String = suspendCancellableCoroutine { continuation ->
        val active = AtomicReference<HttpURLConnection?>()
        continuation.invokeOnCancellation { active.getAndSet(null)?.disconnect() }
        thread(name = "zarp-subscription", isDaemon = true) {
            fun cancelled() { if (!continuation.isActive) throw CancellationException() }
            try {
                var url = URI(source.trim())
                var answer: String? = null
                for (hop in 0..5) {
                    cancelled()
                    if (!Subscription.isUrl(url.toString())) throw SubscriptionException("redirect")
                    val connection = connect(url)
                    active.set(connection)
                    try {
                        cancelled()
                        connection.connectTimeout = deadlineMs.coerceAtMost(25_000).toInt()
                        connection.readTimeout = deadlineMs.coerceAtMost(25_000).toInt()
                        connection.instanceFollowRedirects = false
                        connection.setRequestProperty("User-Agent", agent)
                        connection.setRequestProperty("Accept", "*/*")
                        connection.setRequestProperty("Accept-Encoding", "gzip")
                        val code = connection.responseCode
                        if (code in setOf(301, 302, 303, 307, 308)) {
                            if (hop == 5) throw SubscriptionException("redirect")
                            val location = connection.getHeaderField("Location") ?: throw SubscriptionException("redirect")
                            url = try { url.resolve(location) } catch (_: Exception) { throw SubscriptionException("redirect") }
                            continue
                        }
                        if (code != 200) throw SubscriptionException("http", code)
                        if (connection.contentLengthLong > Subscription.MAX_BYTES) throw SubscriptionException("big")
                        val raw = connection.inputStream
                        val input = if (connection.contentEncoding.equals("gzip", true)) GZIPInputStream(raw) else raw
                        input.use {
                            val output = ByteArrayOutputStream()
                            val buffer = ByteArray(16 * 1024)
                            while (true) {
                                cancelled()
                                val n = it.read(buffer)
                                if (n < 0) break
                                if (output.size() + n > Subscription.MAX_BYTES) throw SubscriptionException("big")
                                output.write(buffer, 0, n)
                            }
                            if (output.size() == 0) throw SubscriptionException("empty")
                            answer = output.toString("UTF-8")
                        }
                        break
                    } finally {
                        active.compareAndSet(connection, null)
                        connection.disconnect()
                    }
                }
                cancelled()
                if (continuation.isActive) continuation.resume(answer ?: throw SubscriptionException("redirect"))
            } catch (e: Exception) {
                val safe = when (e) {
                    is SubscriptionException -> e
                    is SocketTimeoutException -> SubscriptionException("timeout")
                    is SSLException -> SubscriptionException("tls")
                    else -> SubscriptionException("network")
                }
                if (continuation.isActive) continuation.resumeWithException(safe)
            }
        }
    }
}

package io.github.feg55.zarp.net

import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.UUID
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.concurrent.thread
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.coroutineContext

/** Parsed https://www.cloudflare.com/cdn-cgi/trace response. */
data class Trace(val fields: Map<String, String>) {
    val warp: String? get() = fields["warp"]

    /** The only accepted proof that traffic goes through WARP. */
    val warpOn: Boolean get() = warp == "on" || warp == "plus"

    companion object {
        fun parse(body: String): Trace = Trace(
            body.lineSequence()
                .map { it.trim() }
                .mapNotNull { line ->
                    val i = line.indexOf('=')
                    if (i <= 0) null else line.substring(0, i) to line.substring(i + 1)
                }
                .toMap()
        )
    }
}

sealed interface Measurement {
    /** Median request time through the tunnel, warp=on|plus confirmed. */
    data class Ok(val pingMs: Int, val warp: String, val firstResponseMs: Int? = null) : Measurement

    /** cdn-cgi/trace answered, but not through WARP. */
    data class NotWarp(val warp: String?) : Measurement

    /** No request got through. */
    data class NoTraffic(val lastError: String?) : Measurement
}

/** Checks a local SOCKS5 proxy (the MASQUE core) against cdn-cgi/trace. */
interface WarpProbe {
    suspend fun measure(socksPort: Int, samples: Int): Measurement
    suspend fun measureProxy(socksPort: Int, samples: Int): Measurement = measure(socksPort, samples)
    /** Exactly one HTTPS request before spending time on latency samples. */
    suspend fun probeProxy(socksPort: Int): Measurement = measureProxy(socksPort, 0)
}

/**
 * Port of Zarp's Warp.MeasureAsync: samples+1 requests, each on a new connection;
 * the first is a warm-up; any answer without warp=on|plus fails immediately;
 * result is the median time.
 */
class TraceClient(
    private val timeoutMs: Int = 6000,
    private val host: String = HOST,
    private val clock: () -> Long = System::nanoTime,
) : WarpProbe {

    override suspend fun measure(socksPort: Int, samples: Int): Measurement =
        measureWith(samples, clock) { fetch(socksPort) }

    override suspend fun measureProxy(socksPort: Int, samples: Int): Measurement =
        measureWith(samples, clock, requireWarp = false) { fetch(socksPort) }

    /** One request through the SOCKS5 proxy on 127.0.0.1:[socksPort]. */
    suspend fun fetch(socksPort: Int): Trace = suspendCancellableCoroutine { continuation ->
        val raw = Socket()
        continuation.invokeOnCancellation { runCatching { raw.close() } }
        thread(name = "zarp-probe", isDaemon = true) {
            try {
                val trace = raw.use {
                    if (!continuation.isActive) throw IOException("request cancelled")
                    raw.soTimeout = timeoutMs
                    raw.connect(InetSocketAddress("127.0.0.1", socksPort), timeoutMs)
                    Socks5.connect(raw.getInputStream(), raw.getOutputStream(), host, 443)
                    val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                    (factory.createSocket(raw, host, 443, true) as SSLSocket).use { tls ->
                        tls.soTimeout = timeoutMs
                        tls.startHandshake()
                        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, tls.session)) {
                            throw IOException("certificate does not match $host")
                        }
                        val path = "/cdn-cgi/trace?" + UUID.randomUUID().toString().replace("-", "")
                        val req = "GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: Zarp-Android/1.0\r\n" +
                            "Accept: */*\r\nConnection: close\r\n\r\n"
                        tls.outputStream.write(req.toByteArray(Charsets.US_ASCII))
                        tls.outputStream.flush()
                        val response = readAll(tls.inputStream).toString(Charsets.UTF_8)
                        parseHttp(response)
                    }
                }
                if (continuation.isActive) continuation.resume(trace)
            } catch (e: Exception) {
                if (continuation.isActive) continuation.resumeWithException(e)
            }
        }
    }

    private fun readAll(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > 64 * 1024) throw IOException("trace response too large")
        }
        return out.toByteArray()
    }

    companion object {
        const val HOST = "www.cloudflare.com"

        /** The measuring rules, separate from the network for tests. */
        suspend fun measureWith(samples: Int, clock: () -> Long, fetch: suspend () -> Trace): Measurement =
            measureWith(samples, clock, true, fetch)

        suspend fun measureWith(samples: Int, clock: () -> Long, requireWarp: Boolean, fetch: suspend () -> Trace): Measurement {
            val times = mutableListOf<Int>()
            var lastError: String? = null
            var warp = "on"
            var firstResponseMs: Int? = null
            for (i in 0..samples) {
                coroutineContext.ensureActive()
                val started = clock()
                val trace = try {
                    fetch()
                } catch (e: IOException) {
                    lastError = e.message ?: e.javaClass.simpleName
                    continue
                }
                val ms = ((clock() - started) / 1_000_000).toInt()
                if (requireWarp && !trace.warpOn) return Measurement.NotWarp(trace.warp)
                if (!requireWarp && trace.fields["ip"].isNullOrBlank()) {
                    lastError = "trace response has no IP address"
                    continue
                }
                warp = trace.warp ?: "off"
                if (!requireWarp && firstResponseMs == null) firstResponseMs = ms
                if (i > 0 || samples == 0) times += ms // the first measurement request is a warm-up
            }
            if (times.isEmpty()) return Measurement.NoTraffic(lastError)
            times.sort()
            return Measurement.Ok(times[times.size / 2], warp, firstResponseMs)
        }

        fun parseHttp(response: String): Trace {
            val status = response.substringBefore("\r\n")
            val code = status.split(" ").getOrNull(1)?.toIntOrNull()
                ?: throw IOException("bad HTTP response: ${status.take(60)}")
            if (code != 200) throw IOException("cdn-cgi/trace: HTTP $code")
            return Trace.parse(response.substringAfter("\r\n\r\n", ""))
        }
    }
}

/** Minimal SOCKS5 CONNECT (no auth, domain name resolved by the proxy). */
object Socks5 {
    fun connect(input: InputStream, output: OutputStream, host: String, port: Int) {
        output.write(byteArrayOf(5, 1, 0))
        output.flush()
        val greeting = readN(input, 2)
        if (greeting[0].toInt() != 5 || greeting[1].toInt() != 0) throw IOException("SOCKS5: no acceptable auth method")
        val name = host.toByteArray(Charsets.US_ASCII)
        require(name.size in 1..255)
        val req = byteArrayOf(5, 1, 0, 3, name.size.toByte()) + name + byteArrayOf((port shr 8).toByte(), port.toByte())
        output.write(req)
        output.flush()
        val head = readN(input, 4)
        if (head[0].toInt() != 5) throw IOException("SOCKS5: bad reply version")
        if (head[1].toInt() != 0) throw IOException("SOCKS5: connect failed (reply ${head[1]})")
        val addrLen = when (head[3].toInt()) {
            1 -> 4
            4 -> 16
            3 -> readN(input, 1)[0].toInt() and 0xff
            else -> throw IOException("SOCKS5: bad address type ${head[3]}")
        }
        readN(input, addrLen + 2)
    }

    private fun readN(input: InputStream, n: Int): ByteArray {
        val b = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(b, off, n - off)
            if (r < 0) throw IOException("SOCKS5: connection closed")
            off += r
        }
        return b
    }
}

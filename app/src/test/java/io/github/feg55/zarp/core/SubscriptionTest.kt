package io.github.feg55.zarp.core

import io.github.feg55.zarp.data.ServerRepository
import io.github.feg55.zarp.net.SubscriptionDownloader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPOutputStream
import javax.net.ssl.SSLHandshakeException
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class SubscriptionTest {
    private val link = "vless://00000000-0000-4000-8000-000000000001@server.example.com:443?security=tls#Example"
    private val source = "https://subscription.example.com/list?token=test-token"
    @Before fun language() = TestLang.english()

    @Test fun plainAndAllBase64Variants() {
        val body = "# Comment\n" + link + "\n" + "hy2://test-password@quic.example.com:443#Example"
        assertEquals(2, Subscription.parse("\uFEFF" + body).links.size)
        for (encoder in listOf(Base64.getEncoder(), Base64.getUrlEncoder())) {
            for (padding in listOf(true, false)) {
                val encoded = (if (padding) encoder else encoder.withoutPadding()).encodeToString(body.toByteArray())
                assertEquals(2, Subscription.parse(encoded.chunked(19).joinToString("\n")).links.size)
            }
        }
    }

    @Test fun mixedMalformedAndDuplicateLinesHaveCounts() {
        val result = Subscription.parse(listOf(link, link + "-renamed", "vmess://test-only", "ss://test-only",
            "not a link", link.substringBefore('?') + "?fm=test-value", "trojan://@server.example.com:443", "", "# Comment").joinToString("\n"))
        assertEquals(1, result.links.size)
        assertEquals(3, result.unsupported)
        assertEquals(2, result.refused)
        assertFalse(result.toString().contains("test-value"))
        assertTrue(Subscription.parse("%%% malformed base64").links.isEmpty())
    }

    @Test fun jsonAndHtmlAreNamedAndLimitsAreEnforced() {
        for ((body, reason) in listOf("""{"servers":[]}""" to "json", "<!DOCTYPE html><html></html>" to "html")) {
            val failure = runCatching { Subscription.parse(body).requireServers() }.exceptionOrNull() as SubscriptionException
            assertEquals(reason, failure.reason)
        }
        val many = (1..203).joinToString("\n") { link.replace(":443?", ":" + (1000 + it) + "?") }
        val limited = Subscription.parse(many)
        assertEquals(200, limited.links.size)
        assertEquals(3, limited.truncated)
        assertEquals("big", (runCatching { Subscription.parse("x".repeat(Subscription.MAX_BYTES + 1)) }.exceptionOrNull() as SubscriptionException).reason)
        assertNull(SubscriptionSnapshot.decode("""{"source":"test","links":[]}"""))
    }

    @Test fun httpsSourceRulesAndNames() {
        assertTrue(Subscription.isUrl(source))
        for (bad in listOf("http://example.com/list", "https://user:password@example.com/list",
            "https://example.com/list#fragment", "https:///list", "https://example.com:65536/list")) assertFalse(Subscription.isUrl(bad))
        assertEquals("proxy.subscriptionHttps", Subscription.explainSource("http://example.com/list")!!.key)
        val profiles = listOf(link, link.replace("server.example.com", "other.example.com"),
            link.replace("security=tls", "security=tls&fp=chrome")).map(ProxyProfile::parse)
        val names = ServerPairs.names(profiles)
        assertEquals(3, names.toSet().size)
        assertEquals("Example [server.example.com:443] #2", names[2])
    }

    private class Response(
        val code: Int = 200,
        val bytes: ByteArray,
        val headers: Map<String, String> = emptyMap(),
        val declaredSize: Long = -1,
        val failure: Exception? = null,
        val input: InputStream? = null,
    ) : HttpURLConnection(URL("https://example.com/")) {
        @Volatile var disconnected = false
        override fun connect() = Unit
        override fun usingProxy() = false
        override fun disconnect() { disconnected = true; input?.close() }
        override fun getResponseCode(): Int { failure?.let { throw it }; return code }
        override fun getInputStream(): InputStream = input ?: ByteArrayInputStream(bytes)
        override fun getHeaderField(name: String): String? = headers[name]
        override fun getContentLengthLong() = declaredSize
        override fun getContentEncoding() = headers["Content-Encoding"]
    }
    private fun response(body: String) = Response(bytes = body.toByteArray())

    @Test fun retryUsesV2rayNOnlyForUnusableResponse() = runBlocking {
        val responses = mutableListOf(response("<html>Panel</html>"), response(link))
        val seen = mutableListOf<Response>()
        val downloader = SubscriptionDownloader(connect = { responses.removeAt(0).also { seen += it } })
        assertEquals(listOf(link), downloader.load(source).links)
        assertEquals(listOf("Zarp/1.0", "v2rayN/7.0"), seen.map { it.getRequestProperty("User-Agent") })
        assertTrue(seen.all { it.disconnected && !it.instanceFollowRedirects })
        val first = response("""{"not":"a list"}""")
        var count = 0
        val failedRetry = SubscriptionDownloader(connect = { if (count++ == 0) first else Response(bytes = byteArrayOf(), failure = SSLHandshakeException(source)) })
        assertTrue(failedRetry.load(source).json)
        assertEquals(2, count)
        count = 0
        val httpFailure = SubscriptionDownloader(connect = { count++; Response(403, byteArrayOf()) })
        assertEquals("http", (runCatching { httpFailure.load(source) }.exceptionOrNull() as SubscriptionException).reason)
        assertEquals(1, count)
    }

    @Test fun redirectsAreHttpsOnlyAndAtMostFive() = runBlocking {
        var count = 0
        val good = SubscriptionDownloader(connect = {
            count++
            if (count <= 5) Response(302, byteArrayOf(), mapOf("Location" to "/hop" + count)) else response(link)
        })
        assertEquals(1, good.load(source).links.size)
        assertEquals(6, count)
        count = 0
        val loop = SubscriptionDownloader(connect = { count++; Response(302, byteArrayOf(), mapOf("Location" to "/again")) })
        assertEquals("redirect", (runCatching { loop.load(source) }.exceptionOrNull() as SubscriptionException).reason)
        assertEquals(6, count)
        for (location in listOf("http://example.com/list", "https://user:password@example.com/list", "https://example.com/list#fragment")) {
            count = 0
            val unsafe = SubscriptionDownloader(connect = { count++; Response(302, byteArrayOf(), mapOf("Location" to location)) })
            assertEquals("redirect", (runCatching { unsafe.load(source) }.exceptionOrNull() as SubscriptionException).reason)
            assertEquals(1, count)
        }
    }

    @Test fun compressedAndStreamingSizesAndTlsErrorsAreSafe() = runBlocking {
        val compressed = ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(link.toByteArray()) } }.toByteArray()
        assertEquals(1, SubscriptionDownloader(connect = { Response(bytes = compressed, headers = mapOf("Content-Encoding" to "gzip")) }).load(source).links.size)
        for (response in listOf(Response(bytes = byteArrayOf(), declaredSize = Subscription.MAX_BYTES + 1L),
            Response(bytes = ByteArray(Subscription.MAX_BYTES + 1)))) {
            assertEquals("big", (runCatching { SubscriptionDownloader(connect = { response }).load(source) }.exceptionOrNull() as SubscriptionException).reason)
        }
        val tls = runCatching { SubscriptionDownloader(connect = { Response(bytes = byteArrayOf(), failure = SSLHandshakeException(source)) }).load(source) }.exceptionOrNull() as SubscriptionException
        assertEquals("tls", tls.reason)
        assertFalse(tls.message!!.contains("test-token"))
        assertFalse(tls.message!!.contains("subscription.example.com"))
    }

    @Test fun oneDeadlineAndCancellationDisconnectBlockedReads() = runBlocking {
        fun blocked(): Pair<Response, CountDownLatch> {
            val entered = CountDownLatch(1)
            val closed = CountDownLatch(1)
            val input = object : InputStream() {
                override fun read(): Int { entered.countDown(); closed.await(5, TimeUnit.SECONDS); return -1 }
                override fun close() { closed.countDown() }
            }
            return Response(bytes = byteArrayOf(), input = input) to entered
        }
        val (timed, _) = blocked()
        val failure = runCatching { SubscriptionDownloader(connect = { timed }, deadlineMs = 80).load(source) }.exceptionOrNull() as SubscriptionException
        assertEquals("timeout", failure.reason)
        assertTrue(timed.disconnected)
        val (cancelled, entered) = blocked()
        val job = launch(Dispatchers.Default) { SubscriptionDownloader(connect = { cancelled }).load(source) }
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        withTimeout(1000) { job.cancelAndJoin() }
        assertTrue(cancelled.disconnected)
    }

    @Test fun cacheIsBoundToSourceAndSurvivesFailedRefreshAndRestart() = runTest {
        var now = 100_000L
        var settings = AppSettings(useProxy = true, proxyUri = source)
        var calls = 0
        var answer = SubscriptionResult(listOf(link))
        var error: Exception? = null
        val logs = LogBus()
        val repository = ServerRepository({ settings }, { settings = it(settings) }, {
            calls++; error?.let { throw it }; answer
        }, logs, { now })
        assertTrue(repository.save(source, "", true))
        val selected = ProxyProfile.parse(link).id
        settings = settings.copy(serverSelectionId = selected)
        val encoded = SubscriptionSnapshot.encode(settings.subscription!!)
        settings = settings.copy(subscription = SubscriptionSnapshot.decode(encoded))
        repository.ensure(settings)
        assertEquals(1, calls)
        now += Subscription.MAX_AGE_MS + 1
        error = SubscriptionException("network")
        assertEquals(listOf(link), repository.ensure(settings).subscription!!.links)
        assertEquals(selected, settings.serverSelectionId)
        assertFalse(repository.save(source, "", true))
        assertEquals("proxy.subKept", repository.importState.value.error!!.key)
        assertEquals(listOf(link), settings.subscription!!.links)
        error = null
        answer = SubscriptionResult(listOf(link.replace("server.example.com", "other.example.com")))
        assertTrue(repository.save(source, "", true))
        assertEquals(selected, settings.serverSelectionId)
        assertTrue(ServerPairs.profiles(settings).none { it.id == selected })
        assertTrue(ServerPairs.profiles(settings.copy(proxyUri = "https://other.example.com/list")).isEmpty())
        assertTrue(logs.lines.value.none { it.contains("test-token") || it.contains("vless://") || it.contains("server.example.com") })
        repository.delete()
        assertNull(settings.subscription)
        assertNull(settings.serverSelectionId)
        assertFalse(settings.useProxy)
    }
}

package io.github.feg55.zarp.strategy

import io.github.feg55.zarp.core.Blob
import io.github.feg55.zarp.core.StrategyCatalog
import io.github.feg55.zarp.core.Strategy
import io.github.feg55.zarp.core.Transport
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.InetSocketAddress

class FakeStrategyTest {
    // the real blobs shipped in the APK
    private val assets = File("src/main/assets")
    private val blobs = BlobStore { File(assets, it).inputStream() }
    private val endpoint = InetSocketAddress("162.159.198.1", 443)

    /** Records everything a strategy does to the socket, in order. */
    private class RecordingSocket(override val isIpv6: Boolean = false, private var ttl: Int = 64) : StrategySocket {
        val events = mutableListOf<String>()
        val sent = mutableListOf<Pair<ByteArray, Int>>() // payload, ttl at send time

        override fun send(payload: ByteArray, endpoint: InetSocketAddress) {
            events += "send"
            sent += payload to ttl
        }

        override fun getTtl() = ttl

        override fun setTtl(ttl: Int) {
            events += "ttl=$ttl"
            this.ttl = ttl
        }
    }

    private fun strategy(id: String) =
        ZarpStrategies.forStrategy(StrategyCatalog.builtIn.single { it.id == id }, blobs)

    @Test
    fun `blobs are real QUIC Initial packets`() {
        for (b in listOf(Blob.QuicGoogle, Blob.QuicVk)) {
            val data = blobs.bytes(b)
            assertTrue("${b.key} is at least 1200 bytes", data.size >= 1200)
            assertEquals("long header, Initial", 0xC0, data[0].toInt() and 0xF0)
            assertEquals("QUIC v1", listOf(0, 0, 0, 1), data.slice(1..4).map { it.toInt() })
        }
        assertEquals(64, blobs.bytes(Blob.Zero64).size)
    }

    @Test
    fun `fake google x6 sends six google Initials`() = runTest {
        val sock = RecordingSocket()
        strategy("warp-q-google6").beforeHandshake(sock, endpoint)
        assertEquals(6, sock.sent.size)
        sock.sent.forEach { assertArrayEquals(blobs.bytes(Blob.QuicGoogle), it.first) }
        assertEquals(List(6) { "send" }, sock.events) // TTL untouched
    }

    @Test
    fun `google + vk keeps order`() = runTest {
        val sock = RecordingSocket()
        strategy("warp-q-google-vk").beforeHandshake(sock, endpoint)
        val g = blobs.bytes(Blob.QuicGoogle)
        val v = blobs.bytes(Blob.QuicVk)
        assertEquals(6, sock.sent.size)
        sock.sent.take(3).forEach { assertArrayEquals(g, it.first) }
        sock.sent.drop(3).forEach { assertArrayEquals(v, it.first) }
    }

    @Test
    fun `ttl 4 applies only to fakes and is restored`() = runTest {
        val sock = RecordingSocket(ttl = 64)
        strategy("warp-q-google-ttl").beforeHandshake(sock, endpoint)
        assertEquals(listOf("ttl=4") + List(6) { "send" } + "ttl=64", sock.events)
        assertTrue(sock.sent.all { it.second == 4 })
        assertEquals(64, sock.getTtl()) // the real Initial goes out with the normal TTL
    }

    @Test
    fun `ttl uses hop limit on ipv6 sockets`() = runTest {
        val sock = RecordingSocket(isIpv6 = true, ttl = 255)
        strategy("warp-q-vk-ttl").beforeHandshake(sock, InetSocketAddress("2606:4700:103::1", 443))
        assertEquals("ttl=4", sock.events.first())
        assertEquals("ttl=255", sock.events.last())
    }

    @Test
    fun `ttl is restored even if sending fails`() = runTest {
        var current = 64
        val sock = object : StrategySocket {
            override val isIpv6 = false
            override fun send(payload: ByteArray, endpoint: InetSocketAddress) = throw java.io.IOException("network down")
            override fun getTtl() = current
            override fun setTtl(ttl: Int) { current = ttl }
        }
        runCatching { strategy("warp-q-google-ttl").beforeHandshake(sock, endpoint) }
        assertEquals(64, current)
    }

    @Test
    fun `direct and http2 strategies send nothing from the udp socket`() = runTest {
        assertSame(DirectStrategy, strategy(StrategyCatalog.DIRECT_ID))
        assertSame(DirectStrategy, strategy("warp-t-split"))
        val sock = RecordingSocket()
        DirectStrategy.beforeHandshake(sock, endpoint)
        assertTrue(sock.events.isEmpty())
    }

    @Test(expected = UnsupportedStrategyException::class)
    fun `badsum is refused`() {
        ZarpStrategies.forStrategy(Strategy("custom-raw", "Raw", Transport.MasqueH3,
            "--lua-desync=fake:blob=quic_google:badsum"), blobs)
    }
}

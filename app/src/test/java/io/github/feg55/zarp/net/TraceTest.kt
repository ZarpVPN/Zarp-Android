package io.github.feg55.zarp.net

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException

class TraceTest {
    private val body = """
        fl=123f45
        h=www.cloudflare.com
        ip=104.28.222.16
        ts=1758760000.123
        visit_scheme=https
        uag=Zarp-Android/1.0
        colo=HEL
        http=http/1.1
        loc=FI
        tls=TLSv1.3
        warp=on
        gateway=off
    """.trimIndent()

    @Test
    fun `parses trace and accepts only warp on or plus`() {
        val t = Trace.parse(body)
        assertEquals("on", t.warp)
        assertEquals("FI", t.fields["loc"])
        assertTrue(t.warpOn)
        assertTrue(Trace.parse("warp=plus").warpOn)
        assertFalse(Trace.parse("warp=off").warpOn)
        assertFalse(Trace.parse("ip=1.2.3.4").warpOn)
    }

    @Test
    fun `parses http response`() {
        val resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n$body"
        assertEquals("on", TraceClient.parseHttp(resp).warp)
    }

    @Test(expected = IOException::class)
    fun `non 200 is an error`() {
        TraceClient.parseHttp("HTTP/1.1 403 Forbidden\r\n\r\nwarp=on")
    }

    /** Fake clock: every fetch "takes" the next duration. */
    private fun timed(vararg ms: Long, fetch: (Int) -> Trace): Pair<() -> Long, suspend () -> Trace> {
        var now = 0L
        var i = 0
        val clock = { now }
        val f: suspend () -> Trace = {
            val k = i++
            now += ms[k] * 1_000_000
            fetch(k)
        }
        return clock to f
    }

    @Test
    fun `median of samples, first request is warm-up`() = runTest {
        val (clock, fetch) = timed(900, 80, 120, 100) { Trace.parse("warp=on") }
        assertEquals(Measurement.Ok(100, "on"), TraceClient.measureWith(3, clock, fetch))
    }

    @Test
    fun `warp off fails immediately`() = runTest {
        val (clock, fetch) = timed(50, 50, 50, 50) { Trace.parse("warp=off") }
        assertEquals(Measurement.NotWarp("off"), TraceClient.measureWith(3, clock, fetch))
    }

    @Test
    fun `custom proxy accepts a valid trace with warp off but rejects an empty page`() = runTest {
        val (clock, fetch) = timed(70, 40) { Trace.parse("ip=203.0.113.7\nwarp=off") }
        assertEquals(Measurement.Ok(40, "off", firstResponseMs = 70), TraceClient.measureWith(1, clock, false, fetch))
        val (clock2, empty) = timed(70, 40) { Trace.parse("<html>login</html>") }
        assertTrue(TraceClient.measureWith(1, clock2, false, empty) is Measurement.NoTraffic)
    }

    @Test
    fun `failed requests are skipped, all failed means no traffic`() = runTest {
        val (clock, fetch) = timed(10, 10, 10, 10) { k -> if (k < 3) throw IOException("reset $k") else Trace.parse("warp=plus") }
        assertEquals(Measurement.Ok(10, "plus"), TraceClient.measureWith(3, clock, fetch))
        val (clock2, fetch2) = timed(10, 10, 10, 10) { throw IOException("timeout") }
        assertEquals(Measurement.NoTraffic("timeout"), TraceClient.measureWith(3, clock2, fetch2))
    }

    @Test
    fun `socks5 connect sends domain name request`() {
        val server = ByteArrayInputStream(byteArrayOf(5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90.toByte()))
        val out = ByteArrayOutputStream()
        Socks5.connect(server, out, "www.cloudflare.com", 443)
        val name = "www.cloudflare.com".toByteArray()
        val expected = byteArrayOf(5, 1, 0) + byteArrayOf(5, 1, 0, 3, name.size.toByte()) + name + byteArrayOf(1, 0xBB.toByte())
        assertArrayEquals(expected, out.toByteArray())
        assertEquals(0, server.available())
    }

    @Test(expected = IOException::class)
    fun `socks5 connect failure is reported`() {
        val server = ByteArrayInputStream(byteArrayOf(5, 0, 5, 4, 0, 1, 0, 0, 0, 0, 0, 0))
        Socks5.connect(server, ByteArrayOutputStream(), "www.cloudflare.com", 443)
    }
}

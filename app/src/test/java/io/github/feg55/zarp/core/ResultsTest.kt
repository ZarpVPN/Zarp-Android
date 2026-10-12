package io.github.feg55.zarp.core

import io.github.feg55.zarp.data.DataStoreZarpStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ResultsTest {
    @Test
    fun `score is connect plus four pings`() {
        assertEquals(300 + 4 * 50, TestResult("a", ok = true, connectMs = 300, pingMs = 50).score)
        assertEquals(Int.MAX_VALUE, TestResult("a", ok = false, connectMs = 1, pingMs = 1).score)
    }

    @Test
    fun `confirmed merge takes slower connect and average ping`() {
        val r1 = TestResult("a", ok = true, connectMs = 400, pingMs = 60, timestamp = 1)
        val r2 = TestResult("a", ok = true, connectMs = 700, pingMs = 40, endpoint = "192.0.2.2:500", timestamp = 2)
        val m = TestResult.confirmed(r1, r2)
        assertTrue(m.ok && m.confirmed)
        assertEquals(700, m.connectMs)
        assertEquals(50, m.pingMs)
        assertEquals(2L, m.timestamp)
        assertEquals("192.0.2.2:500", m.endpoint)
    }

    @Test
    fun `errors are shown in the current language`() {
        TestLang.english()
        assertEquals("not confirmed: timeout", TestResult("a", error = "timeout", rechecked = true).displayError)
        val r = TestResult.failed("a", Msg("err.timeout", 15), 1).copy(rechecked = true)
        assertEquals("not confirmed: no connection within 15 s", r.displayError)
        L.setLanguage("ru")
        assertEquals("не подтвердилась: нет подключения за 15 с", r.displayError)
        L.setLanguage("en")
    }

    @Test
    fun `results survive a json round trip`() {
        val map = mapOf(
            "warp-q-google6" to TestResult("warp-q-google6", ok = true, confirmed = true, connectMs = 812, pingMs = 71, timestamp = 1_700_000_000_000),
            "direct" to TestResult("direct", errorKey = "err.timeout", errorArgs = listOf("15"), timestamp = 5),
        )
        assertEquals(map, DataStoreZarpStore.decodeResults(DataStoreZarpStore.encodeResults(map)))
        assertEquals(emptyMap<String, TestResult>(), DataStoreZarpStore.decodeResults("{broken"))
    }

    @Test
    fun `endpoints rotate like Zarp`() {
        val e = WarpEndpoints()
        val h3 = (0 until 12).map { e.next(Transport.MasqueH3) }
        assertEquals(
            listOf(
                "162.159.198.1:443", "162.159.198.2:443", "162.159.198.1:500", "162.159.198.2:500",
                "162.159.198.1:1701", "162.159.198.2:1701", "162.159.198.1:4500", "162.159.198.2:4500",
                "162.159.198.1:4443", "162.159.198.2:4443", "162.159.198.1:8443", "162.159.198.2:8443",
            ),
            h3,
        )
        assertEquals(h3.size, h3.toSet().size)
        // HTTP/2 has a single endpoint with the pinned key
        assertEquals("162.159.198.2:443", e.next(Transport.MasqueH2))
        assertEquals("162.159.198.2:443", e.next(Transport.MasqueH2))
    }
}

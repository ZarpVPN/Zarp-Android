package io.github.feg55.zarp.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class WarpAccountManagerTest {
    @Before fun language() = TestLang.english()

    private class Env {
        val opened = mutableListOf<String>()
        val closed = mutableListOf<String>()
        val calls = mutableListOf<String>()
        var existing = false
        var failDirect = "network"
        var failProtected: String? = null
        var failLicense: String? = null
        val manager = WarpAccountManager({ strategy ->
            val id = strategy?.id ?: "direct"
            opened += id
            object : WarpAccountSession {
                override suspend fun ensureRegistered() {
                    calls += "$id/register"
                    if (!existing && strategy == null) throw WarpAccountException(failDirect)
                    failProtected?.let { if (strategy != null) throw WarpAccountException(it) }
                    existing = true
                }
                override suspend fun read(): WarpAccountType { calls += "$id/read"; return WarpAccountType.Unlimited }
                override suspend fun apply(license: String): WarpAccountType {
                    calls += "$id/apply"
                    failLicense?.let { throw WarpAccountException(it) }
                    return read()
                }
                override fun close() { closed += id }
            }
        }, { existing }, LogBus())
        val strategies = StrategyCatalog.builtIn.filter { it.plan.tcpDesync != null }
    }

    @Test fun `blocked registration keeps protected transport for license and account`() = runTest {
        val e = Env()
        assertEquals(WarpAccountType.Unlimited, e.manager.apply("12345678-abcdefgh-ABCD1234", e.strategies, true))
        val protected = e.opened[1]
        assertEquals(listOf("direct/register", "$protected/register", "$protected/apply", "$protected/read"), e.calls)
        assertEquals(e.opened, e.closed)
    }

    @Test fun `rate limits rejections storage and license failures never trigger extra requests`() = runTest {
        for (code in listOf("rateLimit", "rejected", "config", "api")) {
            val e = Env().apply { failDirect = code }
            try { e.manager.ensure(e.strategies, true); fail(code) } catch (ex: WarpAccountException) { assertEquals(code, ex.code) }
            assertEquals(listOf("direct"), e.opened)
            assertEquals(e.opened, e.closed)
        }
        val e = Env().apply { failLicense = "network" }
        try { e.manager.apply("12345678-abcdefgh-ABCD1234", e.strategies, true); fail() } catch (_: WarpAccountException) { }
        assertEquals(2, e.opened.size)
        assertEquals(1, e.calls.count { it.endsWith("/apply") })
        assertEquals(e.opened, e.closed)
    }

    @Test fun `existing registrations are untouched and unsafe contexts do not search`() = runTest {
        val e = Env().apply { existing = true }
        e.manager.ensure(e.strategies, true)
        assertTrue(e.opened.isEmpty())
        e.manager.apply("12345678-abcdefgh-ABCD1234", e.strategies, true)
        assertEquals(listOf("direct"), e.opened)
        val blocked = Env()
        try { blocked.manager.ensure(blocked.strategies, false); fail() } catch (_: WarpAccountException) { }
        assertEquals(listOf("direct"), blocked.opened)
    }

    @Test fun `only supported TLS strategies are used and terminal failures stop search`() = runTest {
        val e = Env().apply { failProtected = "rateLimit" }
        val unsupported = e.strategies.first().copy(id = "unsupported", deviceIssue = Msg("unsup.tcpTtl"))
        try { e.manager.ensure(StrategyCatalog.builtIn + unsupported, true); fail() } catch (_: WarpAccountException) { }
        assertEquals(2, e.opened.size)
        assertEquals(e.opened, e.closed)
    }

    @Test fun `invalid licenses never open a session`() = runTest {
        val e = Env()
        for (license in listOf("", "secret", "12345678-abcdefgh-ABCD1234\nextra")) {
            try { e.manager.apply(license, e.strategies, true); fail() } catch (ex: WarpAccountException) { assertEquals("invalid", ex.code) }
        }
        assertTrue(e.opened.isEmpty())
        assertTrue(WarpAccountType.validLicense(" 12345678-abcdefgh-ABCD1234 "))
    }

    @Test fun `cancellation closes an in-flight API transport`() = runTest {
        val started = CompletableDeferred<Unit>()
        val wait = CompletableDeferred<Unit>()
        var closed = false
        val manager = WarpAccountManager({ object : WarpAccountSession {
            override suspend fun ensureRegistered() { started.complete(Unit); wait.await() }
            override suspend fun read() = WarpAccountType.Unknown
            override suspend fun apply(license: String) = WarpAccountType.Unknown
            override fun close() { closed = true }
        } }, { false }, LogBus())
        val job = async { manager.ensure(emptyList(), true) }
        started.await()
        job.cancel(); job.join()
        assertTrue(closed)
    }
}

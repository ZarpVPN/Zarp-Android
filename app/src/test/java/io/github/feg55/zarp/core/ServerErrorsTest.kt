package io.github.feg55.zarp.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerErrorsTest {
    @Test fun exactNativeClassesTakePrecedenceOverDetail() {
        for (kind in listOf("refused", "timeout", "unreachable", "reset", "certificate", "ech", "reality", "status", "ttl", "protect", "blocked", "other")) {
            val msg = ServerErrors.describe(kind, "tls: server rejected ECH at example.com test-password")
            assertEquals("server.err." + kind, msg.key)
            assertTrue(msg.args.isEmpty())
        }
    }

    @Test fun fallbackClassifiesWordsWithoutMatchingUnrelatedSubstrings() {
        for (detail in listOf("technical failure", "mechanical failure", "unreality", "certificateStore failed", "preview protection failure", "thereof", "preset statusCode", "ECHRejectionError")) {
            assertEquals(detail, "server.err.other", ServerErrors.describe("", detail).key)
        }
        for ((detail, kind) in listOf(
            "tls: server rejected ECH" to "ech", "encrypted client hello rejected" to "ech",
            "REALITY: invalid connection" to "reality", "x509: unknown authority" to "certificate",
            "pinned certificate mismatch" to "certificate", "zarp: ttl failed" to "ttl",
            "VpnService.protect failed" to "protect", "only dials its own server" to "blocked",
            "connection refused" to "refused", "i/o timeout" to "timeout", "deadline exceeded" to "timeout",
            "network unreachable" to "unreachable", "connection reset" to "reset", "EOF" to "reset",
            "unexpected status 404" to "status",
        )) assertEquals(detail, "server.err." + kind, ServerErrors.describe("", detail).key)
        assertEquals("server.err.other", ServerErrors.describe("technical", "technical failure").key)
    }
}

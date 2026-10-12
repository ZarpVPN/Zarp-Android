package io.github.feg55.zarp.core

/** Raw engine diagnostics never leave this classifier. */
object ServerErrors {
    private val classes = setOf("refused", "timeout", "unreachable", "reset", "certificate", "ech", "reality", "status", "ttl", "protect", "blocked", "other")
    fun describe(kind: String, detail: String = ""): Msg {
        val detected = if (kind in classes) kind else classify(detail)
        return Msg("server.err." + detected)
    }
    private fun classify(text: String): String {
        val s = text.lowercase()
        val words = s.split(Regex("[^\\p{L}\\p{N}_]+")).toSet()
        return when {
            "ech" in words || "encrypted client hello" in s -> "ech"
            "reality" in words -> "reality"
            "x509" in words || "certificate" in words || "pinned" in words -> "certificate"
            "ttl" in words -> "ttl"
            "protect" in words -> "protect"
            "only dials" in s -> "blocked"
            "refused" in words -> "refused"
            "timeout" in words || "timed out" in s || "deadline" in words -> "timeout"
            "unreachable" in words || "no route" in s -> "unreachable"
            "reset" in words || "eof" in words -> "reset"
            "status" in words -> "status"
            else -> "other"
        }
    }
}

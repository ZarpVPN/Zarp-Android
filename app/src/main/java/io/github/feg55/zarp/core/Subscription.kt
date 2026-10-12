package io.github.feg55.zarp.core

import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class SubscriptionSnapshot(
    val source: String, val links: List<String>, val updatedAt: Long,
    val unsupported: Int = 0, val refused: Int = 0, val truncated: Int = 0,
) {
    override fun toString() = "SubscriptionSnapshot(servers=" + links.size + ", updatedAt=$updatedAt)"
    fun fresh(now: Long) = updatedAt > 0 && now >= updatedAt && now - updatedAt < Subscription.MAX_AGE_MS
    companion object {
        private val json = Json { ignoreUnknownKeys = true }
        fun decode(text: String): SubscriptionSnapshot? = runCatching {
            require(text.length <= Subscription.MAX_BYTES * 2)
            json.decodeFromString<SubscriptionSnapshot>(text).also {
                require(it.links.size in 1..Subscription.MAX_SERVERS && it.links.all { link -> link.length <= 8192 })
            }
        }.getOrNull()
        fun encode(snapshot: SubscriptionSnapshot) = json.encodeToString(serializer(), snapshot)
    }
}

data class SubscriptionResult(
    val links: List<String>, val unsupported: Int = 0, val refused: Int = 0, val truncated: Int = 0,
    val json: Boolean = false, val html: Boolean = false,
) {
    override fun toString() = "SubscriptionResult(servers=" + links.size + ", unsupported=$unsupported, refused=$refused, truncated=$truncated)"
    fun requireServers(): SubscriptionResult {
        if (links.isEmpty()) throw SubscriptionException(when { json -> "json"; html -> "html"; else -> "empty" })
        return this
    }
}

class SubscriptionException(val reason: String, val status: Int = 0) : ZarpException(
    if (reason == "http") Msg("proxy.subHttp", status) else Msg("proxy.sub" + when (reason) {
        "timeout" -> "Timeout"
        "tls" -> "Tls"
        "big" -> "Big"
        "redirect" -> "Redirect"
        "empty" -> "Empty"
        "json" -> "Json"
        "html" -> "Html"
        else -> "Network"
    }),
)

/** Plain link lists and base64 link lists. No arbitrary client configuration is imported. */
object Subscription {
    const val MAX_BYTES = 2 * 1024 * 1024
    const val MAX_SERVERS = 200
    const val MAX_AGE_MS = 12 * 60 * 60 * 1000L
    private val scheme = Regex("^[A-Za-z][A-Za-z0-9+.\\-]*://")
    fun isUrl(text: String) = RoutingSettings.validSource(text.trim())
    fun sourceId(text: String) = ProxyProfile.identity(text.trim()).removePrefix("proxy-")

    fun explainSource(text: String): Msg? = when {
        isUrl(text) -> null
        text.trim().startsWith("http://", true) -> Msg("proxy.subscriptionHttps")
        text.trim().startsWith("https://", true) -> Msg("proxy.subscriptionUrl")
        else -> ProxyProfile.explain(text)
    }

    fun parse(body: String): SubscriptionResult {
        if (body.toByteArray(Charsets.UTF_8).size > MAX_BYTES) throw SubscriptionException("big")
        var text = body.trimStart('\uFEFF').trim()
        if (text.lineSequence().none { scheme.containsMatchIn(it.trim()) }) {
            val compact = text.replace(Regex("\\s+"), "").trimEnd('=').replace('-', '+').replace('_', '/')
            if (compact.length >= 8 && compact.length % 4 != 1 && compact.matches(Regex("[A-Za-z0-9+/]+"))) {
                val decoded = runCatching { String(Base64.getDecoder().decode(compact), Charsets.UTF_8).trimStart('\uFEFF') }.getOrNull()
                if (decoded != null && ("://" in decoded || decoded.trimStart().startsWith('{') || decoded.trimStart().startsWith('['))) text = decoded
            }
        }
        val trimmed = text.trimStart()
        if (trimmed.startsWith('{') || trimmed.startsWith('[')) return SubscriptionResult(emptyList(), json = true)
        if (trimmed.startsWith("<!doctype", true) || trimmed.startsWith("<html", true)) return SubscriptionResult(emptyList(), html = true)
        var unsupported = 0
        var refused = 0
        var truncated = 0
        val links = mutableListOf<String>()
        val seen = mutableSetOf<String>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith('#')) continue
            if (!scheme.containsMatchIn(line) || line.substringBefore("://").lowercase() !in setOf("vless", "trojan", "hy2", "hysteria2")) { unsupported++; continue }
            val profile = runCatching { ProxyProfile.parse(line) }.getOrNull()
            if (profile == null) { refused++; continue }
            if (!seen.add(profile.id)) continue
            if (links.size == MAX_SERVERS) { truncated++; continue }
            links += line
        }
        return SubscriptionResult(links, unsupported, refused, truncated)
    }
}

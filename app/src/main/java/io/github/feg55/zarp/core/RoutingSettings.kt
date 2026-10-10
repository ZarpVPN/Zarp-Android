package io.github.feg55.zarp.core

import java.net.URI
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.put

@Serializable
data class RoutingPreset(
    val id: String,
    val name: String = "",
    val direct: String = "",
    val proxy: String = "",
    val block: String = "",
) {
    fun text(action: String) = when (action) { "direct" -> direct; "proxy" -> proxy; else -> block }
    fun withRules(action: String, text: String) = when (action) {
        "direct" -> copy(direct = text); "proxy" -> copy(proxy = text); else -> copy(block = text)
    }
    fun rulesJson(): String = buildJsonObject {
        listOf("direct", "proxy", "block").forEach { action ->
            put(action, buildJsonArray { lines(text(action)).forEach { add(JsonPrimitive(it)) } })
        }
    }.toString()

    companion object {
        fun lines(text: String) = text.lineSequence().map(String::trim)
            .filter { it.isNotEmpty() && !it.startsWith('#') }.toList()
    }
}

@Serializable
data class RoutingSettings(
    val enabled: Boolean = false,
    val selectedPreset: String = "lan",
    val presets: List<RoutingPreset> = defaults(),
    val geoipUrl: String = GEOIP_URL,
    val geositeUrl: String = GEOSITE_URL,
) {
    fun active(): RoutingPreset? = if (enabled) presets.firstOrNull { it.id == selectedPreset } else null
    fun replace(preset: RoutingPreset) = copy(presets = presets.map { if (it.id == preset.id) preset else it })

    companion object {
        const val GEOIP_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
        const val GEOSITE_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
        private val json = Json { ignoreUnknownKeys = true }
        fun defaults() = listOf(RoutingPreset("lan", direct = "geoip:private")) +
            listOf("ru", "ir", "cn").map { RoutingPreset(it, direct = "geoip:private\ngeoip:$it") }
        fun encode(value: RoutingSettings): String = json.encodeToString(value)
        fun decode(value: String): RoutingSettings = json.decodeFromString(value)
        fun migrate(lan: Boolean, countries: Set<String>): RoutingSettings {
            val rules = (if (lan) listOf("geoip:private") else emptyList()) +
                listOf("ru", "ir", "cn").filter { it in countries }.map { "geoip:$it" }
            if (rules.isEmpty()) return RoutingSettings()
            val saved = RoutingPreset("migrated", direct = rules.joinToString("\n"))
            return RoutingSettings(enabled = true, selectedPreset = saved.id, presets = defaults() + saved)
        }
        fun validSource(value: String): Boolean = runCatching {
            val uri = URI(value)
            value.length <= 2048 && uri.scheme.equals("https", true) && !uri.host.isNullOrEmpty() &&
                uri.userInfo == null && uri.fragment == null && (uri.port == -1 || uri.port in 1..65535)
        }.getOrDefault(false)
    }
}

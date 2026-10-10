package io.github.feg55.zarp.data

import android.content.Context
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.core.RoutingPreset
import io.github.feg55.zarp.core.RoutingSettings
import io.github.feg55.zarpcore.Zarpcore
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.*

data class GeoFileState(
    val downloading: Boolean = false,
    val bytes: Long = 0,
    val categories: Int = 0,
    val updatedAt: Long = 0,
    val error: String? = null,
)

/** Files are keyed by their source URL. A failed update never replaces the last valid file. */
class GeoDataRepository(context: Context) {
    private val assets = context.applicationContext.assets
    private val directory = File(context.filesDir, "geodata")
    private val downloadLock = Mutex()
    private val fileLock = Mutex()
    private val state = MutableStateFlow<Map<String, GeoFileState>>(emptyMap())
    val files = state.asStateFlow()

    fun key(kind: String, url: String): String {
        require(kind in listOf("geoip", "geosite"))
        val hash = MessageDigest.getInstance("SHA-256").digest(url.toByteArray())
            .take(16).joinToString("") { "%02x".format(it) }
        return "$kind-$hash"
    }

    private fun dataFile(kind: String, url: String) = File(directory, "${key(kind, url)}.dat")
    private fun metadata(kind: String, url: String) = File(directory, "${key(kind, url)}.json")

    suspend fun refresh(settings: RoutingSettings) = withContext(Dispatchers.IO) {
        listOf("geoip" to settings.geoipUrl, "geosite" to settings.geositeUrl).forEach { (kind, url) ->
            val key = key(kind, url)
            if (state.value[key]?.downloading == true) return@forEach
            val file = dataFile(kind, url)
            val saved = runCatching { Json.parseToJsonElement(metadata(kind, url).readText()).jsonObject }.getOrNull()
            val current = GeoFileState(
                bytes = if (file.exists()) file.length() else 0,
                categories = if (file.exists()) saved?.get("categories")?.jsonPrimitive?.intOrNull ?: 0 else 0,
                updatedAt = if (file.exists()) file.lastModified() else 0,
            )
            state.update { latest ->
                if (latest[key]?.downloading == true) latest
                else latest + (key to current.copy(error = latest[key]?.error))
            }
        }
    }

    suspend fun download(kind: String, url: String) = downloadLock.withLock {
        require(RoutingSettings.validSource(url)) { L.t("geo.invalidUrl") }
        withContext(Dispatchers.IO) {
            val key = key(kind, url)
            val previous = state.value[key] ?: GeoFileState()
            var staging: File? = null
            state.update { it + (key to previous.copy(downloading = true, bytes = 0, error = null)) }
            try {
                directory.mkdirs()
                val temporary = File.createTempFile("download-", ".part", directory)
                staging = temporary
                withTimeout(180_000) {
                    fetch(url, temporary) { bytes -> state.update { it + (key to previous.copy(downloading = true, bytes = bytes, error = null)) } }
                    currentCoroutineContext().ensureActive()
                    val categories = Json.parseToJsonElement(Zarpcore.geoDataInfo(kind, temporary.absolutePath)).jsonArray.size
                    currentCoroutineContext().ensureActive()
                    fileLock.withLock {
                        Files.move(temporary.toPath(), dataFile(kind, url).toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                        metadata(kind, url).writeText(buildJsonObject { put("categories", categories) }.toString())
                    }
                    state.update { it + (key to GeoFileState(bytes = dataFile(kind, url).length(), categories = categories, updatedAt = dataFile(kind, url).lastModified())) }
                }
            } catch (e: CancellationException) {
                state.update { it + (key to previous.copy(error = L.t("geo.cancelled"))) }
                throw e
            } catch (_: Exception) {
                // Download URLs can contain secret query parameters; never echo connection exceptions.
                state.update { it + (key to previous.copy(error = L.t("geo.failed"))) }
            } finally { staging?.delete() }
        }
    }

    private suspend fun fetch(source: String, target: File, progress: (Long) -> Unit) {
        var url = source
        repeat(6) {
            require(RoutingSettings.validSource(url))
            val connection = URI(url).toURL().openConnection() as HttpURLConnection
            try {
                connection.connectTimeout = 15_000
                connection.readTimeout = 20_000
                connection.instanceFollowRedirects = false
                connection.setRequestProperty("Accept-Encoding", "identity")
                connection.setRequestProperty("User-Agent", "Zarp-Android")
                val code = connection.responseCode
                if (code in listOf(301, 302, 303, 307, 308)) {
                    url = URI(url).resolve(requireNotNull(connection.getHeaderField("Location"))).toString()
                    return@repeat
                }
                check(code == 200 && connection.contentLengthLong <= MAX_BYTES)
                var bytes = 0L
                var reported = 0L
                connection.inputStream.use { input -> target.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = input.read(buffer)
                        if (count < 0) break
                        bytes += count
                        check(bytes <= MAX_BYTES)
                        output.write(buffer, 0, count)
                        if (bytes - reported >= 256 * 1024) { progress(bytes); reported = bytes }
                    }
                } }
                check(bytes > 0 && (connection.contentLengthLong < 0 || bytes == connection.contentLengthLong))
                return
            } finally { connection.disconnect() }
        }
        error("too many redirects")
    }

    suspend fun validate(preset: RoutingPreset) = withContext(Dispatchers.IO) {
        Zarpcore.validateRouteRules(preset.rulesJson())
    }

    suspend fun compile(settings: RoutingSettings): JsonArray = withContext(Dispatchers.IO) {
        val preset = settings.active() ?: return@withContext JsonArray(emptyList())
        fileLock.withLock {
            val ip = dataFile("geoip", settings.geoipUrl)
            val site = dataFile("geosite", settings.geositeUrl)
            val bundled = if (!ip.exists() && settings.geoipUrl == RoutingSettings.GEOIP_URL) buildJsonObject {
                listOf("ru", "ir", "cn").forEach { country ->
                    put(country, buildJsonArray {
                        assets.open("routes/$country.txt").bufferedReader().useLines { lines ->
                            lines.map(String::trim).filter { it.isNotEmpty() && !it.startsWith('#') }.forEach { add(JsonPrimitive(it)) }
                        }
                    })
                }
            }.toString() else "{}"
            try {
                Json.parseToJsonElement(Zarpcore.compileRouteRules(preset.rulesJson(),
                    if (ip.exists()) ip.absolutePath else "", if (site.exists()) site.absolutePath else "", bundled)).jsonArray
            } catch (e: Exception) { throw IllegalStateException(L.t("geo.rulesUnavailable") + ": " + e.message, e) }
        }
    }

    private companion object { const val MAX_BYTES = 64L * 1024 * 1024 }
}

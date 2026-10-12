package io.github.feg55.zarp.data

import io.github.feg55.zarp.core.*
import io.github.feg55.zarp.net.SubscriptionDownloader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

data class ServerImportState(val loading: Boolean = false, val error: Msg? = null)

/** The URL hash, links and selection are saved in one private DataStore file under filesDir. */
class ServerRepository(
    private val read: suspend () -> AppSettings,
    private val update: suspend ((AppSettings) -> AppSettings) -> Unit,
    private val download: suspend (String) -> SubscriptionResult = SubscriptionDownloader()::load,
    private val log: LogBus,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val mutex = Mutex()
    private val state = MutableStateFlow(ServerImportState())
    val importState = state.asStateFlow()

    suspend fun save(source: String, endpoints: String, useProxy: Boolean): Boolean = mutex.withLock {
        state.value = ServerImportState(loading = true)
        try {
            val value = source.trim()
            if (useProxy) Subscription.explainSource(value)?.let { throw ZarpException(it) }
            if (!useProxy) EndpointParser.parse(endpoints)
            val snapshot = if (useProxy && Subscription.isUrl(value)) fetch(value) else null
            update { previous ->
                previous.copy(
                    proxyUri = value, customEndpoints = endpoints.trim(), useProxy = useProxy,
                    subscription = if (snapshot != null) snapshot else if (previous.proxyUri == value) previous.subscription else null,
                    serverSelectionId = if (previous.proxyUri == value) previous.serverSelectionId else null,
                )
            }
            state.value = ServerImportState()
            true
        } catch (e: CancellationException) {
            state.value = ServerImportState(error = Msg("proxy.subCancelled"))
            throw e
        } catch (e: Exception) {
            val reason = (e as? ZarpException)?.msg ?: Msg("proxy.invalid")
            val previous = read()
            val kept = previous.proxyUri == source.trim() && !previous.subscription?.links.isNullOrEmpty()
            state.value = ServerImportState(error = if (kept) Msg("proxy.subKept", reason.toString()) else reason)
            if (kept) log.write(L.t("proxy.subKept", reason.toString()))
            false
        }
    }

    private suspend fun fetch(source: String): SubscriptionSnapshot {
        val result = download(source).requireServers()
        log.write(L.t("proxy.subLoaded", result.links.size, result.unsupported, result.refused, result.truncated))
        return SubscriptionSnapshot(Subscription.sourceId(source), result.links, clock(), result.unsupported, result.refused, result.truncated)
    }

    suspend fun ensure(settings: AppSettings): AppSettings = mutex.withLock {
        if (!settings.useProxy || !Subscription.isUrl(settings.proxyUri)) return@withLock settings
        val saved = settings.subscription?.takeIf { it.source == Subscription.sourceId(settings.proxyUri) }
        if (saved?.fresh(clock()) == true) return@withLock settings
        try {
            val next = fetch(settings.proxyUri)
            // A refresh cannot overwrite a source the user has since replaced or deleted.
            update { current -> if (current.proxyUri == settings.proxyUri) current.copy(subscription = next) else current }
            read()
        } catch (e: CancellationException) { throw e }
        catch (e: Exception) {
            if (saved?.links.isNullOrEmpty()) throw e
            log.write(L.t("proxy.subCached", ((e as? ZarpException)?.msg ?: Msg("proxy.subNetwork")).toString()))
            settings
        }
    }

    suspend fun delete() = mutex.withLock {
        update { it.copy(proxyUri = "", subscription = null, serverSelectionId = null, useProxy = false) }
        state.value = ServerImportState()
    }
}

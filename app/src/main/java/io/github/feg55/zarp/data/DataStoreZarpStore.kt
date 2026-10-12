package io.github.feg55.zarp.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import io.github.feg55.zarp.core.AppSettings
import io.github.feg55.zarp.core.RoutingSettings
import io.github.feg55.zarp.core.TestResult
import io.github.feg55.zarp.core.ZarpStore
import io.github.feg55.zarp.core.SubscriptionSnapshot
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

private val Context.zarpDataStore: DataStore<Preferences> by preferencesDataStore(name = "zarp")

/**
 * DataStore persistence: selected strategy, test results (ok/confirmed, connect time,
 * ping, score inputs, timestamp) and settings.
 */
class DataStoreZarpStore(context: Context) : ZarpStore {
    private val ds = context.applicationContext.zarpDataStore

    private object Keys {
        val selected = stringPreferencesKey("selected_strategy")
        val results = stringPreferencesKey("results_json")
        val timeout = intPreferencesKey("test_timeout_sec")
        val stopAfter = intPreferencesKey("stop_after_working")
        val isolate = booleanPreferencesKey("isolate_tests")
        val ipv6 = booleanPreferencesKey("tunnel_ipv6")
        val dns = stringPreferencesKey("dns")
        val autoConnect = booleanPreferencesKey("auto_connect")
        val custom = stringPreferencesKey("custom_strategies")
        val tos = booleanPreferencesKey("tos_accepted")
        val perApp = booleanPreferencesKey("per_app_proxy")
        val apps = stringSetPreferencesKey("proxy_apps")
        val lan = booleanPreferencesKey("bypass_lan")
        val countries = stringSetPreferencesKey("bypass_countries")
        val endpoints = stringPreferencesKey("custom_endpoints")
        val country = stringPreferencesKey("strategy_country")
        val useProxy = booleanPreferencesKey("use_proxy")
        val proxyUri = stringPreferencesKey("proxy_uri")
        val routing = stringPreferencesKey("routing_json")
        val schema = intPreferencesKey("server_schema")
        val subscription = stringPreferencesKey("subscription_json")
        val server = stringPreferencesKey("selected_server")
        val plain = booleanPreferencesKey("allow_plain_server")
    }

    val settingsFlow: Flow<AppSettings> = ds.data.map(::readSettings).distinctUntilChanged().flowOn(Dispatchers.Default)

    private fun readSettings(p: Preferences): AppSettings {
        val d = AppSettings()
        return AppSettings(
            testTimeoutSec = (p[Keys.timeout] ?: d.testTimeoutSec).coerceIn(5, 120),
            stopAfterWorking = (p[Keys.stopAfter] ?: d.stopAfterWorking).coerceIn(1, 20),
            isolateTests = p[Keys.isolate] ?: d.isolateTests,
            tunnelIpv6 = p[Keys.ipv6] ?: d.tunnelIpv6,
            dns = p[Keys.dns] ?: d.dns,
            autoConnect = p[Keys.autoConnect] ?: d.autoConnect,
            customStrategies = p[Keys.custom] ?: d.customStrategies,
            tosAccepted = p[Keys.tos] ?: d.tosAccepted,
            perAppProxy = p[Keys.perApp] ?: false,
            proxyApps = p[Keys.apps] ?: emptySet(),
            bypassLan = p[Keys.lan] ?: false,
            bypassCountries = p[Keys.countries] ?: emptySet(),
            customEndpoints = p[Keys.endpoints].orEmpty(),
            strategyCountry = p[Keys.country] ?: "all",
            useProxy = p[Keys.useProxy] ?: false,
            proxyUri = p[Keys.proxyUri].orEmpty(),
            subscription = p[Keys.subscription]?.let(SubscriptionSnapshot::decode),
            serverSelectionId = p[Keys.server],
            allowPlainServer = p[Keys.plain] ?: false,
            routing = p[Keys.routing]?.let { RoutingSettings.decode(it) }
                ?: RoutingSettings.migrate(p[Keys.lan] ?: false, p[Keys.countries] ?: emptySet()),
        )
    }

    override suspend fun settings(): AppSettings {
        if (ds.data.first()[Keys.schema] != 2) ds.edit { p ->
            if (p[Keys.schema] != 2) {
                val migrated = migrateLegacyResults(p[Keys.results].orEmpty())
                p[Keys.results] = encodeResults(migrated)
                if (p[Keys.selected]?.startsWith("proxy-") == true) p.remove(Keys.selected)
                p[Keys.schema] = 2
            }
        }
        return settingsFlow.first()
    }

    suspend fun updateSettings(transform: (AppSettings) -> AppSettings): Boolean {
        var resultsReset = false
        ds.edit { p ->
            // Transform inside the transaction: fast consecutive app toggles must not overwrite each other.
            val previous = readSettings(p)
            val s = transform(previous)
            p[Keys.timeout] = s.testTimeoutSec.coerceIn(5, 120)
            p[Keys.stopAfter] = s.stopAfterWorking.coerceIn(1, 20)
            p[Keys.isolate] = s.isolateTests
            p[Keys.ipv6] = s.tunnelIpv6
            p[Keys.dns] = s.dns
            p[Keys.autoConnect] = s.autoConnect
            p[Keys.custom] = s.customStrategies
            p[Keys.tos] = s.tosAccepted
            p[Keys.perApp] = s.perAppProxy
            p[Keys.apps] = s.proxyApps
            p[Keys.lan] = s.bypassLan
            p[Keys.countries] = s.bypassCountries
            p[Keys.endpoints] = s.customEndpoints
            p[Keys.country] = s.strategyCountry
            p[Keys.useProxy] = s.useProxy
            p[Keys.proxyUri] = s.proxyUri
            if (s.subscription == null) p.remove(Keys.subscription)
            else p[Keys.subscription] = SubscriptionSnapshot.encode(s.subscription)
            if (s.serverSelectionId == null) p.remove(Keys.server) else p[Keys.server] = s.serverSelectionId
            p[Keys.plain] = s.allowPlainServer
            p[Keys.routing] = RoutingSettings.encode(s.routing)
            if (previous.customEndpoints != s.customEndpoints || previous.proxyUri != s.proxyUri || previous.useProxy != s.useProxy) {
                resultsReset = true
                p.remove(Keys.results)
                p.remove(Keys.selected)
            }
            p[Keys.schema] = 2
        }
        return resultsReset
    }

    override suspend fun results(): Map<String, TestResult> =
        ds.data.first()[Keys.results]?.let { decodeResults(it) } ?: emptyMap()

    override suspend fun saveResults(results: Map<String, TestResult>) {
        ds.edit { it[Keys.results] = encodeResults(results) }
    }

    override suspend fun selectedStrategyId(): String? = ds.data.first()[Keys.selected]

    override suspend fun setSelectedStrategyId(id: String?) {
        ds.edit { if (id == null) it.remove(Keys.selected) else it[Keys.selected] = id }
    }

    suspend fun clearResults() {
        ds.edit {
            it.remove(Keys.results)
            it.remove(Keys.selected)
        }
    }

    companion object {
        private val json = Json { ignoreUnknownKeys = true }
        private val serializer = MapSerializer(String.serializer(), TestResult.serializer())

        fun encodeResults(results: Map<String, TestResult>): String = json.encodeToString(serializer, results)

        /** Broken or old data must not break startup: it is dropped, as in Zarp's AppConfig.Load. */
        fun decodeResults(text: String): Map<String, TestResult> =
            runCatching { json.decodeFromString(serializer, text) }.getOrDefault(emptyMap())

        /** Old plain-server results cannot certify a strategy and server pair. */
        fun migrateLegacyResults(text: String): Map<String, TestResult> =
            decodeResults(text).filterKeys { !it.startsWith("proxy-") }
    }
}

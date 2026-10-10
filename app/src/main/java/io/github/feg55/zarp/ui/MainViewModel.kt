package io.github.feg55.zarp.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.feg55.zarp.ZarpApp
import io.github.feg55.zarp.core.AppSettings
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.core.Strategy
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.map
import io.github.feg55.zarp.core.StrategyCatalog
import io.github.feg55.zarp.core.StrategyFilter
import io.github.feg55.zarp.core.RoutingPreset
import io.github.feg55.zarp.core.RoutingSettings
import kotlinx.coroutines.launch

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val zarp = app as ZarpApp
    val engine = zarp.engine
    val log = zarp.log

    val status = engine.status
    val results = engine.results
    val selectedId = engine.selectedId
    val lines = log.lines
    val settings: StateFlow<AppSettings?> =
        zarp.store.settingsFlow.stateIn(viewModelScope, SharingStarted.Eagerly, null)

    val strategies = zarp.store.settingsFlow.map { s ->
        StrategyFilter.apply(StrategyCatalog.forSettings(s), s.strategyCountry)
    }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val accountRegistered: Boolean get() = zarp.account.registered
    val geoFiles = zarp.geoData.files
    fun geoKey(kind: String, url: String) = zarp.geoData.key(kind, url)
    fun refreshGeo(settings: RoutingSettings) { viewModelScope.launch { zarp.geoData.refresh(settings) } }
    fun downloadGeo(kind: String, url: String) {
        if (!RoutingSettings.validSource(url)) return
        // The app scope keeps an explicit download alive across screen/activity recreation.
        zarp.appScope.launch {
            zarp.store.updateSettings { s -> s.copy(routing = if (kind == "geoip") s.routing.copy(geoipUrl = url) else s.routing.copy(geositeUrl = url)) }
            zarp.geoData.download(kind, url)
        }
    }
    suspend fun validateRules(preset: RoutingPreset) = zarp.geoData.validate(preset)

    fun connect() = engine.connect()
    fun disconnect() = engine.disconnect()
    fun cancel() = engine.cancel()
    fun quickScan() = engine.search(full = false)
    fun fullScan() = engine.search(full = true)
    fun use(s: Strategy) = engine.useStrategy(s)
    fun test(list: List<Strategy>) = engine.testStrategies(list)

    fun updateSettings(transform: (AppSettings) -> AppSettings) {
        viewModelScope.launch {
            if (zarp.store.updateSettings(transform)) engine.refreshSavedState()
        }
    }

    fun clearResults() {
        viewModelScope.launch {
            zarp.store.clearResults()
            engine.refreshSavedState()
        }
    }

    /** null follows the system language. */
    fun setLanguage(code: String?) = zarp.setLanguage(code)

    fun resetAccount() {
        zarp.account.reset()
        log.write(L.t("log.accountReset"))
    }
}

package io.github.feg55.zarp

import android.app.Application
import android.content.Context
import android.content.res.Configuration
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import androidx.core.content.edit
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.core.LogBus
import io.github.feg55.zarp.core.NetworkInspector
import io.github.feg55.zarp.core.ZarpEngine
import io.github.feg55.zarp.data.DataStoreZarpStore
import io.github.feg55.zarp.data.GeoDataRepository
import io.github.feg55.zarp.masque.MasqueAccount
import io.github.feg55.zarp.masque.MasqueTunnelFactory
import io.github.feg55.zarp.masque.ProxyTunnelFactory
import io.github.feg55.zarp.net.TraceClient
import io.github.feg55.zarp.strategy.BlobStore
import io.github.feg55.zarp.vpn.VpnServiceController
import io.github.feg55.zarpcore.Zarpcore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File

class ZarpApp : Application() {
    companion object {
        private const val KEY_LANGUAGE = "language"
    }

    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    val log = LogBus { Log.i("Zarp", it) }
    lateinit var store: DataStoreZarpStore
        private set
    lateinit var account: MasqueAccount
        private set
    lateinit var engine: ZarpEngine
        private set
    lateinit var geoData: GeoDataRepository
        private set

    private val uiPrefs by lazy { getSharedPreferences("ui", MODE_PRIVATE) }

    /** Globe button: null follows the system language. */
    fun setLanguage(code: String?) {
        L.setLanguage(code)
        uiPrefs.edit { if (code == null) remove(KEY_LANGUAGE) else putString(KEY_LANGUAGE, code) }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        L.onSystemLocaleChanged(newConfig.locales[0])
    }

    override fun onCreate() {
        super.onCreate()
        L.init(open = { assets.open(it) }, setting = uiPrefs.getString(KEY_LANGUAGE, null))
        store = DataStoreZarpStore(this)
        geoData = GeoDataRepository(this)
        Zarpcore.setLogger { line -> log.write("core: $line") }

        val settings = suspend { store.settings() }
        val warpConfig = File(filesDir, "warp-masque.json")
        account = MasqueAccount(warpConfig, settings, log)
        val vpn = VpnServiceController(this, settings)
        engine = ZarpEngine(
            scope = appScope,
            store = store,
            tunnels = ProxyTunnelFactory(
                MasqueTunnelFactory(warpConfig.absolutePath, BlobStore { assets.open(it) }, settings, vpn, log),
                settings,
                routingRules = geoData::compile,
            ),
            probe = TraceClient(),
            vpn = vpn,
            account = account,
            network = AndroidNetworkInspector(this),
            log = log,
        )
        log.write(L.t("log.started", BuildConfig.VERSION_NAME))
        appScope.launch { engine.load() }
    }
}

/** Port of Zarp's NetCheck: is another VPN carrying the default network? */
class AndroidNetworkInspector(context: Context) : NetworkInspector {
    private val cm = context.getSystemService(ConnectivityManager::class.java)

    override fun foreignVpnActive(): Boolean {
        val caps = cm.getNetworkCapabilities(cm.activeNetwork ?: return false) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }
}

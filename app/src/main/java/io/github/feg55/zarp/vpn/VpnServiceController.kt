package io.github.feg55.zarp.vpn

import android.content.Context
import android.net.VpnService
import androidx.core.content.ContextCompat
import io.github.feg55.zarp.core.AppSettings
import io.github.feg55.zarp.core.VpnController
import io.github.feg55.zarp.core.VpnStartException
import io.github.feg55.zarp.masque.SocketProtector
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

/** Starts/stops [ZarpVpnService] and waits until it really runs. */
class VpnServiceController(
    private val context: Context,
    private val settings: suspend () -> AppSettings,
) : VpnController, SocketProtector {

    override suspend fun start(socksPort: Int, sessionName: String) {
        if (VpnService.prepare(context) != null) throw VpnStartException("VPN permission is not granted")
        val s = settings()
        val done = CompletableDeferred<Result<Unit>>()
        ZarpVpnService.pendingStart = done
        val intent = ZarpVpnService.intent(context, ZarpVpnService.ACTION_START)
            .putExtra(ZarpVpnService.EXTRA_SOCKS_PORT, socksPort)
            .putExtra(ZarpVpnService.EXTRA_SESSION, sessionName)
            .putExtra(ZarpVpnService.EXTRA_DNS, s.dns)
            .putExtra(ZarpVpnService.EXTRA_IPV6, s.tunnelIpv6)
            .putExtra(ZarpVpnService.EXTRA_PER_APP, s.perAppProxy)
            .putStringArrayListExtra(ZarpVpnService.EXTRA_APPS, ArrayList(s.proxyApps))
            // Routing now runs in the proxy engine, where block/proxy rules can override LAN.
            .putExtra(ZarpVpnService.EXTRA_BYPASS_LAN, false)
        ContextCompat.startForegroundService(context, intent)
        val result = withTimeoutOrNull(START_TIMEOUT_MS) { done.await() }
            ?: throw VpnStartException("VPN service did not start in time")
        result.getOrElse { throw VpnStartException("VPN did not start: ${it.message}", it) }
    }

    override suspend fun stop() {
        if (ZarpVpnService.instance == null) return
        context.startService(ZarpVpnService.intent(context, ZarpVpnService.ACTION_STOP))
        withTimeoutOrNull(STOP_TIMEOUT_MS) {
            while (ZarpVpnService.instance != null) delay(50)
        }
    }

    /** Sockets of the core stay outside the VPN (Zarp is also a disallowed app, this is a second guard). */
    override fun protect(fd: Int): Boolean = ZarpVpnService.instance?.protect(fd) ?: true

    private companion object {
        const val START_TIMEOUT_MS = 10_000L
        const val STOP_TIMEOUT_MS = 5_000L
    }
}

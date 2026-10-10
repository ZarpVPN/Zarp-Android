package io.github.feg55.zarp.core

/** A running MASQUE tunnel exposed as a local SOCKS5 proxy. */
interface TunnelHandle {
    val connectMs: Int
    val socksPort: Int
    val endpoint: String
    fun close()
}

class TunnelException(message: String, val timeout: Boolean = false) : Exception(message)

/** Opens MASQUE tunnels with a strategy applied to their handshake. */
interface TunnelFactory {
    /**
     * Connects (blocking up to [timeoutMs]) and returns the tunnel, or throws
     * [TunnelException]. [endpoint] null = account's default endpoint.
     * [persistent] tunnels reconnect by themselves (VPN mode) and report through [onStatus].
     */
    suspend fun open(
        strategy: Strategy,
        endpoint: String?,
        timeoutMs: Int,
        persistent: Boolean,
        onStatus: (connected: Boolean, message: String) -> Unit = { _, _ -> },
    ): TunnelHandle
}

/** The Android VPN (TUN + hev-socks5-tunnel) in front of the SOCKS5 proxy. */
interface VpnController {
    suspend fun start(socksPort: Int, sessionName: String)
    suspend fun stop()
}

/** WARP device registration. */
interface WarpAccount {
    val registered: Boolean

    /** Registers a device if needed. Throws with a readable message on failure. */
    suspend fun ensureRegistered()
}

/** Other VPNs would carry WARP traffic themselves and make results meaningless. */
fun interface NetworkInspector {
    fun foreignVpnActive(): Boolean
}

/** Persistent state (DataStore in the app, in-memory in tests). */
interface ZarpStore {
    suspend fun settings(): AppSettings
    suspend fun results(): Map<String, TestResult>
    suspend fun saveResults(results: Map<String, TestResult>)
    suspend fun selectedStrategyId(): String?
    suspend fun setSelectedStrategyId(id: String?)
}

data class AppSettings(
    /** Seconds to wait for WARP to connect with one strategy (Zarp: TestTimeoutSec). */
    val testTimeoutSec: Int = 15,
    /** Quick scan stops after this many working strategies (Zarp: StopAfterWorking). */
    val stopAfterWorking: Int = 3,
    /** Every test on a new WARP endpoint (Zarp: IsolateTests). */
    val isolateTests: Boolean = true,
    val tunnelIpv6: Boolean = true,
    val dns: String = "1.1.1.1,1.0.0.1",
    val autoConnect: Boolean = false,
    val customStrategies: String = StrategyCatalog.CUSTOM_TEMPLATE,
    val tosAccepted: Boolean = false,
    val perAppProxy: Boolean = false,
    val proxyApps: Set<String> = emptySet(),
    val bypassLan: Boolean = false,
    val bypassCountries: Set<String> = emptySet(),
    val customEndpoints: String = "",
    val strategyCountry: String = "all",
    val useProxy: Boolean = false,
    val proxyUri: String = "",
    val routing: RoutingSettings = RoutingSettings(),
)

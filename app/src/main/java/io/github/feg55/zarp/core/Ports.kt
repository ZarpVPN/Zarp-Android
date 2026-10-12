package io.github.feg55.zarp.core

/** A running MASQUE tunnel exposed as a local SOCKS5 proxy. */
interface TunnelHandle {
    val connectMs: Int
    val socksPort: Int
    val endpoint: String
    fun failure(): Msg? = null
    fun strategyApplied(): Boolean = true
    fun metrics(): TunnelMetrics? = null
    fun close()
}

/** Counts only; no destination, credential or payload is exposed. */
data class TunnelMetrics(val connections: Long, val splits: Long, val fakeFlows: Long, val fakePackets: Long, val foreignConnections: Long)

class TunnelException(message: String, val timeout: Boolean = false) : Exception(message)

/** Opens MASQUE tunnels with a strategy applied to their handshake. */
interface TunnelFactory {
    /** Reset per-operation resolution, including failed lookups. */
    fun beginOperation(settings: AppSettings) = Unit
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

interface StrategyCapabilities {
    val udpTtl: Boolean
    val tcpTtl: Boolean
}

data class CapabilitySnapshot(override val udpTtl: Boolean = true, override val tcpTtl: Boolean = true) : StrategyCapabilities

/** Foreground lifetime of a scan, independent of the actual VPN adapter. */
interface OperationLifetime {
    suspend fun start()
    suspend fun stop()
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
    val subscription: SubscriptionSnapshot? = null,
    /** null means all servers; keep an unavailable id until the user changes it. */
    val serverSelectionId: String? = null,
    val allowPlainServer: Boolean = false,
    val routing: RoutingSettings = RoutingSettings(),
)

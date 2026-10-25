package io.github.feg55.zarp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import io.github.feg55.zarpcore.Zarpcore
import io.github.feg55.zarpcore.AccountProtector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File

/**
 * Debug-only: runs engine commands sent with adb (see src/debug/AndroidManifest.xml).
 * Only the shell (DUMP permission) can send them. VPN permission must already be granted.
 */
class DebugCommandReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val app = context.applicationContext as ZarpApp
        val engine = app.engine
        val parts = intent.getStringExtra("cmd").orEmpty().trim().split(" ", limit = 2)
        val arg = parts.getOrNull(1).orEmpty()
        fun pick() = engine.strategies.value.filter { it.id in arg.split(",") }
        val ok = when (parts[0]) {
            "registration-verify" -> DebugWarpRegistrationVerifier.start(app)
            "registration-stop" -> DebugWarpRegistrationVerifier.stop()
            "account-direct", "account-protected" -> {
                val protected = parts[0] == "account-protected"
                app.appScope.launch(Dispatchers.IO) {
                    val operation = Zarpcore.newAccountOperation(File(app.filesDir, "warp-masque.json").absolutePath,
                        if (protected) "split:1,midsld" else "", 25_000, AccountProtector { fd -> io.github.feg55.zarp.vpn.ZarpVpnService.instance?.protect(fd.toInt()) ?: true })
                    try {
                        val type = operation.readAccount()
                        app.log.write("debug account ${if (protected) "protected" else "direct"}: " + io.github.feg55.zarp.core.WarpAccountType.parse(type).key)
                    } catch (e: Exception) {
                        val code = e.message.orEmpty().substringAfterLast("account:")
                            .takeIf { it in setOf("network", "timeout", "rateLimit", "rejected", "missing", "config", "response", "api", "protect") } ?: "other"
                        app.log.write("debug account ${if (protected) "protected" else "direct"}: $code")
                    }
                    finally { operation.close() }
                }
                true
            }
            "verify-start" -> DebugServerVerifier.start(app)
            "verify-stats" -> DebugServerVerifier.snapshot(app)
            "verify-stop" -> DebugServerVerifier.stop(app)
            "quick" -> engine.search(full = false)
            "full" -> engine.search(full = true)
            "connect" -> engine.connect()
            "disconnect" -> engine.disconnect()
            "cancel" -> { engine.cancel(); true }
            "test" -> pick().takeIf { it.isNotEmpty() }?.let { engine.testStrategies(it) } ?: false
            "use" -> pick().firstOrNull()?.let { engine.useStrategy(it) } ?: false
            else -> false
        }
        app.log.write("debug command: ${if (ok) "started" else "rejected"}")
    }
}

package io.github.feg55.zarp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

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

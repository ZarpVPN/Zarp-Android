package io.github.feg55.zarp.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.content.ContextCompat
import io.github.feg55.zarp.MainActivity
import io.github.feg55.zarp.R
import io.github.feg55.zarp.ZarpApp
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.core.OperationLifetime
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

/** Keeps user-requested VPN connectivity checks alive before the TUN exists. */
class ScanKeepAliveService : Service() {
    private var finishing = false
    private var foreground = false
    private val destroyed = CompletableDeferred<Unit>()
    override fun onCreate() { super.onCreate(); instance = this; finishing = explicitStop }
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, L.t("notif.channel"), NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 10, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val cancel = PendingIntent.getService(this, 11, Intent(this, ScanKeepAliveService::class.java).setAction(CANCEL), PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_stat_zarp)
            .setContentTitle(L.t("notif.scanTitle")).setContentText(L.t("notif.scanText"))
            .setContentIntent(open).setOngoing(true)
            .addAction(Notification.Action.Builder(null, L.t("btn.cancel"), cancel).build()).build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(2, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(2, notification)
        foreground = true
        pendingStart?.complete(Unit)
        // Even an already cancelled start must acknowledge startForegroundService before stopping.
        if (explicitStop || intent?.action == CANCEL) {
            if (intent?.action == CANCEL) (application as ZarpApp).engine.cancel()
            finish()
        } else finishing = false
        return START_NOT_STICKY
    }
    override fun onDestroy() {
        if (instance === this) instance = null
        if (!foreground) pendingStart?.completeExceptionally(IllegalStateException("Connectivity check service stopped before starting"))
        if (!finishing && !explicitStop) (application as ZarpApp).engine.cancel()
        destroyed.complete(Unit)
        super.onDestroy()
    }
    override fun onTaskRemoved(rootIntent: Intent?) {
        (application as ZarpApp).engine.onUiClosed()
        finish()
        super.onTaskRemoved(rootIntent)
    }
    fun finish() {
        finishing = true
        if (!foreground) return // onStartCommand still owes Android its foreground acknowledgement
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    companion object {
        @Volatile private var instance: ScanKeepAliveService? = null
        @Volatile private var explicitStop = false
        @Volatile private var pendingStart: CompletableDeferred<Unit>? = null
        suspend fun start(context: Context) {
            explicitStop = false
            val ready = CompletableDeferred<Unit>()
            pendingStart = ready
            try {
                ContextCompat.startForegroundService(context, Intent(context, ScanKeepAliveService::class.java))
                withTimeout(5_000) { ready.await() }
            } finally {
                if (pendingStart === ready) pendingStart = null
            }
        }
        suspend fun stop() {
            explicitStop = true
            // A queued start must reach onStartCommand; stopService here can crash Android 8–10.
            val current = instance ?: return
            current.finish()
            withTimeoutOrNull(5_000) { current.destroyed.await() }
        }
        private const val CHANNEL = "zarp_checks"
        private const val CANCEL = "io.github.feg55.zarp.CANCEL_CHECKS"
    }
}

class AndroidOperationLifetime(private val context: Context) : OperationLifetime {
    override suspend fun start() {
        // Keep the operation lock until Android acknowledges the foreground start, even on cancellation.
        withContext(NonCancellable) { ScanKeepAliveService.start(context) }
    }
    override suspend fun stop() {
        // An explicit stop is different from the system destroying an ongoing scan.
        ScanKeepAliveService.stop()
    }
}

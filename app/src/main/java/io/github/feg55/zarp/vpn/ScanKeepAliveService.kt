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

/** Keeps user-requested VPN connectivity checks alive before the TUN exists. */
class ScanKeepAliveService : Service() {
    private var finishing = false
    override fun onCreate() { super.onCreate(); instance = this; finishing = explicitStop }
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (explicitStop) { finish(); return START_NOT_STICKY }
        if (intent?.action == CANCEL) {
            (application as ZarpApp).engine.cancel()
            return START_NOT_STICKY
        }
        finishing = false
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
        return START_NOT_STICKY
    }
    override fun onDestroy() {
        if (instance === this) instance = null
        if (!finishing && !explicitStop) (application as ZarpApp).engine.cancel()
        super.onDestroy()
    }
    fun finish() { finishing = true; stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() }

    companion object {
        @Volatile private var instance: ScanKeepAliveService? = null
        @Volatile private var explicitStop = false
        fun start(context: Context) {
            explicitStop = false
            ContextCompat.startForegroundService(context, Intent(context, ScanKeepAliveService::class.java))
        }
        fun stop(context: Context) {
            explicitStop = true
            instance?.finish() ?: context.stopService(Intent(context, ScanKeepAliveService::class.java))
        }
        private const val CHANNEL = "zarp_checks"
        private const val CANCEL = "io.github.feg55.zarp.CANCEL_CHECKS"
    }
}

class AndroidOperationLifetime(private val context: Context) : OperationLifetime {
    override suspend fun start() {
        ScanKeepAliveService.start(context)
    }
    override suspend fun stop() {
        // An explicit stop is different from the system destroying an ongoing scan.
        ScanKeepAliveService.stop(context)
    }
}

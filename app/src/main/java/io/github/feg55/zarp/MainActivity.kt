package io.github.feg55.zarp

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.ui.MainViewModel
import io.github.feg55.zarp.ui.ZarpRoot
import io.github.feg55.zarp.ui.ZarpTheme

class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()
    private var afterVpnPermission: (() -> Unit)? = null

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        val action = afterVpnPermission
        afterVpnPermission = null
        if (VpnService.prepare(this) == null) {
            action?.invoke()
        } else {
            vm.log.write(L.t("log.vpnPermission"))
        }
    }

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ZarpTheme {
                ZarpRoot(vm = vm, withVpnPermission = ::withVpnPermission)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    /** Scans end with connecting, so every engine action needs the VPN permission first. */
    private fun withVpnPermission(action: () -> Unit) {
        val intent = VpnService.prepare(this)
        if (intent == null) {
            action()
        } else {
            afterVpnPermission = action
            vpnPermission.launch(intent)
        }
    }

    override fun onDestroy() {
        if (isFinishing) (application as ZarpApp).engine.onUiClosed()
        super.onDestroy()
    }
}

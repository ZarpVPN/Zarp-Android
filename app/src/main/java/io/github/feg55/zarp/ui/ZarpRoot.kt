package io.github.feg55.zarp.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.List
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.core.EngineState
import io.github.feg55.zarp.core.L

private enum class Tab(val key: String, val icon: ImageVector) {
    Home("tab.home", Icons.Outlined.Home),
    Strategies("tab.strategies", Icons.AutoMirrored.Outlined.List),
    Logs("tab.log", Icons.Outlined.Terminal),
    Settings("tab.settings", Icons.Outlined.Settings),
}

/**
 * Root of the UI. [withVpnPermission] runs an engine action after the VPN
 * permission is granted; actions also wait for the WARP Terms of Service consent.
 */
@Composable
fun ZarpRoot(vm: MainViewModel, withVpnPermission: (() -> Unit) -> Unit) {
    // the whole tree is rebuilt in the new language when it changes
    val language by L.current.collectAsStateWithLifecycle()
    var tab by rememberSaveable { mutableStateOf(Tab.Home) }
    val settings by vm.settings.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    var pendingTos by remember { mutableStateOf<(() -> Unit)?>(null) }
    var otherVpn by remember { mutableStateOf(false) }
    var pendingOtherVpn by remember { mutableStateOf<(() -> Unit)?>(null) }

    // engine action -> ToS consent (registration) -> VPN permission -> action
    val guarded: (() -> Unit) -> Unit = { action ->
        val run = { withVpnPermission(action) }
        val consent = {
            if (settings?.useProxy == true || settings?.tosAccepted == true || vm.accountRegistered) run() else pendingTos = run
        }
        if (vm.foreignVpnActive()) {
            if (settings?.useProxy == true) otherVpn = true else pendingOtherVpn = consent
        } else consent()
    }

    // auto-connect once per process start, only when nothing needs the user's answer
    var autoTried by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(settings?.autoConnect) {
        val s = settings ?: return@LaunchedEffect
        if (!autoTried && s.autoConnect && status.state == EngineState.Idle && (s.useProxy || s.tosAccepted || vm.accountRegistered)) {
            autoTried = true
            if (!vm.foreignVpnActive()) withVpnPermission { vm.connect() }
        }
    }

    key(language) {
        if (otherVpn) AlertDialog(
            onDismissRequest = { otherVpn = false },
            title = { Text(L.t("server.otherVpnTitle")) },
            text = { Text(L.t("server.otherVpn")) },
            confirmButton = { TextButton(onClick = { otherVpn = false }) { Text(L.t("btn.back")) } },
        )
        pendingOtherVpn?.let { next ->
            AlertDialog(
                onDismissRequest = { pendingOtherVpn = null },
                title = { Text(L.t("server.otherVpnTitle")) },
                text = { Text(L.t("warp.otherVpn")) },
                confirmButton = {
                    TextButton(onClick = { pendingOtherVpn = null; next() }) { Text(L.t("btn.continue")) }
                },
                dismissButton = {
                    TextButton(onClick = { pendingOtherVpn = null }) { Text(L.t("btn.cancel")) }
                },
            )
        }
        pendingTos?.let { next ->
            AlertDialog(
                onDismissRequest = { pendingTos = null },
                containerColor = Zc.Panel,
                titleContentColor = Zc.Text,
                textContentColor = Zc.Text,
                title = { Text(L.t("tos.title")) },
                text = { Text(L.t("tos.text"), fontSize = 15.sp) },
                confirmButton = {
                    TextButton(onClick = {
                        vm.updateSettings { it.copy(tosAccepted = true) }
                        pendingTos = null
                        next()
                    }) { Text(L.t("tos.accept"), color = Zc.Accent) }
                },
                dismissButton = {
                    TextButton(onClick = { pendingTos = null }) { Text(L.t("btn.cancel"), color = Zc.TextDim) }
                },
            )
        }

        Scaffold(
            containerColor = Zc.Back,
            bottomBar = {
                NavigationBar(containerColor = Zc.Back) {
                    Tab.entries.forEach { t ->
                        NavigationBarItem(
                            selected = tab == t,
                            onClick = { tab = t },
                            icon = { Icon(t.icon, contentDescription = null) },
                            label = { Text(L.t(t.key)) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = Zc.Accent,
                                selectedTextColor = Zc.Accent,
                                indicatorColor = Zc.Accent.copy(alpha = 0.16f),
                                unselectedIconColor = Zc.TextDim,
                                unselectedTextColor = Zc.TextDim,
                            ),
                        )
                    }
                }
            },
        ) { padding ->
            val m = Modifier.padding(padding)
            when (tab) {
                Tab.Home -> HomeScreen(vm, guarded, m)
                Tab.Strategies -> StrategiesScreen(vm, guarded, m)
                Tab.Logs -> LogsScreen(vm, m)
                Tab.Settings -> SettingsScreen(vm, m)
            }
        }
    }
}

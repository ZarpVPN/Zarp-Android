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
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.core.EngineState
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.core.Msg
import io.github.feg55.zarp.core.WarpAccountException
import io.github.feg55.zarp.core.ZarpException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

private enum class Tab(val key: String, val icon: ImageVector) {
    Home("tab.home", Icons.Outlined.Home),
    Strategies("tab.strategies", Icons.AutoMirrored.Outlined.List),
    Logs("tab.log", Icons.Outlined.Terminal),
    Settings("tab.settings", Icons.Outlined.Settings),
}

/**
 * First-time WARP registration runs before requesting permission for Zarp's VPN.
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
    var registeredViaVpn by rememberSaveable { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun connectWithPermission(action: () -> Unit) {
        val run = { withVpnPermission(action) }
        if (vm.foreignVpnActive()) {
            if (settings?.useProxy == true) otherVpn = true else pendingOtherVpn = run
        } else run()
    }

    fun register(viaVpn: Boolean, action: (() -> Unit)? = null) {
        scope.launch {
            try {
                vm.engine.registerWarp(viaVpn)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                vm.registrationFailure = e as? ZarpException ?: ZarpException(Msg("detail.registerFailed"))
                return@launch
            }
            if (viaVpn) registeredViaVpn = true
            else action?.let(::connectWithPermission)
        }
    }

    fun withWarpConsent(next: () -> Unit) {
        if (settings?.tosAccepted == true || vm.accountRegistered) next() else pendingTos = next
    }

    val guarded: (() -> Unit) -> Unit = { action ->
        if (settings?.useProxy == true || vm.accountRegistered) connectWithPermission(action)
        else withWarpConsent { register(vm.foreignVpnActive(), action) }
    }

    // auto-connect once per process start, only when nothing needs the user's answer
    var autoTried by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(settings?.autoConnect) {
        val s = settings ?: return@LaunchedEffect
        if (!autoTried && s.autoConnect && status.state == EngineState.Idle && (s.useProxy || s.tosAccepted || vm.accountRegistered)) {
            autoTried = true
            if (!vm.foreignVpnActive()) guarded { vm.connect() }
        }
    }

    CompositionLocalProvider(LocalLayoutDirection provides if (L.isRtl(language)) LayoutDirection.Rtl else LayoutDirection.Ltr) {
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
                        pendingTos = null
                        scope.launch { vm.acceptWarpTos(); next() }
                    }) { Text(L.t("tos.accept"), color = Zc.Accent) }
                },
                dismissButton = {
                    TextButton(onClick = { pendingTos = null }) { Text(L.t("btn.cancel"), color = Zc.TextDim) }
                },
            )
        }
        vm.registrationFailure?.let { failure ->
            val accountFailure = failure as? WarpAccountException
            val retry = accountFailure?.canRetryViaVpn == true
            AlertDialog(
                onDismissRequest = { vm.registrationFailure = null },
                title = { Text(L.t("detail.registerFailed")) },
                text = {
                    Text(if (retry && accountFailure?.code != "vpnUnavailable") {
                        L.t("warpRegistration.retryHint", failure.msg)
                    } else failure.msg.toString())
                },
                confirmButton = {
                    TextButton(onClick = {
                        if (!retry) vm.registrationFailure = null
                        else if (vm.foreignVpnActive()) {
                            vm.registrationFailure = null
                            register(viaVpn = true)
                        } else vm.registrationFailure = WarpAccountException("vpnUnavailable")
                    }) { Text(L.t(if (retry) "warpRegistration.retry" else "btn.back")) }
                },
                dismissButton = if (retry) {
                    { TextButton(onClick = { vm.registrationFailure = null }) { Text(L.t("btn.cancel")) } }
                } else null,
            )
        }
        if (registeredViaVpn) AlertDialog(
            onDismissRequest = { registeredViaVpn = false },
            title = { Text(L.t("log.warpRegistered")) },
            text = { Text(L.t("warpRegistration.registeredViaVpn")) },
            confirmButton = { TextButton(onClick = { registeredViaVpn = false }) { Text(L.t("btn.back")) } },
        )

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
                Tab.Settings -> SettingsScreen(vm, m, registerWarp = {
                    withWarpConsent { register(vm.foreignVpnActive()) }
                })
            }
        }
      }
    }
}

package io.github.feg55.zarp.ui

import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material3.Icon
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.core.graphics.drawable.toBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class InstalledApp(val packageName: String, val label: String)

@Composable
internal fun SettingsHeader(title: String, back: () -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        DarkButton(L.t("btn.back"), back)
        SectionTitle(title)
    }
}

@Composable
internal fun SettingsHint(text: String, error: Boolean = false) {
    Text(text, color = if (error) Zc.Bad else Zc.TextDim, fontSize = 13.sp, modifier = Modifier.padding(vertical = 6.dp))
}

@Composable
fun AppProxyScreen(vm: MainViewModel, back: () -> Unit, modifier: Modifier = Modifier) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val s = settings ?: return
    val context = LocalContext.current
    var apps by remember { mutableStateOf<List<InstalledApp>?>(null) }
    var loadFailed by remember { mutableStateOf(false) }
    var query by rememberSaveable { mutableStateOf("") }
    LaunchedEffect(Unit) {
        val loaded = withContext(Dispatchers.IO) { runCatching {
            val pm = context.packageManager
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(0).asSequence()
                .filter { it.enabled && it.uid != android.os.Process.myUid() &&
                    pm.checkPermission(android.Manifest.permission.INTERNET, it.packageName) == PackageManager.PERMISSION_GRANTED }
                .map { InstalledApp(it.packageName, it.loadLabel(pm).toString()) }
                .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label }).toList()
        } }
        apps = loaded.getOrNull()
        loadFailed = loaded.isFailure
    }
    Column(modifier.fillMaxSize().padding(16.dp)) {
        SettingsHeader(L.t("apps.title"), back)
        SwitchRow(L.t("apps.enable"), s.perAppProxy, { on -> vm.updateSettings { it.copy(perAppProxy = on) } })
        SettingsHint(L.t("settings.reconnect"))
        if (s.perAppProxy) {
            val installed = apps.orEmpty().map { it.packageName }.toSet()
            val count = s.proxyApps.count { it in installed }
            SettingsHint(if (count == 0) L.t("apps.empty") else L.t("apps.selected", count), error = apps != null && count == 0)
            DarkField(query, { query = it }, L.t("apps.search"), singleLine = true)
            when {
                loadFailed -> SettingsHint(L.t("apps.loadFailed"), error = true)
                apps == null -> SettingsHint(L.t("apps.loading"))
                else -> {
                    val visible = apps.orEmpty().filter { it.label.contains(query, true) || it.packageName.contains(query, true) }
                    if (visible.isEmpty()) SettingsHint(L.t("apps.noMatches"))
                    LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(bottom = 16.dp)) {
                        items(visible, key = { it.packageName }) { app ->
                            Row(Modifier.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                                AppIcon(app.packageName, Modifier.padding(end = 12.dp).size(40.dp))
                                Column(Modifier.weight(1f)) {
                                    SwitchRow(app.label, app.packageName in s.proxyApps, { on ->
                                        vm.updateSettings { it.copy(proxyApps = if (on) it.proxyApps + app.packageName else it.proxyApps - app.packageName) }
                                    })
                                    Text(app.packageName, color = Zc.TextDim, fontSize = 11.sp)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AppIcon(packageName: String, modifier: Modifier) {
    val pm = LocalContext.current.packageManager
    val size = with(LocalDensity.current) { 40.dp.roundToPx() }
    val icon by produceState<ImageBitmap?>(null, packageName, size) {
        value = withContext(Dispatchers.IO) {
            runCatching { pm.getApplicationIcon(packageName).toBitmap(size, size).asImageBitmap() }.getOrNull()
        }
    }
    if (icon != null) Image(icon!!, contentDescription = null, modifier = modifier)
    else Icon(Icons.Default.Android, contentDescription = null, modifier = modifier, tint = Zc.TextDim)
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun EndpointsScreen(vm: MainViewModel, back: () -> Unit, modifier: Modifier = Modifier) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val s = settings ?: return
    val importing by vm.importState.collectAsStateWithLifecycle()
    val busy = vm.status.collectAsStateWithLifecycle().value.state.busy || importing.loading
    var custom by rememberSaveable(s.customEndpoints) { mutableStateOf(s.customEndpoints) }
    var useProxy by rememberSaveable(s.useProxy) { mutableStateOf(s.useProxy) }
    var uri by rememberSaveable(s.proxyUri) { mutableStateOf(s.proxyUri) }
    val endpointValid = remember(custom) { runCatching { EndpointParser.parse(custom) }.isSuccess }
    val issue = remember(uri) { Subscription.explainSource(uri) }
    val subscription = remember(uri) { Subscription.isUrl(uri) }
    val profiles by vm.serverProfiles.collectAsStateWithLifecycle()
    val names = remember(profiles) { ServerPairs.names(profiles) }
    val dirty = custom != s.customEndpoints || uri != s.proxyUri || useProxy != s.useProxy
    val unavailable = s.serverSelectionId != null && profiles.none { it.id == s.serverSelectionId }
    LazyColumn(modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            SettingsHeader(L.t("endpoint.title"), back)
            SwitchRow(L.t("proxy.enable"), useProxy, { useProxy = it }, enabled = !busy)
            if (useProxy) {
                SettingsHint(L.t("proxy.hint"))
                DarkField(uri, { uri = it.take(16_384) }, L.t("proxy.link"), monospace = true, uriInput = true, modifier = Modifier.heightIn(min = 100.dp))
                if (issue != null && uri.isNotBlank()) SettingsHint(issue.toString(), error = true)
                else if (uri.isNotBlank()) SettingsHint(L.t(if (subscription) "proxy.sourceSubscription" else "proxy.sourceLink"))
                if (importing.loading) SettingsHint(L.t("proxy.subLoading"))
                importing.error?.let { SettingsHint(it.toString(), error = true) }
            } else {
                SectionTitle(L.t("endpoint.warp"))
                SettingsHint(L.t("endpoint.hint"))
                DarkField(custom, { custom = it }, "IP:port / [IPv6]:port", monospace = true, modifier = Modifier.heightIn(min = 130.dp))
                if (!endpointValid) SettingsHint(L.t("endpoint.invalid"), error = true)
                if (custom.isNotBlank()) DarkButton(L.t("endpoint.reset"), { custom = "" }, enabled = !busy)
            }
            if (useProxy) {
                SectionTitle(L.t("endpoint.warp"))
                DarkField(custom, {}, "IP:port / [IPv6]:port", monospace = true, enabled = false,
                    modifier = Modifier.heightIn(min = 70.dp, max = 120.dp))
                SettingsHint(L.t("server.warpOnly"))
            }
            SettingsHint(L.t("endpoint.applies"))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                DarkButton(L.t("btn.save"), { vm.saveSource(uri, custom, useProxy) }, Modifier.weight(1f), primary = true,
                    enabled = !busy && (dirty || subscription) && (if (useProxy) issue == null else endpointValid))
                if (importing.loading) DarkButton(L.t("btn.cancel"), vm::cancelImport)
                else if (s.proxyUri.isNotEmpty()) DarkButton(L.t("proxy.delete"), vm::deleteSource, enabled = !busy)
            }
            if (s.useProxy && Subscription.isUrl(s.proxyUri)) {
                DarkButton(L.t("proxy.refresh"), vm::refreshSource, Modifier.fillMaxWidth(), enabled = !busy && !dirty)
                s.subscription?.let { cached ->
                    val time = java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT)
                        .format(java.util.Date(cached.updatedAt))
                    SettingsHint(L.t("proxy.subStatus", profiles.size, time, cached.unsupported + cached.refused + cached.truncated))
                }
            }
            if (s.useProxy) {
                SectionTitle(L.t("server.connections"))
                if (unavailable) SettingsHint(L.t("server.unavailable"), error = true)
                ConnectionChoice(L.t("server.automatic"), null, s.serverSelectionId, !busy, vm::selectServer)
            }
        }
        if (s.useProxy) items(profiles, key = { it.id }) { profile ->
            Column {
                ConnectionChoice(names[profiles.indexOf(profile)], profile.id, s.serverSelectionId, !busy, vm::selectServer)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    ConnectionChip(profile.protocolTitle)
                    ConnectionChip(L.t(if (profile.outerTransport == Transport.MasqueH3) "server.quic" else "server.tcp"))
                    ConnectionChip(L.t("server.security." + profile.security))
                    if (profile.hasEch) ConnectionChip(L.t("server.ech"))
                }
                if (!profile.hasTls && !s.allowPlainServer) SettingsHint(L.t("proxy.noHandshake"), error = true)
                if (!profile.hasTls && s.allowPlainServer) Text(L.t("server.plainOnly"), color = androidx.compose.ui.graphics.Color(0xFFFFC857), fontSize = 13.sp)
                if (profile.obfuscated) SettingsHint(L.t("server.salamander"))
            }
        }
    }
}

@Composable
private fun ConnectionChip(text: String) {
    Surface(color = Zc.Panel, shape = RoundedCornerShape(8.dp), border = BorderStroke(1.dp, Zc.Border)) {
        Text(text, color = Zc.TextDim, fontSize = 12.sp, modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp))
    }
}

@Composable
private fun ConnectionChoice(name: String, id: String?, selected: String?, enabled: Boolean, choose: (String?) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        androidx.compose.material3.RadioButton(selected = id == selected, onClick = { choose(id) }, enabled = enabled)
        androidx.compose.material3.TextButton(onClick = { choose(id) }, enabled = enabled, modifier = Modifier.weight(1f)) {
            Text(name, color = Zc.Text, fontSize = 15.sp)
        }
    }
}

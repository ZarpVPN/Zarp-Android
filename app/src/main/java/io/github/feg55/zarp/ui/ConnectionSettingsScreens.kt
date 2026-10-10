package io.github.feg55.zarp.ui

import android.content.pm.PackageManager
import androidx.compose.foundation.Image
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
fun EndpointsScreen(vm: MainViewModel, back: () -> Unit, modifier: Modifier = Modifier) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val s = settings ?: return
    val busy = vm.status.collectAsStateWithLifecycle().value.state.busy
    var custom by rememberSaveable(s.customEndpoints) { mutableStateOf(s.customEndpoints) }
    var useProxy by rememberSaveable(s.useProxy) { mutableStateOf(s.useProxy) }
    var uri by rememberSaveable(s.proxyUri) { mutableStateOf(s.proxyUri) }
    val endpointValid = remember(custom) { runCatching { EndpointParser.parse(custom) }.isSuccess }
    val profile = remember(uri) { runCatching { ProxyProfile.parse(uri) }.getOrNull() }
    val dirty = custom != s.customEndpoints || uri != s.proxyUri || useProxy != s.useProxy
    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        SettingsHeader(L.t("endpoint.title"), back)
        SwitchRow(L.t("proxy.enable"), useProxy, { useProxy = it })
        if (useProxy) {
            SettingsHint(L.t("proxy.hint"))
            DarkField(uri, { uri = it }, L.t("proxy.link"), monospace = true, uriInput = true, modifier = Modifier.heightIn(min = 110.dp))
            if (profile != null) SettingsHint("${profile.transport.title}: ${profile.endpoint}")
            else if (uri.isNotBlank()) SettingsHint(L.t("proxy.invalid"), error = true)
        } else {
            SectionTitle(L.t("endpoint.warp"))
            SettingsHint(L.t("endpoint.hint"))
            DarkField(custom, { custom = it }, "IP:port / [IPv6]:port", monospace = true, modifier = Modifier.heightIn(min = 150.dp))
            if (!endpointValid) SettingsHint(L.t("endpoint.invalid"), error = true)
            if (custom.isNotBlank()) DarkButton(L.t("endpoint.reset"), { custom = "" }, Modifier.padding(top = 8.dp))
        }
        SettingsHint(L.t("endpoint.applies"))
        DarkButton(L.t("btn.save"), {
            vm.updateSettings { it.copy(customEndpoints = custom.trim(), useProxy = useProxy, proxyUri = uri.trim()) }
        }, Modifier.fillMaxWidth().padding(top = 12.dp), primary = true,
            enabled = !busy && dirty && endpointValid && (!useProxy || profile != null))
    }
}

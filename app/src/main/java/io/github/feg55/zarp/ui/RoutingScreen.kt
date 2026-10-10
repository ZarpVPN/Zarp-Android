package io.github.feg55.zarp.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.core.RoutingPreset
import io.github.feg55.zarp.core.RoutingSettings
import io.github.feg55.zarp.data.GeoFileState
import java.text.DateFormat
import java.util.Date
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

private fun presetName(preset: RoutingPreset): String = preset.name.ifBlank {
    when (preset.id) {
        "lan" -> L.t("routing.lanPreset")
        "ru", "ir", "cn" -> L.t("country.${preset.id}")
        else -> L.t("routing.customPreset")
    }
}

@Composable
fun RoutingScreen(vm: MainViewModel, back: () -> Unit, modifier: Modifier = Modifier) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val routing = settings?.routing ?: return
    var page by rememberSaveable { mutableStateOf("") }
    var editingId by rememberSaveable { mutableStateOf("") }
    var action by rememberSaveable { mutableStateOf("") }
    var adding by rememberSaveable { mutableStateOf(false) }
    val preset = routing.presets.firstOrNull { it.id == editingId }
    fun navigateBack() { page = if (page == "rules") "preset" else "" }
    BackHandler(page.isNotEmpty()) { navigateBack() }
    when {
        page == "geo" -> { GeoSourcesScreen(vm, routing, { page = "" }, modifier); return }
        page == "rules" && preset != null -> {
            RulesEditor(vm, preset, action, { page = "preset" }, modifier); return
        }
        page == "preset" && preset != null -> {
            Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
                SettingsHeader(presetName(preset), { page = "" })
                listOf("direct", "proxy", "block").forEach { group ->
                    RoutingNavigationRow(L.t("routing.$group"), RoutingPreset.lines(preset.text(group)).size.toString()) {
                        action = group; page = "rules"
                    }
                }
                SettingsHint(L.t("routing.priority"))
                SettingsHint(L.t("settings.reconnect"))
                val original = RoutingSettings.defaults().firstOrNull { it.id == preset.id }
                if (original != null && original != preset) DarkButton(L.t("routing.resetPreset"), {
                    vm.updateSettings { it.copy(routing = it.routing.replace(original)) }
                }, Modifier.fillMaxWidth().padding(top = 12.dp))
                if (original == null) DarkButton(L.t("routing.deletePreset"), {
                    vm.updateSettings { s -> s.copy(routing = s.routing.copy(
                        presets = s.routing.presets.filterNot { it.id == preset.id },
                        selectedPreset = if (s.routing.selectedPreset == preset.id) "lan" else s.routing.selectedPreset,
                        enabled = s.routing.enabled && s.routing.selectedPreset != preset.id,
                    )) }
                    page = ""
                }, Modifier.fillMaxWidth().padding(top = 12.dp))
            }
            return
        }
    }
    LazyColumn(modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item {
            SettingsHeader(L.t("routing.title"), back)
            SwitchRow(L.t("routing.enable"), routing.enabled, { enabled ->
                vm.updateSettings { it.copy(routing = it.routing.copy(enabled = enabled)) }
            })
        }
        item { RoutingNavigationRow(L.t("geo.title")) { page = "geo" } }
        item { SectionTitle(L.t("routing.presets")) }
        items(routing.presets, key = { it.id }) { preset ->
            Card(
                colors = CardDefaults.cardColors(containerColor = Zc.Panel),
                border = BorderStroke(1.dp, if (preset.id == routing.selectedPreset) Zc.Accent else Zc.Border),
                shape = RoundedCornerShape(10.dp),
            ) {
                Row(Modifier.fillMaxWidth().padding(end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Row(Modifier.weight(1f).clickable {
                        vm.updateSettings { it.copy(routing = it.routing.copy(selectedPreset = preset.id)) }
                    }.padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = preset.id == routing.selectedPreset, onClick = null,
                            modifier = Modifier.padding(horizontal = 14.dp), colors = RadioButtonDefaults.colors(selectedColor = Zc.Accent))
                        Text(presetName(preset), color = Zc.Text, modifier = Modifier.weight(1f))
                    }
                    IconButton(onClick = { editingId = preset.id; page = "preset" }) {
                        Icon(Icons.Default.Edit, contentDescription = L.t("routing.edit", presetName(preset)), tint = Zc.TextDim)
                    }
                }
            }
        }
        item { DarkButton(L.t("routing.addPreset"), { adding = true }, Modifier.fillMaxWidth()) }
        item { SettingsHint(L.t("settings.reconnect")) }
    }
    if (adding) {
        var name by rememberSaveable { mutableStateOf("") }
        AlertDialog(onDismissRequest = { adding = false }, containerColor = Zc.Panel,
            title = { Text(L.t("routing.addPreset"), color = Zc.Text) },
            text = { DarkField(name, { name = it.take(80) }, L.t("routing.name"), singleLine = true) },
            confirmButton = { TextButton(enabled = name.isNotBlank(), onClick = {
                val added = RoutingPreset("custom-${UUID.randomUUID()}", name.trim())
                vm.updateSettings { it.copy(routing = it.routing.copy(presets = it.routing.presets + added)) }
                editingId = added.id; page = "preset"; adding = false
            }) { Text(L.t("btn.save")) } },
            dismissButton = { TextButton(onClick = { adding = false }) { Text(L.t("btn.cancel")) } },
        )
    }
}

@Composable
private fun RoutingNavigationRow(title: String, detail: String = "", onClick: () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = Zc.Panel), border = BorderStroke(1.dp, Zc.Border),
        shape = RoundedCornerShape(10.dp), modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable(onClick = onClick)) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(title, color = Zc.Text, modifier = Modifier.weight(1f))
            if (detail.isNotEmpty()) Text(detail, color = Zc.TextDim)
            Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, tint = Zc.TextDim, modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
private fun RulesEditor(vm: MainViewModel, preset: RoutingPreset, action: String, back: () -> Unit, modifier: Modifier) {
    var draft by rememberSaveable(preset.id, action, preset.text(action)) { mutableStateOf(preset.text(action)) }
    var error by remember { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        SettingsHeader(L.t("routing.$action"), back)
        SettingsHint(presetName(preset))
        DarkField(draft, { draft = it; error = null }, L.t("routing.rules"), monospace = true, uriInput = true,
            modifier = Modifier.heightIn(min = 220.dp))
        SettingsHint(L.t("routing.syntax"))
        error?.let { SettingsHint(it, error = true) }
        DarkButton(L.t("btn.save"), {
            scope.launch {
                saving = true
                try {
                    vm.validateRules(preset.withRules(action, draft))
                    vm.updateSettings { s ->
                        val current = s.routing.presets.firstOrNull { it.id == preset.id } ?: preset
                        s.copy(routing = s.routing.replace(current.withRules(action, draft.trim())))
                    }
                    back()
                } catch (e: CancellationException) { throw e }
                catch (e: Exception) { error = L.t("routing.invalidRules") + ": " + e.message }
                finally { saving = false }
            }
        }, Modifier.fillMaxWidth().padding(top = 12.dp), primary = true, enabled = !saving && draft != preset.text(action))
    }
}

@Composable
private fun GeoSourcesScreen(vm: MainViewModel, routing: RoutingSettings, back: () -> Unit, modifier: Modifier) {
    val files by vm.geoFiles.collectAsStateWithLifecycle()
    LaunchedEffect(routing.geoipUrl, routing.geositeUrl) { vm.refreshGeo(routing) }
    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        SettingsHeader(L.t("geo.title"), back)
        listOf("geoip", "geosite").forEach { kind ->
            val saved = if (kind == "geoip") routing.geoipUrl else routing.geositeUrl
            var url by rememberSaveable(kind, saved) { mutableStateOf(saved) }
            val file = files[vm.geoKey(kind, saved)] ?: GeoFileState()
            SectionTitle(if (kind == "geoip") "GeoIP" else "GeoSite")
            DarkField(url, { url = it }, L.t("geo.source"), uriInput = true)
            if (!RoutingSettings.validSource(url)) SettingsHint(L.t("geo.invalidUrl"), error = true)
            when {
                file.downloading -> {
                    LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 10.dp), color = Zc.Accent, trackColor = Zc.Panel)
                    SettingsHint(L.t("geo.downloading", (file.bytes / 1024).toInt()))
                }
                file.updatedAt > 0 -> SettingsHint(L.t("geo.ready", file.categories,
                    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(file.updatedAt))))
                kind == "geoip" && saved == RoutingSettings.GEOIP_URL -> SettingsHint(L.t("geo.bundled"))
                else -> SettingsHint(L.t("geo.missing"))
            }
            file.error?.let { SettingsHint(it, error = true) }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                DarkButton(L.t(if (file.updatedAt > 0) "geo.update" else "geo.download"), { vm.downloadGeo(kind, url.trim()) },
                    Modifier.weight(1f), enabled = files.values.none { it.downloading } && RoutingSettings.validSource(url))
                if (url != saved) DarkButton(L.t("btn.save"), {
                    vm.updateSettings { s -> s.copy(routing = if (kind == "geoip") s.routing.copy(geoipUrl = url.trim()) else s.routing.copy(geositeUrl = url.trim())) }
                }, enabled = RoutingSettings.validSource(url))
            }
            val defaultUrl = if (kind == "geoip") RoutingSettings.GEOIP_URL else RoutingSettings.GEOSITE_URL
            if (url != defaultUrl) TextButton(onClick = { url = defaultUrl }) { Text(L.t("geo.resetSource"), color = Zc.TextDim, fontSize = 12.sp) }
        }
        SettingsHint(L.t("geo.format"))
        SettingsHint(L.t("settings.reconnect"))
    }
}

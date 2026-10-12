package io.github.feg55.zarp.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ButtonDefaults
import io.github.feg55.zarp.core.StrategyFilter
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.core.L
import io.github.feg55.zarp.core.Strategy
import io.github.feg55.zarp.core.TestResult
import java.text.DateFormat
import java.util.Date
import java.util.Locale

@Composable
fun StrategiesScreen(vm: MainViewModel, guarded: (() -> Unit) -> Unit, modifier: Modifier = Modifier) {
    val strategies by vm.strategies.collectAsStateWithLifecycle()
    val results by vm.results.collectAsStateWithLifecycle()
    val selectedId by vm.selectedId.collectAsStateWithLifecycle()
    val active by vm.activePair.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    var checked by remember { mutableStateOf(setOf<String>()) }
    var details by remember { mutableStateOf<Strategy?>(null) }
    val busy = status.state.busy
    val settings by vm.settings.collectAsStateWithLifecycle()
    var endpointsOpen by rememberSaveable { mutableStateOf(false) }
    var query by rememberSaveable { mutableStateOf("") }
    val visible = remember(strategies, query) { strategies.filter { query.isBlank() || it.name.contains(query, true) || it.protocolTitle.contains(query, true) } }
    BackHandler(endpointsOpen) { endpointsOpen = false }
    if (endpointsOpen) {
        EndpointsScreen(vm, { endpointsOpen = false }, modifier)
        return
    }
    LaunchedEffect(strategies) {
        checked = checked.intersect(strategies.map { it.id }.toSet())
        if (details?.id !in strategies.map { it.id }) details = null
    }

    Box(modifier.fillMaxSize()) {
        LazyColumn(
            contentPadding = PaddingValues(12.dp, 12.dp, 12.dp, 96.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item {
                DarkButton(L.t("endpoint.title"), { endpointsOpen = true }, Modifier.fillMaxWidth())
            }
            item {
                CountryFilter(settings?.strategyCountry ?: "all", enabled = !busy) { country ->
                    checked = emptySet()
                    details = null
                    vm.updateSettings { it.copy(strategyCountry = StrategyFilter.toggle(it.strategyCountry, country)) }
                }
            }
            item { DarkField(query, { query = it.take(128) }, L.t("server.searchPairs"), singleLine = true) }
            if (active?.profile != null) item { SettingsHint(L.t("server.activePair", active!!.name)) }
            if (visible.isEmpty()) item { Text(L.t("filter.empty"), color = Zc.TextDim) }
            items(visible, key = { it.id }) { s ->
                StrategyRow(
                    s = s,
                    r = results[s.id],
                    current = s.id == (active?.id ?: selectedId),
                    checked = s.id in checked,
                    onCheck = { on -> checked = if (on) checked + s.id else checked - s.id },
                    onClick = { details = s },
                )
            }
        }
        if (checked.isNotEmpty()) {
            ExtendedFloatingActionButton(
                onClick = {
                    if (!busy) {
                        val list = strategies.filter { it.id in checked }
                        guarded { vm.test(list) }
                        checked = emptySet()
                    }
                },
                containerColor = if (busy) Zc.Panel else Zc.Accent,
                contentColor = if (busy) Zc.TextDim else Zc.OnAccent,
                modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp),
            ) { Text(L.t("btn.testSelected") + " (${checked.size})", fontWeight = FontWeight.SemiBold) }
        }
    }

    details?.let { s -> StrategyDialog(s, results[s.id], busy, guarded, vm) { details = null } }
}

@Composable
private fun CountryFilter(selected: String, enabled: Boolean, onChange: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val countries = StrategyFilter.selected(selected)
    val label = if (countries.isEmpty()) L.t("country.all")
        else StrategyFilter.countries.filter { it in countries }.joinToString(", ") { L.t("country.$it") }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
        Box {
            OutlinedButton(
                onClick = { expanded = true }, enabled = enabled,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Zc.Text),
                border = BorderStroke(1.dp, if (countries.isEmpty()) Zc.Border else Zc.Accent),
                shape = RoundedCornerShape(10.dp),
            ) {
                Text(label, modifier = Modifier.padding(end = 10.dp))
                Icon(Icons.Default.FilterList, contentDescription = L.t("filter.title"))
            }
            DropdownMenu(expanded = expanded && enabled, onDismissRequest = { expanded = false }, containerColor = Zc.Panel) {
                StrategyFilter.countries.forEach { country ->
                    DropdownMenuItem(
                        text = { Text(L.t("country.$country"), color = Zc.Text) },
                        leadingIcon = {
                            Checkbox(checked = if (country == "all") countries.isEmpty() else country in countries,
                                onCheckedChange = { onChange(country) })
                        },
                        onClick = { onChange(country) },
                    )
                }
            }
        }
    }
}

@Composable
private fun StrategyRow(
    s: Strategy,
    r: TestResult?,
    current: Boolean,
    checked: Boolean,
    onCheck: (Boolean) -> Unit,
    onClick: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = if (current) Zc.PanelHover else Zc.Panel),
        border = BorderStroke(1.dp, if (current) Zc.Accent else Zc.Border),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
    ) {
        Row(Modifier.padding(start = 4.dp, end = 12.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = checked,
                onCheckedChange = onCheck,
                enabled = s.supported,
                colors = CheckboxDefaults.colors(
                    checkedColor = Zc.Accent,
                    uncheckedColor = Zc.TextDim,
                    checkmarkColor = Zc.OnAccent,
                    disabledUncheckedColor = Zc.TextDisabled,
                ),
            )
            Column(Modifier.weight(1f)) {
                Text(
                    (if (current) "✔ " else "") + s.name,
                    color = if (s.supported) Zc.Text else Zc.TextDim,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Medium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    AssistChip(
                        onClick = onClick,
                        label = { Text(s.profile?.protocolTitle ?: s.transport.shortName.uppercase(), fontSize = 12.sp) },
                        colors = AssistChipDefaults.assistChipColors(labelColor = Zc.TextDim),
                        border = BorderStroke(1.dp, Zc.Border),
                    )
                    val (text, color) = resultLabel(s, r)
                    Text(text, color = color, fontSize = 13.sp, maxLines = 2)
                }
            }
        }
    }
}

/** Result text and color: green for ✔✔, orange for a single check, red for a failure. */
fun resultLabel(s: Strategy, r: TestResult?): Pair<String, Color> = when {
    s.plain -> L.t("server.plainOnly") to Color(0xFFFFC857)
    !s.supported -> L.t("result.unsupported") to Zc.TextDisabled
    r == null -> L.t("result.notTested") to Zc.TextDim
    r.ok && r.confirmed -> (L.t("result.works2") + "  " + L.t("result.times", r.connectMs, r.pingMs)) to Zc.Ok
    r.ok -> (L.t("result.works1") + "  " + L.t("result.times", r.connectMs, r.pingMs)) to Zc.Accent
    else -> ("✘ " + r.displayError) to Zc.Bad
}

@Composable
private fun StrategyDialog(
    s: Strategy,
    r: TestResult?,
    busy: Boolean,
    guarded: (() -> Unit) -> Unit,
    vm: MainViewModel,
    close: () -> Unit,
) {
    val language by L.current.collectAsStateWithLifecycle()
    val usable = !busy && s.supported
    AlertDialog(
        onDismissRequest = close,
        containerColor = Zc.Panel,
        titleContentColor = Zc.Text,
        textContentColor = Zc.Text,
        title = { Text(s.name, fontSize = 19.sp) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(s.protocolTitle, color = Zc.TextDim, fontSize = 13.sp)
                if (s.plain) Text(L.t("server.plainOnly"), color = Color(0xFFFFC857), fontSize = 14.sp)
                Text(s.args.ifBlank { "-" }, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Zc.TextDim)
                s.unsupported?.let { Text(L.t("err.unsupported", it.toString()), color = Zc.Bad, fontSize = 14.sp) }
                if (r != null && s.supported) {
                    val (text, color) = resultLabel(s, r)
                    Text(text, color = color, fontSize = 14.sp)
                    r.endpoint?.let { Text(L.t("result.endpoint", it), fontSize = 14.sp, color = Zc.TextDim) }
                    if (r.timestamp > 0) {
                        val time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.forLanguageTag(language))
                            .format(Date(r.timestamp))
                        Text(L.t("result.tested", time), fontSize = 13.sp, color = Zc.TextDim)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = usable, onClick = { close(); guarded { vm.use(s) } }) {
                Text(L.t("btn.use"), color = if (usable) Zc.Accent else Zc.TextDisabled)
            }
        },
        dismissButton = {
            TextButton(enabled = usable, onClick = { close(); guarded { vm.test(listOf(s)) } }) {
                Text(L.t("btn.test"), color = if (usable) Zc.Text else Zc.TextDisabled)
            }
        },
    )
}

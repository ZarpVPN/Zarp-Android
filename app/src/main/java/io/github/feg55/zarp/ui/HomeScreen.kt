package io.github.feg55.zarp.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.core.EngineState
import io.github.feg55.zarp.core.L

@Composable
fun HomeScreen(vm: MainViewModel, guarded: (() -> Unit) -> Unit, modifier: Modifier = Modifier) {
    val status by vm.status.collectAsStateWithLifecycle()
    val results by vm.results.collectAsStateWithLifecycle()
    val strategies by vm.strategies.collectAsStateWithLifecycle()
    val selectedId by vm.selectedId.collectAsStateWithLifecycle()
    val settings by vm.settings.collectAsStateWithLifecycle()
    val state = status.state
    val busy = state.busy

    val power: @Composable (Dp) -> Unit = { size ->
        PowerButton(
            look = when {
                state == EngineState.Connected -> PowerLook.On
                busy -> PowerLook.Busy
                else -> PowerLook.Off
            },
            description = L.t(
                when {
                    state == EngineState.Connected -> "tray.disconnect"
                    busy -> "tray.cancel"
                    else -> "tray.connect"
                }
            ),
            onClick = {
                when {
                    state == EngineState.Connected -> vm.disconnect()
                    busy -> vm.cancel()
                    else -> guarded { vm.connect() }
                }
            },
            modifier = Modifier.size(size),
        )
    }

    // everything fits on one screen: the power button takes whatever height is left
    BoxWithConstraints(modifier.fillMaxSize()) {
        val short = maxHeight < 520.dp // landscape: scroll instead of squeezing the button
        Column(
            Modifier.fillMaxSize()
                .then(if (short) Modifier.verticalScroll(rememberScrollState()) else Modifier)
                .padding(horizontal = 24.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("Zarp", color = Zc.Text, fontSize = 28.sp, fontWeight = FontWeight.Bold)
            Text(L.t(if (status.strategy?.profile != null || settings?.useProxy == true) "proxy.subtitle" else "main.subtitle"), color = Zc.TextDim, fontSize = 14.sp, textAlign = TextAlign.Center)

            if (short) {
                Spacer(Modifier.height(16.dp))
                power(180.dp)
                Spacer(Modifier.height(16.dp))
            } else {
                BoxWithConstraints(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    power(minOf(maxHeight - 24.dp, maxWidth * 0.66f, 240.dp))
                }
            }

            val statusColor by animateColorAsState(
                when {
                    state == EngineState.Connected -> Zc.Accent
                    state == EngineState.Error -> Zc.Bad
                    busy -> Zc.Busy
                    else -> Zc.Text
                },
                label = "status",
            )
            Text(stateLabel(state), color = statusColor, fontSize = 24.sp, fontWeight = FontWeight.Bold)
            Text(
                status.detail.toString(), color = Zc.TextDim, fontSize = 15.sp, textAlign = TextAlign.Center,
                maxLines = 2, overflow = TextOverflow.Ellipsis,
            )
            // same height with and without the progress line, so nothing jumps
            Box(Modifier.fillMaxWidth().height(28.dp), contentAlignment = Alignment.Center) {
                if (state == EngineState.Searching && status.progressTotal > 0) {
                    ProgressLine(status.progressDone.toFloat() / status.progressTotal)
                }
            }

            Column(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(Zc.Panel)
                    .border(1.dp, Zc.Border, RoundedCornerShape(12.dp)).padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                // the running or tested strategy, otherwise the saved one; its name is shown above
                val s = status.strategy ?: strategies.firstOrNull { it.id == selectedId }
                val saved = results[s?.id]?.takeIf { it.ok }
                val connectMs = status.connectMs ?: saved?.connectMs
                val pingMs = status.pingMs ?: saved?.pingMs
                InfoRow(L.t("col.protocol"), s?.protocolTitle ?: "-")
                if (s?.plain == true) Text(L.t("server.plainOnly"), color = androidx.compose.ui.graphics.Color(0xFFFFC857), fontSize = 13.sp)
                InfoRow(L.t("info.endpoint"), status.endpoint ?: saved?.endpoint ?: "-")
                InfoRow(L.t("info.connect"), connectMs?.let { L.t("info.ms", it) } ?: "-")
                InfoRow(L.t("info.ping"), pingMs?.let { L.t("info.ms", it) } ?: "-")
            }

            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                DarkButton(L.t("btn.quickScan"), { guarded { vm.quickScan() } }, Modifier.weight(1f), primary = true, enabled = !busy)
                DarkButton(L.t("btn.fullScan"), { guarded { vm.fullScan() } }, Modifier.weight(1f), enabled = !busy)
            }
        }
        LanguageButton(vm, Modifier.align(Alignment.TopEnd).padding(8.dp))
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = Zc.TextDim, fontSize = 15.sp)
        Text(value, color = Zc.Text, fontSize = 15.sp, fontWeight = FontWeight.Medium, textAlign = TextAlign.End)
    }
}

/** Thin progress line of the desktop window, animated between steps. */
@Composable
fun ProgressLine(fraction: Float) {
    val animated by animateFloatAsState(fraction.coerceIn(0f, 1f), label = "progress")
    Box(Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)).background(Zc.Panel)) {
        Box(Modifier.fillMaxWidth(animated).height(4.dp).clip(RoundedCornerShape(2.dp)).background(Zc.Busy))
    }
}

/** Globe button: system language or one of Zarp's languages. */
@Composable
private fun LanguageButton(vm: MainViewModel, modifier: Modifier) {
    var open by remember { mutableStateOf(false) }
    Box(modifier) {
        IconButton(onClick = { open = true }) {
            Icon(Icons.Outlined.Language, L.t("main.languageTip"), tint = Zc.TextDim)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }, containerColor = Zc.Panel) {
            val setting = L.setting
            val system = L.languages.first { it.code == L.systemLanguage }.nativeName
            LanguageItem(L.t("lang.system", system), setting == null) { vm.setLanguage(null); open = false }
            HorizontalDivider(color = Zc.Border)
            L.languages.forEach { lang ->
                LanguageItem(lang.nativeName, setting == lang.code) { vm.setLanguage(lang.code); open = false }
            }
        }
    }
}

@Composable
private fun LanguageItem(text: String, checked: Boolean, onClick: () -> Unit) {
    DropdownMenuItem(
        text = { Text(text, color = if (checked) Zc.Accent else Zc.Text, fontSize = 15.sp) },
        leadingIcon = { Text(if (checked) "✔" else "", color = Zc.Accent, modifier = Modifier.size(18.dp)) },
        onClick = onClick,
    )
}

fun stateLabel(s: EngineState): String = L.t(
    when (s) {
        EngineState.Idle -> "status.disconnected"
        EngineState.Preparing -> "status.preparing"
        EngineState.Searching -> "status.searching"
        EngineState.Connecting -> "status.connecting"
        EngineState.Connected -> "status.connected"
        EngineState.Disconnecting -> "status.disconnecting"
        EngineState.Error -> "status.error"
    }
)

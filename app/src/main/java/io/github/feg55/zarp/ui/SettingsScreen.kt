package io.github.feg55.zarp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.activity.compose.BackHandler
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.BuildConfig
import io.github.feg55.zarp.core.L

@Composable
fun SettingsScreen(vm: MainViewModel, modifier: Modifier = Modifier) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val s = settings ?: return
    val busy = vm.status.collectAsStateWithLifecycle().value.state.busy
    var page by rememberSaveable { mutableStateOf("") }
    BackHandler(page.isNotEmpty()) { page = "" }
    when (page) {
        "apps" -> { AppProxyScreen(vm, { page = "" }, modifier); return }
        "routing" -> { RoutingScreen(vm, { page = "" }, modifier); return }
    }

    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 4.dp)) {
        SectionTitle(L.t("settings.scanning"))
        NumberSlider(L.t("opt.timeout"), s.testTimeoutSec, 5..60) { v -> vm.updateSettings { it.copy(testTimeoutSec = v) } }
        NumberSlider(L.t("opt.stopAfter").replace('\n', ' '), s.stopAfterWorking, 1..10) { v ->
            vm.updateSettings { it.copy(stopAfterWorking = v) }
        }
        SwitchRow(L.t("opt.isolate"), s.isolateTests, { v -> vm.updateSettings { it.copy(isolateTests = v) } })

        SectionTitle(L.t("settings.connection"))
        DarkButton(L.t("apps.title"), { page = "apps" }, Modifier.fillMaxWidth())
        DarkButton(L.t("routing.title"), { page = "routing" }, Modifier.fillMaxWidth().padding(top = 8.dp))
        SwitchRow(L.t("opt.autoConnect"), s.autoConnect, { v -> vm.updateSettings { it.copy(autoConnect = v) } })
        SwitchRow(L.t("opt.ipv6"), s.tunnelIpv6, { v -> vm.updateSettings { it.copy(tunnelIpv6 = v) } })
        var dns by remember(s.dns) { mutableStateOf(s.dns) }
        DarkField(dns, { dns = it }, L.t("opt.dns"), singleLine = true)
        if (dns != s.dns) {
            DarkButton(L.t("btn.save"), { vm.updateSettings { it.copy(dns = dns.trim()) } }, Modifier.padding(top = 8.dp))
        }

        SectionTitle(L.t("settings.custom"))
        var custom by remember(s.customStrategies) { mutableStateOf(s.customStrategies) }
        DarkField(custom, { custom = it }, null, monospace = true, modifier = Modifier.heightIn(min = 170.dp))
        if (custom != s.customStrategies) {
            DarkButton(L.t("btn.save"), { vm.updateSettings { it.copy(customStrategies = custom) } }, Modifier.padding(top = 8.dp))
        }

        SectionTitle(L.t("settings.data"))
        Text(L.t(if (vm.accountRegistered) "opt.deviceOn" else "opt.deviceOff"), color = Zc.Text, fontSize = 15.sp)
        Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DarkButton(L.t("btn.clearResults"), { vm.clearResults() }, enabled = !busy)
            DarkButton(L.t("btn.newDevice"), { vm.resetAccount() }, enabled = !busy)
        }

        SectionTitle(L.t("settings.about"))
        Text(L.t("about.text", BuildConfig.VERSION_NAME), color = Zc.TextDim, fontSize = 12.sp, lineHeight = 17.sp)
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
fun DarkField(
    value: String,
    onChange: (String) -> Unit,
    label: String?,
    modifier: Modifier = Modifier,
    singleLine: Boolean = false,
    monospace: Boolean = false,
    uriInput: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = label?.let { { Text(it) } },
        singleLine = singleLine,
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.None,
            autoCorrectEnabled = false,
            keyboardType = if (uriInput) KeyboardType.Uri else KeyboardType.Text,
        ),
        textStyle = TextStyle(fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default, fontSize = if (monospace) 12.sp else 15.sp),
        modifier = modifier.fillMaxWidth().padding(top = 6.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Zc.Accent,
            unfocusedBorderColor = Zc.Border,
            focusedLabelColor = Zc.Accent,
            unfocusedLabelColor = Zc.TextDim,
            focusedTextColor = Zc.Text,
            unfocusedTextColor = Zc.Text,
            cursorColor = Zc.Accent,
            focusedContainerColor = Zc.Panel,
            unfocusedContainerColor = Zc.Panel,
        ),
    )
}

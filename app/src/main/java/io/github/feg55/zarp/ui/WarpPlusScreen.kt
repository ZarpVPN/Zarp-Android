package io.github.feg55.zarp.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.core.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

@Composable
fun WarpPlusScreen(vm: MainViewModel, back: () -> Unit, modifier: Modifier = Modifier) {
    val settings by vm.settings.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    val accountBusy by vm.accountBusy.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    // Deliberately absent from rememberSaveable, ViewModel, DataStore and logs.
    var key by remember { mutableStateOf("") }
    var account by remember { mutableStateOf(WarpAccountType.Unknown) }
    var message by remember { mutableStateOf<Msg?>(null) }
    var error by remember { mutableStateOf(false) }
    var operation by remember { mutableStateOf<Job?>(null) }
    var consent by remember { mutableStateOf(false) }
    val busy = accountBusy || status.state.busy || operation?.isActive == true

    suspend fun execute(license: String?) {
        error = false
        message = Msg(if (license == null) "warpPlus.loading" else "warpPlus.applying")
        try {
            account = vm.engine.warpAccount(license)
            if (license != null) {
                val confirmed = account == WarpAccountType.Plus || account == WarpAccountType.Unlimited
                message = Msg(if (confirmed) "warpPlus.applied" else "warpPlus.unconfirmed")
                error = !confirmed
            } else message = null
        } catch (e: CancellationException) {
            message = Msg("detail.cancelled")
            throw e
        } catch (e: Exception) {
            account = WarpAccountType.Unknown
            message = (e as? ZarpException)?.msg ?: Msg(if (license == null) "warpPlus.accountFailed" else "warpPlus.applyFailed")
            error = true
        }
    }

    fun apply() {
        if (busy || !WarpAccountType.validLicense(key)) return
        if (!vm.accountRegistered && settings?.tosAccepted != true) { consent = true; return }
        val license = key.trim()
        key = ""
        operation = scope.launch { execute(license) }
    }

    LaunchedEffect(Unit) { if (!vm.engine.accountBusy.value && !status.state.busy) execute(null) }

    if (consent) AlertDialog(
        onDismissRequest = { consent = false },
        title = { Text(L.t("tos.title")) },
        text = { Text(L.t("tos.text")) },
        confirmButton = { TextButton(onClick = {
            consent = false
            val license = key.trim()
            key = ""
            operation = scope.launch { vm.acceptWarpTos(); execute(license) }
        }) { Text(L.t("tos.accept")) } },
        dismissButton = { TextButton(onClick = { consent = false }) { Text(L.t("btn.cancel")) } },
    )

    Column(modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)) {
        SettingsHeader(L.t("warpPlus.title"), back)
        SettingsHint(L.t("warpPlus.hint"))
        Text(L.t("warpPlus.account", L.t("warpPlus." + account.key)), color = Zc.Text)
        OutlinedTextField(
            value = key, onValueChange = { key = it.take(128) }, enabled = !busy,
            label = { Text(L.t("warpPlus.key")) }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
            textStyle = TextStyle(color = Zc.Text, textDirection = TextDirection.Ltr),
            modifier = Modifier.fillMaxWidth(),
        )
        if (key.isNotEmpty() && !WarpAccountType.validLicense(key)) SettingsHint(L.t("warpPlus.invalid"), error = true)
        SettingsHint(L.t("warpPlus.privacy"))
        message?.let { SettingsHint(it.toString(), error) }
        DarkButton(L.t("warpPlus.apply"), ::apply, Modifier.fillMaxWidth(), primary = true,
            enabled = !busy && WarpAccountType.validLicense(key))
        DarkButton(L.t("warpPlus.refresh"), { operation = scope.launch { execute(null) } }, Modifier.fillMaxWidth(), enabled = !busy)
        if (operation?.isActive == true) DarkButton(L.t("btn.cancel"), { operation?.cancel() })
    }
}

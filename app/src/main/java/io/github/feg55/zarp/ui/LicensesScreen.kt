package io.github.feg55.zarp.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.feg55.zarp.core.L
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun LicensesScreen(back: () -> Unit, modifier: Modifier = Modifier) {
    val assets = LocalContext.current.assets
    var files by remember { mutableStateOf(emptyList<String>()) }
    var selected by remember { mutableStateOf<String?>(null) }
    var lines by remember { mutableStateOf(emptyList<String>()) }
    LaunchedEffect(Unit) {
        files = withContext(Dispatchers.IO) { assets.list("licenses").orEmpty().sorted() }
    }
    LaunchedEffect(selected) {
        val file = selected
        lines = if (file == null) emptyList() else withContext(Dispatchers.IO) {
            assets.open("licenses/$file").bufferedReader().use { it.readLines() }
        }
    }
    Column(modifier.fillMaxSize().padding(16.dp)) {
        SettingsHeader(selected ?: L.t("btn.licenses"), { if (selected == null) back() else selected = null })
        if (selected == null) LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(files, key = { it }) { name -> DarkButton(name, { selected = name }, Modifier.fillMaxWidth()) }
        } else LazyColumn {
            items(lines) { line -> Text(line, color = Zc.TextDim, fontFamily = FontFamily.Monospace,
                fontSize = 12.sp, style = TextStyle(textDirection = TextDirection.Ltr)) }
        }
    }
}

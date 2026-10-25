package io.github.feg55.zarp.ui

import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.feg55.zarp.core.L

@Composable
fun LogsScreen(vm: MainViewModel, modifier: Modifier = Modifier) {
    val lines by vm.lines.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()
    val ctx = LocalContext.current
    LaunchedEffect(lines.size) {
        if (lines.isNotEmpty()) listState.scrollToItem(lines.size - 1)
    }
    Column(modifier.fillMaxSize().padding(12.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DarkButton(L.t("btn.copy"), {
                val cm = ctx.getSystemService(ClipboardManager::class.java)
                cm.setPrimaryClip(ClipData.newPlainText("Zarp log", lines.joinToString("\n")))
            })
            DarkButton(L.t("btn.clear"), { vm.log.clear() })
        }
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize().padding(top = 10.dp).clip(RoundedCornerShape(10.dp)).background(Zc.Panel)
                .padding(horizontal = 10.dp, vertical = 8.dp),
        ) {
            items(lines) { line ->
                Text(line, color = Zc.TextDim, fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 15.sp,
                    style = TextStyle(textDirection = TextDirection.Ltr))
            }
        }
    }
}

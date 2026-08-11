package com.winarp.mobile.ui

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Stroke
import com.winarp.mobile.ui.theme.TextSecondary
import java.io.File

@Composable
fun LogsTab(logs: List<String>, logPath: String, onClear: () -> Unit) {
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 8.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Log", color = Color.White, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = {
                try {
                    val file = File(logPath)
                    val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", file)
                    val send = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_STREAM, uri)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    context.startActivity(Intent.createChooser(send, "Export log"))
                } catch (_: Throwable) {
                }
            }) { Text("Export", color = Accent) }
            TextButton(onClick = onClear) { Text("Clear", color = TextSecondary) }
        }
        Text(
            "Full history: $logPath",
            color = TextSecondary,
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace
        )
        Spacer(Modifier.height(6.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(12.dp))
                .background(Color(0xFF0A1020))
                .border(1.dp, Stroke, RoundedCornerShape(12.dp))
                .padding(10.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Text(
                text = logs.joinToString("\n").ifBlank { "No logs yet" },
                color = Color(0xFFB7C7E6),
                fontSize = 11.sp,
                lineHeight = 15.sp,
                fontFamily = FontFamily.Monospace
            )
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "For CTF / authorized sandbox testing only. Disruption features require root.",
            color = TextSecondary,
            style = MaterialTheme.typography.labelSmall
        )
    }
}

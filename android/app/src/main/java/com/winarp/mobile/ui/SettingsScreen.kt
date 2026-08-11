package com.winarp.mobile.ui

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Article
import androidx.compose.material.icons.outlined.ClearAll
import androidx.compose.material.icons.outlined.DeviceHub
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Danger
import com.winarp.mobile.ui.theme.Mint
import com.winarp.mobile.ui.theme.NightBg
import com.winarp.mobile.ui.theme.TextSecondary
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    ifaceLabel: String,
    logPath: String,
    proxyPort: Int,
    autoRestore: Boolean,
    onBack: () -> Unit,
    onRefreshIfaces: () -> Unit,
    onClearLogs: () -> Unit,
    onRestoreNetwork: () -> Unit,
    onProxyPort: (Int) -> Unit,
    onToggleAutoRestore: () -> Unit,
    onExportCa: () -> String?
) {
    val context = LocalContext.current
    Scaffold(
        containerColor = NightBg,
        topBar = {
            TopAppBar(
                navigationIcon = { TextButton(onClick = onBack) { Text("‹ Back", color = Accent) } },
                title = { Text("Settings", fontWeight = FontWeight.Bold, color = Color.White) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = Color.White
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            SectionCard(title = "Network", icon = { Icon(Icons.Outlined.DeviceHub, null, tint = Accent) }) {
                Text(ifaceLabel, color = Color.White)
                Spacer(Modifier.height(8.dp))
                Text(
                    "The ⚙ replaces the old refresh button. Re-detect NICs / IP / gateway here:",
                    color = TextSecondary,
                    style = MaterialTheme.typography.labelMedium
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = onRefreshIfaces,
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Accent)
                ) { Text("Refresh interfaces") }
            }

            SectionCard(title = "Storage & logs", icon = { Icon(Icons.Outlined.Article, null, tint = Mint) }) {
                Text("All logs are written here (survives restarts):", color = TextSecondary, style = MaterialTheme.typography.labelMedium)
                Spacer(Modifier.height(4.dp))
                Text(logPath, color = Color.White, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelSmall)
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            try {
                                val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", File(logPath))
                                val send = Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_STREAM, uri)
                                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                }
                                context.startActivity(Intent.createChooser(send, "Export log"))
                            } catch (_: Throwable) {
                            }
                        },
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent)
                    ) { Text("Export log") }
                    OutlinedButton(onClick = onClearLogs, shape = RoundedCornerShape(12.dp)) { Text("Clear log") }
                }
            }

            SectionCard(title = "Proxy / server", icon = { Icon(Icons.Outlined.DeviceHub, null, tint = Accent) }) {
                OutlinedTextField(
                    value = if (proxyPort == 0) "" else proxyPort.toString(),
                    onValueChange = { s -> onProxyPort(s.filter { it.isDigit() }.take(5).toIntOrNull() ?: 8080) },
                    label = { Text("Local proxy / page-server port") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    colors = winArpFieldColors(),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                FilterChip(
                    selected = autoRestore,
                    onClick = onToggleAutoRestore,
                    label = { Text("Auto-restore network when app closes") },
                    colors = chipColors()
                )
                Text(
                    "When on, closing the app reverts all root network changes automatically.",
                    color = TextSecondary,
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.padding(top = 4.dp)
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    "HTTPS decryption CA. Non-validating IoT/TV apps are decrypted with no client " +
                        "change; to decrypt other (non-pinned) apps, install this CA as trusted on that device.",
                    color = TextSecondary,
                    style = MaterialTheme.typography.labelMedium
                )
                Spacer(Modifier.height(6.dp))
                Button(
                    onClick = {
                        val path = onExportCa() ?: return@Button
                        try {
                            val uri = FileProvider.getUriForFile(context, context.packageName + ".fileprovider", File(path))
                            val send = Intent(Intent.ACTION_SEND).apply {
                                type = "application/x-pem-file"
                                putExtra(Intent.EXTRA_STREAM, uri)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                            context.startActivity(Intent.createChooser(send, "Export MITM CA"))
                        } catch (_: Throwable) {
                        }
                    },
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Mint)
                ) { Text("Export MITM CA (.pem)") }
            }

            SectionCard(title = "Restore / safety", icon = { Icon(Icons.Outlined.ClearAll, null, tint = Danger) }) {
                Text(
                    "Undo every root change this app may have made: IP forwarding, HTTP redirects, " +
                        "per-host bandwidth/latency limits, blocks, and DoT/QUIC blocking. Also stops the " +
                        "sniffer and page server.",
                    color = TextSecondary,
                    style = MaterialTheme.typography.labelMedium
                )
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = onRestoreNetwork,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Danger)
                ) { Text("Restore network (revert all)") }
            }

            SectionCard(title = "About", icon = { Icon(Icons.Outlined.Security, null, tint = TextSecondary) }) {
                Text("WinARP — LAN scan · ARP control", color = Color.White, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                Text(
                    "For CTF / authorized sandbox testing on your own network only. " +
                        "Disruption, MITM and traffic-shaping features require root.",
                    color = TextSecondary,
                    style = MaterialTheme.typography.labelMedium
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

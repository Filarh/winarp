package com.winarp.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.winarp.mobile.data.CapturePeer
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Danger
import com.winarp.mobile.ui.theme.Mint
import com.winarp.mobile.ui.theme.NightBg
import com.winarp.mobile.ui.theme.NightCard
import com.winarp.mobile.ui.theme.NightCardAlt
import com.winarp.mobile.ui.theme.Stroke
import com.winarp.mobile.ui.theme.TextSecondary
import com.winarp.mobile.ui.theme.Warning
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SnifferScreen(
    target: String?,
    running: Boolean,
    peers: List<CapturePeer>,
    raw: List<String>,
    showRaw: Boolean,
    forcePlaintext: Boolean,
    onBack: () -> Unit,
    onToggleCapture: () -> Unit,
    onClear: () -> Unit,
    onToggleRaw: () -> Unit,
    onToggleForcePlaintext: () -> Unit
) {
    Scaffold(
        containerColor = NightBg,
        topBar = {
            TopAppBar(
                navigationIcon = {
                    TextButton(onClick = onBack) { Text("‹ Back", color = Accent) }
                },
                title = {
                    Column {
                        Text("Traffic", fontWeight = FontWeight.Bold, color = Color.White)
                        Text(
                            (target?.let { "target $it" } ?: "all hosts") +
                                if (running) "  ·  live" else "  ·  stopped",
                            style = MaterialTheme.typography.labelMedium,
                            color = if (running) Mint else TextSecondary
                        )
                    }
                },
                actions = {
                    TextButton(onClick = onToggleCapture) {
                        Text(if (running) "Stop" else "Start", color = if (running) Danger else Mint)
                    }
                    TextButton(onClick = onClear) { Text("Clear", color = TextSecondary) }
                },
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
        ) {
            // Grouped peers (clickable, expandable)
            LazyColumn(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                contentPadding = PaddingValues(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        TextButton(onClick = onToggleForcePlaintext) {
                            Text(
                                if (forcePlaintext) "✓ Force plaintext" else "Force plaintext",
                                color = if (forcePlaintext) Mint else Accent
                            )
                        }
                        Text(
                            "block DoT/QUIC → reveal domains",
                            color = TextSecondary,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }
                item {
                    Text(
                        "Peers · ${peers.size}",
                        color = Color.White,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.padding(start = 4.dp, bottom = 2.dp)
                    )
                }
                if (peers.isEmpty()) {
                    item {
                        Text(
                            if (running) "Waiting for traffic… generate activity on the target."
                            else "Stopped. Tap Start to capture.",
                            color = TextSecondary,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                } else {
                    items(peers, key = { it.ip }) { peer -> PeerRow(peer) }
                }
            }

            // The noise: raw packet feed is opt-in (rendering it lags weak devices)
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                TextButton(onClick = onToggleRaw) {
                    Text(
                        if (showRaw) "Hide raw packets" else "Show raw packets",
                        color = Accent
                    )
                }
            }
            if (showRaw) {
                RawPanel(raw)
            }
        }
    }
}

@Composable
private fun PeerRow(peer: CapturePeer) {
    var expanded by remember(peer.ip) { mutableStateOf(false) }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(NightCard)
            .border(1.dp, Stroke, RoundedCornerShape(14.dp))
            .clickable { expanded = !expanded }
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    peer.host ?: peer.ip,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    buildString {
                        if (peer.host != null) append(peer.ip).append("  ·  ")
                        append(sourcesLabel(peer))
                    },
                    color = TextSecondary,
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(fmtBytes(peer.bytes), color = Accent, fontWeight = FontWeight.SemiBold)
                Text("${peer.packets} pkts", color = TextSecondary, style = MaterialTheme.typography.labelMedium)
            }
        }
        if (expanded) {
            Spacer(Modifier.height(8.dp))
            Text("↑ ${fmtBytes(peer.upBytes)}   ↓ ${fmtBytes(peer.downBytes)}", color = TextSecondary, fontSize = 12.sp)
            if (peer.sources.isNotEmpty()) {
                Text("devices: ${peer.sources.joinToString(", ")}", color = Mint, fontSize = 12.sp)
            }
            Spacer(Modifier.height(6.dp))
            peer.endpoints.take(12).forEach { ep ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        "${ep.proto}/${if (ep.port >= 0) ep.port.toString() else "-"}  ${svcName(ep.port)}",
                        color = Warning,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    )
                    Text("${ep.packets} · ${fmtBytes(ep.bytes)}", color = TextSecondary, fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
private fun RawPanel(raw: List<String>) {
    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .height(200.dp)
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Text(
            "Raw packets · ${raw.size}",
            color = TextSecondary,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(bottom = 4.dp)
        )
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .clip(RoundedCornerShape(12.dp))
                .background(Color(0xFF0A1020))
                .border(1.dp, Stroke, RoundedCornerShape(12.dp))
                .padding(8.dp)
                .verticalScroll(scroll)
        ) {
            Text(
                text = raw.takeLast(120).asReversed().joinToString("\n").ifBlank { "…" },
                color = Color(0xFFB7C7E6),
                fontSize = 10.sp,
                lineHeight = 14.sp,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}

private fun sourcesLabel(peer: CapturePeer): String {
    if (peer.sources.isEmpty()) {
        return peer.endpoints.take(3).joinToString("  ") { "${it.proto}/${if (it.port >= 0) it.port else "-"}" }
    }
    val shown = peer.sources.take(2).joinToString(", ")
    val extra = peer.sources.size - 2
    return "from $shown" + if (extra > 0) " +$extra" else ""
}

private fun svcName(port: Int): String = when (port) {
    53 -> "DNS"
    80 -> "HTTP"
    443 -> "HTTPS/QUIC"
    853 -> "DoT"
    123 -> "NTP"
    993 -> "IMAPS"
    995 -> "POP3S"
    5223 -> "Apple-push"
    6881 -> "BitTorrent"
    else -> ""
}

private fun fmtBytes(b: Long): String {
    if (b < 1024) return "$b B"
    val kb = b / 1024.0
    if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format(Locale.US, "%.1f MB", mb)
    return String.format(Locale.US, "%.1f GB", mb / 1024.0)
}

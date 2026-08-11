package com.winarp.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.winarp.mobile.data.SpoofConfig
import com.winarp.mobile.data.SpoofMode
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Danger
import com.winarp.mobile.ui.theme.Mint
import com.winarp.mobile.ui.theme.NightBg
import com.winarp.mobile.ui.theme.NightCardAlt
import com.winarp.mobile.ui.theme.Stroke
import com.winarp.mobile.ui.theme.TextSecondary

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SpoofScreen(
    config: SpoofConfig,
    html: String,
    running: Boolean,
    requests: Int,
    log: List<String>,
    docRootPath: String,
    onBack: () -> Unit,
    onToggle: () -> Unit,
    onMode: (SpoofMode) -> Unit,
    onRedirectUrl: (String) -> Unit,
    onTargetHosts: (String) -> Unit,
    onHtml: (String) -> Unit,
    onToggleCaptive: () -> Unit,
    onToggleSpa: () -> Unit
) {
    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedBorderColor = Accent,
        unfocusedBorderColor = Stroke,
        focusedContainerColor = NightCardAlt,
        unfocusedContainerColor = NightCardAlt,
        cursorColor = Accent,
        focusedLabelColor = Accent,
        unfocusedLabelColor = TextSecondary,
        focusedTextColor = Color.White,
        unfocusedTextColor = Color.White
    )
    Scaffold(
        containerColor = NightBg,
        topBar = {
            TopAppBar(
                navigationIcon = { TextButton(onClick = onBack) { Text("‹ Back", color = Accent) } },
                title = {
                    Column {
                        Text("Spoof page", fontWeight = FontWeight.Bold, color = Color.White)
                        Text(
                            (if (running) "serving · $requests req" else "stopped"),
                            style = MaterialTheme.typography.labelMedium,
                            color = if (running) Mint else TextSecondary
                        )
                    }
                },
                actions = {
                    TextButton(onClick = onToggle) {
                        Text(if (running) "Stop" else "Start", color = if (running) Danger else Mint)
                    }
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
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Spacer(Modifier.height(2.dp))
            Text("Mode", color = Color.White, style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ModeChip("Single page", config.mode == SpoofMode.SINGLE_PAGE) { onMode(SpoofMode.SINGLE_PAGE) }
                ModeChip("Static site", config.mode == SpoofMode.STATIC_SITE) { onMode(SpoofMode.STATIC_SITE) }
                ModeChip("Redirect", config.mode == SpoofMode.REDIRECT) { onMode(SpoofMode.REDIRECT) }
            }

            when (config.mode) {
                SpoofMode.SINGLE_PAGE -> {
                    OutlinedTextField(
                        value = html,
                        onValueChange = onHtml,
                        label = { Text("HTML served for every request") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 160.dp, max = 320.dp),
                        colors = fieldColors,
                        shape = RoundedCornerShape(14.dp)
                    )
                }
                SpoofMode.STATIC_SITE -> {
                    Text(
                        "Serves this folder (drop an imported site or a Vite/React dist here):",
                        color = TextSecondary,
                        style = MaterialTheme.typography.labelMedium
                    )
                    SelectableMono(docRootPath)
                    ToggleChip("SPA fallback (unknown paths → index.html)", config.spaFallback, onToggleSpa)
                }
                SpoofMode.REDIRECT -> {
                    OutlinedTextField(
                        value = config.redirectUrl,
                        onValueChange = onRedirectUrl,
                        label = { Text("Redirect every request to URL") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        colors = fieldColors,
                        shape = RoundedCornerShape(14.dp)
                    )
                }
            }

            OutlinedTextField(
                value = config.targetHosts,
                onValueChange = onTargetHosts,
                label = { Text("Target hosts (comma separated, empty = all HTTP)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                colors = fieldColors,
                shape = RoundedCornerShape(14.dp)
            )

            ToggleChip("Captive-portal assist (pop portal on Apple/Android/Windows)", config.assistCaptivePortal, onToggleCaptive)

            Text(
                "Only HTTP (:80) is intercepted — no cert needed on the client. HTTPS/HSTS sites " +
                    "(e.g. google) can't be substituted without a trusted CA. Needs an active MITM attack.",
                color = TextSecondary,
                style = MaterialTheme.typography.labelSmall
            )

            Text("Requests · $requests", color = Color.White, style = MaterialTheme.typography.titleSmall)
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(180.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(Color(0xFF0A1020))
                    .border(1.dp, Stroke, RoundedCornerShape(12.dp))
                    .padding(8.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    text = log.takeLast(120).asReversed().joinToString("\n").ifBlank { "no requests yet" },
                    color = Color(0xFFB7C7E6),
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun ModeChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label) },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = Accent.copy(alpha = 0.22f),
            selectedLabelColor = Color.White,
            containerColor = NightCardAlt,
            labelColor = TextSecondary
        )
    )
}

@Composable
private fun ToggleChip(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label) },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = Mint.copy(alpha = 0.20f),
            selectedLabelColor = Color.White,
            containerColor = NightCardAlt,
            labelColor = TextSecondary
        )
    )
}

@Composable
private fun SelectableMono(text: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(NightCardAlt)
            .border(1.dp, Stroke, RoundedCornerShape(10.dp))
            .padding(10.dp)
    ) {
        Text(text, color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
    }
}

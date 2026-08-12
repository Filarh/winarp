package com.winarp.mobile.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.NetworkCheck
import androidx.compose.material.icons.outlined.Speed
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.util.Locale
import com.winarp.mobile.data.HostControl
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Danger
import com.winarp.mobile.ui.theme.Mint
import com.winarp.mobile.ui.theme.NightBg
import com.winarp.mobile.ui.theme.Stroke
import com.winarp.mobile.ui.theme.TextSecondary
import com.winarp.mobile.ui.theme.Warning

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostControlScreen(
    ip: String,
    name: String,
    control: HostControl,
    bps: Double,
    onEdit: (String, (HostControl) -> HostControl) -> Unit,
    onApply: () -> Unit,
    onBack: () -> Unit
) {
    Scaffold(
        containerColor = NightBg,
        topBar = {
            TopAppBar(
                navigationIcon = { TextButton(onClick = onBack) { Text("‹ Back", color = Accent) } },
                title = {
                    Column {
                        Text("Traffic limits", fontWeight = FontWeight.Bold, color = Color.White)
                        Text(
                            (if (name.isNotBlank() && name != "-") "$name · " else "") + ip,
                            style = MaterialTheme.typography.labelMedium,
                            color = if (control.active) Warning else TextSecondary
                        )
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
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Spacer(Modifier.height(4.dp))

            SpeedMeter(bps = bps, capKbps = control.kbps)

            LabeledSlider(
                icon = { Icon(Icons.Outlined.Speed, null, tint = Accent) },
                title = "Bandwidth cap",
                valueText = if (control.kbps == 0) "Unlimited"
                else if (control.kbps >= 1000) String.format(java.util.Locale.US, "%.1f Mbps", control.kbps / 1000.0)
                else "${control.kbps} kbps",
                value = control.kbps.toFloat(),
                range = 0f..20000f,
                accent = Accent
            ) { v -> onEdit(ip) { it.copy(kbps = (v / 50).toInt() * 50) } }

            LabeledSlider(
                icon = { Icon(Icons.Outlined.NetworkCheck, null, tint = Mint) },
                title = "Added latency",
                valueText = if (control.delayMs == 0) "None" else "${control.delayMs} ms",
                value = control.delayMs.toFloat(),
                range = 0f..1000f,
                accent = Mint
            ) { v -> onEdit(ip) { it.copy(delayMs = v.toInt()) } }

            LabeledSlider(
                icon = { Icon(Icons.Outlined.Bolt, null, tint = Warning) },
                title = "Packet loss",
                valueText = if (control.lossPct == 0) "None" else "${control.lossPct}%",
                value = control.lossPct.toFloat(),
                range = 0f..100f,
                accent = Warning
            ) { v -> onEdit(ip) { it.copy(lossPct = v.toInt().coerceIn(0, 100)) } }

            SwitchRow(
                title = "Block (cut internet)",
                subtitle = "Drop this device's traffic — others stay online",
                checked = control.blocked,
                onColor = Danger
            ) { onEdit(ip) { it.copy(blocked = !it.blocked) } }

            SwitchRow(
                title = "Proxy HTTP (:80)",
                subtitle = "Route this device's :80 into the local server",
                checked = control.proxied,
                onColor = Mint
            ) { onEdit(ip) { it.copy(proxied = !it.proxied) } }

            Spacer(Modifier.height(4.dp))
            Button(
                onClick = onApply,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Accent)
            ) { Text("Apply") }
            OutlinedButton(
                onClick = { onEdit(ip) { HostControl() }; onApply() },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp)
            ) { Text("Reset this device") }

            Text(
                "Applies while this device is MITM'd (Keep online on). 0 / None = unlimited.",
                color = TextSecondary,
                style = MaterialTheme.typography.labelSmall
            )
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun LabeledSlider(
    icon: @Composable () -> Unit,
    title: String,
    valueText: String,
    value: Float,
    range: ClosedFloatingPointRange<Float>,
    accent: Color,
    onChange: (Float) -> Unit
) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            icon()
            Spacer(Modifier.width(8.dp))
            Text(title, color = Color.White, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Text(valueText, color = accent, fontWeight = FontWeight.SemiBold)
        }
        Slider(
            value = value.coerceIn(range.start, range.endInclusive),
            onValueChange = onChange,
            valueRange = range,
            colors = SliderDefaults.colors(
                thumbColor = accent,
                activeTrackColor = accent,
                inactiveTrackColor = Stroke
            )
        )
    }
}

@Composable
private fun SwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onColor: Color,
    onToggle: () -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, color = Color.White, fontWeight = FontWeight.SemiBold)
            Text(subtitle, color = TextSecondary, style = MaterialTheme.typography.labelMedium)
        }
        Switch(
            checked = checked,
            onCheckedChange = { onToggle() },
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = onColor,
                uncheckedThumbColor = Color.White,
                uncheckedTrackColor = Stroke
            )
        )
    }
}

@Composable
private fun SpeedMeter(bps: Double, capKbps: Int) {
    val shown by animateFloatAsState(bps.toFloat(), label = "spd")
    val capBps = if (capKbps > 0) capKbps * 1000.0 else 0.0
    val frac = if (capBps > 0) (shown / capBps).coerceIn(0f, 1f) else (shown / 1.0e8f).coerceIn(0f, 1f)
    val atCap = capBps > 0 && shown >= capBps * 0.95
    Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Text("Live throughput (real)", color = TextSecondary, style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.height(2.dp))
        val (num, unit) = fmtSpeed(shown.toDouble())
        Row(verticalAlignment = Alignment.Bottom) {
            Text(num, color = if (atCap) Warning else Accent, fontWeight = FontWeight.Bold, fontSize = 44.sp)
            Spacer(Modifier.width(6.dp))
            Text(unit, color = TextSecondary, fontSize = 16.sp, modifier = Modifier.padding(bottom = 8.dp))
        }
        Spacer(Modifier.height(6.dp))
        LinearProgressIndicator(
            progress = { frac },
            modifier = Modifier
                .fillMaxWidth()
                .height(8.dp),
            color = if (atCap) Warning else Accent,
            trackColor = Stroke
        )
        Text(
            if (capKbps > 0) "capped at " + (if (capKbps >= 1000) String.format(Locale.US, "%.1f Mbps", capKbps / 1000.0) else "$capKbps kbps")
            else "no cap — set a bandwidth limit below and Apply",
            color = TextSecondary,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(top = 4.dp)
        )
    }
}

private fun fmtSpeed(bps: Double): Pair<String, String> = when {
    bps >= 1_000_000 -> String.format(Locale.US, "%.1f", bps / 1_000_000) to "Mbps"
    bps >= 1000 -> String.format(Locale.US, "%.0f", bps / 1000) to "kbps"
    else -> String.format(Locale.US, "%.0f", bps) to "bps"
}

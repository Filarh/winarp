package com.winarp.mobile.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.WifiFind
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.SelectableChipColors
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextFieldColors
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.winarp.mobile.data.HostInfo
import com.winarp.mobile.data.RootState
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Danger
import com.winarp.mobile.ui.theme.Mint
import com.winarp.mobile.ui.theme.NightCard
import com.winarp.mobile.ui.theme.NightCardAlt
import com.winarp.mobile.ui.theme.Stroke
import com.winarp.mobile.ui.theme.TextSecondary
import com.winarp.mobile.ui.theme.Warning

/**
 * Shared, reusable UI building blocks — one definition used across every tab so screens stay small
 * and consistent (no per-screen copies).
 */

@Composable
fun winArpFieldColors(): TextFieldColors = OutlinedTextFieldDefaults.colors(
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

@Composable
fun chipColors(): SelectableChipColors = FilterChipDefaults.filterChipColors(
    selectedContainerColor = Accent.copy(alpha = 0.22f),
    selectedLabelColor = Color.White,
    containerColor = NightCardAlt,
    labelColor = TextSecondary
)

@Composable
fun RootBadge(state: RootState) {
    val (text, color) = when (state) {
        RootState.Available -> "ROOT" to Mint
        RootState.Denied -> "DENIED" to Warning
        RootState.Missing -> "NO ROOT" to Danger
        RootState.Unknown -> "ROOT?" to TextSecondary
    }
    Box(
        modifier = Modifier
            .padding(end = 4.dp)
            .clip(RoundedCornerShape(999.dp))
            .background(color.copy(alpha = 0.15f))
            .border(1.dp, color.copy(alpha = 0.5f), RoundedCornerShape(999.dp))
            .padding(horizontal = 10.dp, vertical = 5.dp)
    ) {
        Text(text, color = color, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun StatusHero(
    status: String,
    scanning: Boolean,
    attacking: Boolean,
    progress: Pair<Int, Int>?,
    nativeLoaded: Boolean
) {
    val glow by animateColorAsState(
        when {
            attacking -> Danger.copy(alpha = 0.35f)
            scanning -> Accent.copy(alpha = 0.30f)
            else -> Mint.copy(alpha = 0.18f)
        },
        label = "glow"
    )
    Card(
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = NightCard),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, glow, RoundedCornerShape(22.dp))
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(
                            when {
                                attacking -> Danger
                                scanning -> Accent
                                else -> Mint
                            }
                        )
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    status,
                    color = Color.White,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(Modifier.height(10.dp))
            if (progress != null && progress.second > 0) {
                LinearProgressIndicator(
                    progress = { progress.first.toFloat() / progress.second.toFloat() },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp)
                        .clip(RoundedCornerShape(99.dp)),
                    color = Accent,
                    trackColor = Stroke
                )
                Spacer(Modifier.height(8.dp))
            }
            Text(
                if (nativeLoaded) "Native ARP engine ready" else "Native engine not loaded",
                color = TextSecondary,
                style = MaterialTheme.typography.labelMedium
            )
        }
    }
}

@Composable
fun SectionCard(
    title: String,
    icon: @Composable () -> Unit,
    action: @Composable (() -> Unit)? = null,
    content: @Composable () -> Unit
) {
    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = NightCard),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Stroke.copy(alpha = 0.7f), RoundedCornerShape(20.dp))
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                icon()
                Spacer(Modifier.width(8.dp))
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.White,
                    modifier = Modifier.weight(1f)
                )
                action?.invoke()
            }
            Spacer(Modifier.height(12.dp))
            content()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IfaceSelector(state: MainUiState, onSelectIface: (Int) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val label = state.selectedIface?.toString() ?: "No NIC found"
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = label,
            onValueChange = {},
            readOnly = true,
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(),
            label = { Text("Select NIC") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
            colors = winArpFieldColors(),
            shape = RoundedCornerShape(14.dp)
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            state.ifaces.forEachIndexed { index, iface ->
                DropdownMenuItem(
                    text = { Text(iface.toString()) },
                    onClick = {
                        onSelectIface(index)
                        expanded = false
                    }
                )
            }
        }
    }
}

/**
 * Central, prominent MITM control. ON (default) = victim keeps internet and its traffic is routed
 * through us (feeds Sniff/Spoof). OFF = cutoff: the target loses internet. Reused wherever the
 * attack is configured so the meaning/warning is defined in exactly one place.
 */
@Composable
fun MitmControl(on: Boolean, onToggle: (Boolean) -> Unit) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = NightCard),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, if (on) Mint.copy(alpha = 0.5f) else Danger.copy(alpha = 0.6f), RoundedCornerShape(18.dp))
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Keep target online (MITM)", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Text(
                        if (on) "Routes traffic through this device (feeds Sniff / Spoof)"
                        else "Cutoff mode — no data is collected",
                        color = TextSecondary,
                        style = MaterialTheme.typography.labelMedium
                    )
                }
                Switch(
                    checked = on,
                    onCheckedChange = onToggle,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = Mint,
                        uncheckedThumbColor = Color.White,
                        uncheckedTrackColor = Danger
                    )
                )
            }
            if (!on) {
                Spacer(Modifier.height(10.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(Danger.copy(alpha = 0.14f))
                        .border(1.dp, Danger.copy(alpha = 0.5f), RoundedCornerShape(10.dp))
                        .padding(10.dp)
                ) {
                    Text(
                        "⚠ Warning: with this OFF the target loses internet (cutoff / DoS).",
                        color = Danger,
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.labelMedium
                    )
                }
            }
        }
    }
}

/** Inline explanation shown under a disabled control so nothing is ever blocked without a why. */
@Composable
fun WhyDisabled(label: String, reason: String?) {
    if (reason == null) return
    Text(
        "ⓘ $label unavailable — $reason",
        color = Warning,
        style = MaterialTheme.typography.labelSmall,
        modifier = Modifier.padding(top = 4.dp, start = 4.dp)
    )
}

@Composable
fun MiniMetric(title: String, value: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(NightCardAlt)
            .border(1.dp, Stroke, RoundedCornerShape(14.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        Text(title, color = TextSecondary, style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.height(2.dp))
        Text(
            value,
            color = Color.White,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
fun HostRow(host: HostInfo, selected: Boolean, onToggle: () -> Unit) {
    val border = if (selected) Accent else Stroke
    val bg = if (selected) Accent.copy(alpha = 0.12f) else NightCard
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = bg),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, border, RoundedCornerShape(16.dp))
            .clickable { onToggle() }
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(
                checked = selected,
                onCheckedChange = { onToggle() },
                colors = CheckboxDefaults.colors(checkedColor = Accent, uncheckedColor = TextSecondary)
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 8.dp)
            ) {
                Text(text = host.ip, color = Color.White, fontWeight = FontWeight.SemiBold)
                Text(text = host.mac, color = TextSecondary, style = MaterialTheme.typography.bodyMedium)
            }
            Text(
                text = host.name.ifBlank { "-" },
                color = if (host.name != "-" && host.name.isNotBlank()) Mint else TextSecondary,
                style = MaterialTheme.typography.labelLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun EmptyHosts() {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = NightCard),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Stroke, RoundedCornerShape(16.dp))
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .padding(22.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(Icons.Outlined.WifiFind, null, tint = TextSecondary, modifier = Modifier.size(28.dp))
            Spacer(Modifier.height(8.dp))
            Text("No devices", color = Color.White, fontWeight = FontWeight.SemiBold)
            Text("Connect Wi-Fi, then tap Scan LAN", color = TextSecondary, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

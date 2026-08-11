package com.winarp.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.winarp.mobile.data.HostControl
import com.winarp.mobile.data.HostInfo
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Danger
import com.winarp.mobile.ui.theme.Mint
import com.winarp.mobile.ui.theme.TextSecondary
import com.winarp.mobile.ui.theme.Warning

/** A scanned device: the selectable row plus its expandable per-host traffic controls. */
@Composable
fun DeviceItem(
    host: HostInfo,
    selected: Boolean,
    control: HostControl,
    onToggleSelect: () -> Unit,
    onEdit: (String, (HostControl) -> HostControl) -> Unit
) {
    Column {
        HostRow(host = host, selected = selected, onToggle = onToggleSelect)
        HostControlsPanel(host, control, onEdit)
    }
}

@Composable
private fun HostControlsPanel(
    host: HostInfo,
    c: HostControl,
    onEdit: (String, (HostControl) -> HostControl) -> Unit
) {
    var expanded by remember(host.ip) { mutableStateOf(false) }
    val summary = buildList {
        if (c.kbps > 0) add("${c.kbps} kbps")
        if (c.delayMs > 0) add("${c.delayMs}ms")
        if (c.lossPct > 0) add("${c.lossPct}% loss")
        if (c.blocked) add("blocked")
        if (c.proxied) add("proxied")
    }.joinToString(" · ")

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 8.dp, end = 4.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
    ) {
        TextButton(onClick = { expanded = !expanded }) {
            Text(if (expanded) "limits ▴" else "limits ▾", color = Accent, fontSize = 12.sp)
        }
        if (summary.isNotEmpty()) {
            Text(summary, color = if (c.blocked) Danger else Warning, fontSize = 12.sp)
        }
    }

    if (expanded) {
        Column(modifier = Modifier.padding(start = 8.dp, end = 8.dp, bottom = 6.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                NumberField("kbps", c.kbps, Modifier.weight(1f)) { v -> onEdit(host.ip) { it.copy(kbps = v) } }
                NumberField("lag ms", c.delayMs, Modifier.weight(1f)) { v -> onEdit(host.ip) { it.copy(delayMs = v) } }
                NumberField("loss %", c.lossPct.coerceIn(0, 100), Modifier.weight(1f)) { v -> onEdit(host.ip) { it.copy(lossPct = v.coerceIn(0, 100)) } }
            }
            Spacer(Modifier.height(6.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = c.blocked,
                    onClick = { onEdit(host.ip) { it.copy(blocked = !it.blocked) } },
                    label = { Text("Block (cut internet)") },
                    colors = chipColors()
                )
                FilterChip(
                    selected = c.proxied,
                    onClick = { onEdit(host.ip) { it.copy(proxied = !it.proxied) } },
                    label = { Text("Proxy :80") },
                    colors = chipColors()
                )
            }
            Text(
                "Tip: 0 = unlimited. Tap “Apply limits” below to push changes. Needs MITM on for this host.",
                color = TextSecondary,
                fontSize = 11.sp,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }
}

@Composable
private fun NumberField(label: String, value: Int, modifier: Modifier = Modifier, onValue: (Int) -> Unit) {
    OutlinedTextField(
        value = if (value == 0) "" else value.toString(),
        onValueChange = { s -> onValue(s.filter { it.isDigit() }.take(7).toIntOrNull() ?: 0) },
        label = { Text(label, fontSize = 11.sp) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        colors = winArpFieldColors(),
        shape = RoundedCornerShape(12.dp),
        modifier = modifier
    )
}

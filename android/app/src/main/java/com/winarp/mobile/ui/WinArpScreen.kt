package com.winarp.mobile.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.ClearAll
import androidx.compose.material.icons.outlined.DeviceHub
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.StopCircle
import androidx.compose.material.icons.outlined.WifiFind
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.winarp.mobile.data.HostInfo
import com.winarp.mobile.data.RootState
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Danger
import com.winarp.mobile.ui.theme.Mint
import com.winarp.mobile.ui.theme.NightBg
import com.winarp.mobile.ui.theme.NightCard
import com.winarp.mobile.ui.theme.NightCardAlt
import com.winarp.mobile.ui.theme.Stroke
import com.winarp.mobile.ui.theme.TextSecondary
import com.winarp.mobile.ui.theme.Warning

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun WinArpScreen(
    state: MainUiState,
    onRefreshIfaces: () -> Unit,
    onSelectIface: (Int) -> Unit,
    onCidr: (String) -> Unit,
    onWorkers: (String) -> Unit,
    onInterval: (String) -> Unit,
    onGateway: (String) -> Unit,
    onTarget: (String) -> Unit,
    onFrom: (String) -> Unit,
    onTo: (String) -> Unit,
    onResolveName: (Boolean) -> Unit,
    onOneWay: (Boolean) -> Unit,
    onToggleMitm: (Boolean) -> Unit,
    onOpenSniffer: () -> Unit,
    onOpenSpoof: () -> Unit,
    onScan: () -> Unit,
    onSelectAll: (Boolean) -> Unit,
    onToggleHost: (String) -> Unit,
    onAttackSelected: () -> Unit,
    onAttackRange: () -> Unit,
    onStop: () -> Unit,
    onClearLog: () -> Unit
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
                title = {
                    Column {
                        Text(
                            "WinARP",
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                        Text(
                            "LAN Scan · ARP Control",
                            style = MaterialTheme.typography.labelMedium,
                            color = TextSecondary
                        )
                    }
                },
                actions = {
                    RootBadge(state.rootState)
                    IconButton(onClick = onRefreshIfaces) {
                        Icon(Icons.Outlined.Refresh, contentDescription = "Refresh", tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = Color.White
                )
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(
                    Brush.verticalGradient(
                        listOf(NightBg, Color(0xFF0E1730), NightBg)
                    )
                ),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                StatusHero(
                    status = state.status,
                    scanning = state.scanning,
                    attacking = state.attacking,
                    progress = state.scanProgress,
                    nativeLoaded = state.nativeLoaded
                )
            }

            item {
                SectionCard(title = "Network Interface", icon = {
                    Icon(Icons.Outlined.DeviceHub, null, tint = Accent)
                }) {
                    IfaceSelector(
                        state = state,
                        onSelectIface = onSelectIface,
                        fieldColors = fieldColors
                    )
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        MiniMetric("Local IP", state.selectedIface?.ip ?: "-", Modifier.weight(1f))
                        MiniMetric("MAC", state.selectedIface?.mac ?: "-", Modifier.weight(1f))
                    }
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        MiniMetric("Gateway", state.gateway.ifBlank { "-" }, Modifier.weight(1f))
                        MiniMetric("Subnet", state.cidr.ifBlank { "-" }, Modifier.weight(1f))
                    }
                }
            }

            item {
                SectionCard(title = "Scan Parameters", icon = {
                    Icon(Icons.Outlined.WifiFind, null, tint = Mint)
                }) {
                    OutlinedTextField(
                        value = state.cidr,
                        onValueChange = onCidr,
                        label = { Text("Scan range (CIDR)") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = fieldColors,
                        shape = RoundedCornerShape(14.dp)
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = state.workers,
                            onValueChange = onWorkers,
                            label = { Text("Threads") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            colors = fieldColors,
                            shape = RoundedCornerShape(14.dp)
                        )
                        OutlinedTextField(
                            value = state.intervalMs,
                            onValueChange = onInterval,
                            label = { Text("Interval ms") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                            colors = fieldColors,
                            shape = RoundedCornerShape(14.dp)
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = state.gateway,
                        onValueChange = onGateway,
                        label = { Text("Gateway IP") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = fieldColors,
                        shape = RoundedCornerShape(14.dp)
                    )
                    Spacer(Modifier.height(8.dp))
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = state.resolveName,
                            onClick = { onResolveName(!state.resolveName) },
                            label = { Text("Resolve device name") },
                            colors = chipColors()
                        )
                        FilterChip(
                            selected = state.oneWay,
                            onClick = { onOneWay(!state.oneWay) },
                            label = { Text("One-way poison only") },
                            colors = chipColors()
                        )
                        FilterChip(
                            selected = state.forwardMitm,
                            onClick = { onToggleMitm(!state.forwardMitm) },
                            label = { Text("Keep online (MITM)") },
                            colors = chipColors()
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = onScan,
                            enabled = !state.scanning && !state.attacking,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Accent)
                        ) {
                            if (state.scanning) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp,
                                    color = Color.White
                                )
                                Spacer(Modifier.width(8.dp))
                            }
                            Text("Scan LAN")
                        }
                        OutlinedButton(
                            onClick = { onSelectAll(true) },
                            enabled = state.hosts.isNotEmpty(),
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(14.dp)
                        ) { Text("Select all") }
                    }
                }
            }

            item {
                SectionCard(title = "Target IP / range", icon = {
                    Icon(Icons.Outlined.Bolt, null, tint = Warning)
                }) {
                    OutlinedTextField(
                        value = state.targetSpec,
                        onValueChange = onTarget,
                        label = { Text("Target list / range e.g. 192.168.1.10-20") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = fieldColors,
                        shape = RoundedCornerShape(14.dp)
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = state.fromIp,
                            onValueChange = onFrom,
                            label = { Text("From") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            colors = fieldColors,
                            shape = RoundedCornerShape(14.dp)
                        )
                        OutlinedTextField(
                            value = state.toIp,
                            onValueChange = onTo,
                            label = { Text("To") },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            colors = fieldColors,
                            shape = RoundedCornerShape(14.dp)
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = onAttackSelected,
                            enabled = !state.scanning && !state.attacking && state.selectedHostIps.isNotEmpty(),
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Danger)
                        ) { Text("Attack selected") }
                        Button(
                            onClick = onAttackRange,
                            enabled = !state.scanning && !state.attacking,
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(14.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE0673D))
                        ) { Text("Attack IP range") }
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onStop,
                        enabled = state.attacking,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Icon(Icons.Outlined.StopCircle, null)
                        Spacer(Modifier.width(6.dp))
                        Text("Stop & restore")
                    }
                    Spacer(Modifier.height(8.dp))
                    Button(
                        onClick = onOpenSniffer,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Mint)
                    ) {
                        Icon(Icons.Outlined.WifiFind, null)
                        Spacer(Modifier.width(6.dp))
                        Text("Live traffic (sniffer)")
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onOpenSpoof,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Icon(Icons.Outlined.Bolt, null)
                        Spacer(Modifier.width(6.dp))
                        Text("Spoof page (fake page / captive portal)")
                    }
                }
            }

            item {
                Text(
                    "Devices · ${state.hosts.size}",
                    style = MaterialTheme.typography.titleMedium,
                    color = Color.White,
                    modifier = Modifier.padding(top = 4.dp, start = 4.dp)
                )
            }

            if (state.hosts.isEmpty()) {
                item {
                    EmptyHosts()
                }
            } else {
                items(state.hosts, key = { it.ip }) { host ->
                    HostRow(
                        host = host,
                        selected = host.ip in state.selectedHostIps,
                        onToggle = { onToggleHost(host.ip) }
                    )
                }
            }

            item {
                SectionCard(title = "Log", icon = {
                    Icon(Icons.Outlined.Security, null, tint = TextSecondary)
                }, action = {
                    IconButton(onClick = onClearLog) {
                        Icon(Icons.Outlined.ClearAll, "Clear", tint = TextSecondary)
                    }
                }) {
                    val scroll = rememberScrollState()
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 160.dp, max = 240.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(Color(0xFF0A1020))
                            .border(1.dp, Stroke, RoundedCornerShape(12.dp))
                            .padding(10.dp)
                            .verticalScroll(scroll)
                    ) {
                        Text(
                            text = state.logs.joinToString("\n").ifBlank { "No logs yet" },
                            color = Color(0xFFB7C7E6),
                            fontSize = 11.sp,
                            lineHeight = 15.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }

            item {
                Text(
                    "For CTF / authorized sandbox testing only. Disruption features require root.",
                    color = TextSecondary,
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(bottom = 24.dp, start = 4.dp, end = 4.dp)
                )
            }
        }
    }
}

@Composable
private fun chipColors() = FilterChipDefaults.filterChipColors(
    selectedContainerColor = Accent.copy(alpha = 0.22f),
    selectedLabelColor = Color.White,
    containerColor = NightCardAlt,
    labelColor = TextSecondary
)

@Composable
private fun RootBadge(state: RootState) {
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
private fun StatusHero(
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
private fun SectionCard(
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
private fun IfaceSelector(
    state: MainUiState,
    onSelectIface: (Int) -> Unit,
    fieldColors: androidx.compose.material3.TextFieldColors
) {
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
            colors = fieldColors,
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

@Composable
private fun MiniMetric(title: String, value: String, modifier: Modifier = Modifier) {
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
private fun HostRow(host: HostInfo, selected: Boolean, onToggle: () -> Unit) {
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
                colors = CheckboxDefaults.colors(
                    checkedColor = Accent,
                    uncheckedColor = TextSecondary
                )
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
private fun EmptyHosts() {
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

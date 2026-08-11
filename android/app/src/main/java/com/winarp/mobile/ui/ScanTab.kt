package com.winarp.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.DeviceHub
import androidx.compose.material.icons.outlined.WifiFind
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.Mint

@Composable
fun ScanTab(
    state: MainUiState,
    onSelectIface: (Int) -> Unit,
    onCidr: (String) -> Unit,
    onWorkers: (String) -> Unit,
    onInterval: (String) -> Unit,
    onResolveName: (Boolean) -> Unit,
    onScan: () -> Unit,
    onSelectAll: (Boolean) -> Unit,
    onToggleHost: (String) -> Unit
) {
    val fieldColors = winArpFieldColors()
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            StatusHero(state.status, state.scanning, state.attacking, state.scanProgress, state.nativeLoaded)
        }
        item {
            SectionCard(title = "Network Interface", icon = { Icon(Icons.Outlined.DeviceHub, null, tint = Accent) }) {
                IfaceSelector(state, onSelectIface)
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
            SectionCard(title = "Scan Parameters", icon = { Icon(Icons.Outlined.WifiFind, null, tint = Mint) }) {
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
                FilterChip(
                    selected = state.resolveName,
                    onClick = { onResolveName(!state.resolveName) },
                    label = { Text("Resolve device name") },
                    colors = chipColors()
                )
                Spacer(Modifier.height(12.dp))
                val scanReason = Gate.scan(state)
                val selectAllReason = Gate.selectAll(state)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onScan,
                        enabled = scanReason == null,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent)
                    ) {
                        if (state.scanning) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.White)
                            Spacer(Modifier.width(8.dp))
                        }
                        Text("Scan LAN")
                    }
                    OutlinedButton(
                        onClick = { onSelectAll(true) },
                        enabled = selectAllReason == null,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp)
                    ) { Text("Select all") }
                }
                WhyDisabled("Scan LAN", scanReason)
                WhyDisabled("Select all", selectAllReason)
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
            item { EmptyHosts() }
        } else {
            items(state.hosts, key = { it.ip }) { host ->
                HostRow(host = host, selected = host.ip in state.selectedHostIps, onToggle = { onToggleHost(host.ip) })
            }
        }
    }
}

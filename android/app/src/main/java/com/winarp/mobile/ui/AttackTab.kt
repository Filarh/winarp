package com.winarp.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.StopCircle
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.winarp.mobile.ui.theme.Danger
import com.winarp.mobile.ui.theme.TextSecondary
import com.winarp.mobile.ui.theme.Warning

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AttackTab(
    state: MainUiState,
    onGateway: (String) -> Unit,
    onTarget: (String) -> Unit,
    onFrom: (String) -> Unit,
    onTo: (String) -> Unit,
    onOneWay: (Boolean) -> Unit,
    onToggleMitm: (Boolean) -> Unit,
    onAttackSelected: () -> Unit,
    onAttackRange: () -> Unit,
    onStop: () -> Unit
) {
    val fieldColors = winArpFieldColors()
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            StatusHero(state.status, state.scanning, state.attacking, state.scanProgress, state.nativeLoaded)
        }
        item {
            SectionCard(title = "Target IP / range", icon = { Icon(Icons.Outlined.Bolt, null, tint = Warning) }) {
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
                Spacer(Modifier.height(10.dp))
                MitmControl(on = state.forwardMitm, onToggle = onToggleMitm)
                Spacer(Modifier.height(8.dp))
                FilterChip(
                    selected = state.oneWay,
                    onClick = { onOneWay(!state.oneWay) },
                    label = { Text("One-way poison only") },
                    colors = chipColors()
                )
                Spacer(Modifier.height(12.dp))
                val selReason = Gate.attackSelected(state)
                val rangeReason = Gate.attackRange(state)
                val stopReason = Gate.stop(state)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onAttackSelected,
                        enabled = selReason == null,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Danger)
                    ) { Text("Attack selected") }
                    Button(
                        onClick = onAttackRange,
                        enabled = rangeReason == null,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE0673D))
                    ) { Text("Attack IP range") }
                }
                WhyDisabled("Attack selected", selReason)
                WhyDisabled("Attack IP range", rangeReason)
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onStop,
                    enabled = stopReason == null,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp)
                ) {
                    Icon(Icons.Outlined.StopCircle, null)
                    Spacer(Modifier.width(6.dp))
                    Text("Stop & restore")
                }
                WhyDisabled("Stop & restore", stopReason)
            }
        }
        item {
            Text(
                "Select devices on the Scan tab, or set a gateway + target here. " +
                    "Enable Keep online (MITM) to route (feeds Sniff/Spoof); leave it off to cut the target.",
                color = TextSecondary,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(horizontal = 4.dp)
            )
        }
    }
}

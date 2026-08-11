package com.winarp.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Article
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.WifiFind
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.winarp.mobile.data.Tab
import com.winarp.mobile.ui.theme.Accent
import com.winarp.mobile.ui.theme.NightBg
import com.winarp.mobile.ui.theme.NightCard
import com.winarp.mobile.ui.theme.TextSecondary

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WinArpRoot(vm: MainViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    if (state.showSettings) {
        SettingsScreen(
            ifaceLabel = state.selectedIface?.toString() ?: "No NIC selected",
            logPath = vm.logFilePath(),
            onBack = vm::closeSettings,
            onRefreshIfaces = vm::refreshIfaces,
            onClearLogs = vm::clearLogs,
            onRestoreNetwork = vm::restoreNetwork
        )
        return
    }
    Scaffold(
        containerColor = NightBg,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("WinARP", fontWeight = FontWeight.Bold, color = Color.White)
                        Text("LAN Scan · ARP Control", style = MaterialTheme.typography.labelMedium, color = TextSecondary)
                    }
                },
                actions = {
                    RootBadge(state.rootState)
                    IconButton(onClick = vm::openSettings) {
                        Icon(Icons.Outlined.Settings, contentDescription = "Settings", tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = Color.White
                )
            )
        },
        bottomBar = { BottomNav(state.tab, vm::selectTab) }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(Brush.verticalGradient(listOf(NightBg, Color(0xFF0E1730), NightBg)))
        ) {
            when (state.tab) {
                Tab.Scan -> ScanTab(
                    state = state,
                    onSelectIface = vm::selectIface,
                    onCidr = vm::updateCidr,
                    onWorkers = vm::updateWorkers,
                    onInterval = vm::updateInterval,
                    onResolveName = vm::updateResolveName,
                    onScan = vm::scan,
                    onSelectAll = vm::selectAllHosts,
                    onToggleHost = vm::toggleHost,
                    hostControls = state.hostControls,
                    onEditControl = vm::editHostControl,
                    onApplyControls = vm::applyHostControls,
                    onClearControls = vm::clearHostControls
                )

                Tab.Attack -> AttackTab(
                    state = state,
                    onGateway = vm::updateGateway,
                    onTarget = vm::updateTargetSpec,
                    onFrom = vm::updateFromIp,
                    onTo = vm::updateToIp,
                    onOneWay = vm::updateOneWay,
                    onToggleMitm = vm::updateForwardMitm,
                    onAttackSelected = vm::attackSelected,
                    onAttackRange = vm::attackRange,
                    onStop = vm::stopAttack
                )

                Tab.Sniff -> {
                    val peers by vm.capturePeers.collectAsStateWithLifecycle()
                    val raw by vm.captureRaw.collectAsStateWithLifecycle()
                    val running by vm.captureRunning.collectAsStateWithLifecycle()
                    val ctarget by vm.captureTarget.collectAsStateWithLifecycle()
                    SniffTab(
                        target = ctarget,
                        running = running,
                        peers = peers,
                        raw = raw,
                        showRaw = state.showRaw,
                        forcePlaintext = state.forcePlaintext,
                        onToggleCapture = vm::toggleCapture,
                        onClear = vm::clearCapture,
                        onToggleRaw = vm::toggleRaw,
                        onToggleForcePlaintext = vm::toggleForcePlaintext
                    )
                }

                Tab.Spoof -> {
                    val srunning by vm.webRunning.collectAsStateWithLifecycle()
                    val requests by vm.webRequests.collectAsStateWithLifecycle()
                    val wlog by vm.webLog.collectAsStateWithLifecycle()
                    SpoofTab(
                        config = state.spoofConfig,
                        html = state.spoofHtml,
                        running = srunning,
                        requests = requests,
                        log = wlog,
                        docRootPath = vm.spoofDocRootPath(),
                        onToggle = vm::toggleSpoof,
                        onMode = vm::updateSpoofMode,
                        onRedirectUrl = vm::updateRedirectUrl,
                        onTargetHosts = vm::updateTargetHosts,
                        onHtml = vm::updateSpoofHtml,
                        onToggleCaptive = vm::toggleCaptive,
                        onToggleSpa = vm::toggleSpa
                    )
                }

                Tab.Logs -> LogsTab(
                    logs = state.logs,
                    logPath = vm.logFilePath(),
                    onClear = vm::clearLogs
                )
            }
        }
    }
}

private data class NavItem(val tab: Tab, val icon: ImageVector, val label: String)

@Composable
private fun BottomNav(current: Tab, onSelect: (Tab) -> Unit) {
    val items = listOf(
        NavItem(Tab.Scan, Icons.Outlined.WifiFind, "Scan"),
        NavItem(Tab.Attack, Icons.Outlined.Bolt, "Attack"),
        NavItem(Tab.Sniff, Icons.Outlined.Visibility, "Sniff"),
        NavItem(Tab.Spoof, Icons.Outlined.Language, "Spoof"),
        NavItem(Tab.Logs, Icons.Outlined.Article, "Logs")
    )
    NavigationBar(containerColor = NightCard) {
        items.forEach { item ->
            NavigationBarItem(
                selected = current == item.tab,
                onClick = { onSelect(item.tab) },
                icon = { Icon(item.icon, contentDescription = item.label) },
                label = { Text(item.label) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Accent,
                    selectedTextColor = Accent,
                    indicatorColor = Accent.copy(alpha = 0.18f),
                    unselectedIconColor = TextSecondary,
                    unselectedTextColor = TextSecondary
                )
            )
        }
    }
}

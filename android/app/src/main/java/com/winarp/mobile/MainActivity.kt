package com.winarp.mobile

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.winarp.mobile.data.AppScreen
import com.winarp.mobile.ui.MainViewModel
import com.winarp.mobile.ui.SnifferScreen
import com.winarp.mobile.ui.WinArpScreen
import com.winarp.mobile.ui.theme.NightBg
import com.winarp.mobile.ui.theme.WinArpTheme

class MainActivity : ComponentActivity() {
    private val vm: MainViewModel by viewModels()

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        vm.refreshIfaces()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        requestNeededPermissions()

        setContent {
            WinArpTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = NightBg) {
                    val state by vm.state.collectAsStateWithLifecycle()
                    when (state.screen) {
                        AppScreen.Sniffer -> {
                            val peers by vm.capturePeers.collectAsStateWithLifecycle()
                            val raw by vm.captureRaw.collectAsStateWithLifecycle()
                            val running by vm.captureRunning.collectAsStateWithLifecycle()
                            val target by vm.captureTarget.collectAsStateWithLifecycle()
                            SnifferScreen(
                                target = target,
                                running = running,
                                peers = peers,
                                raw = raw,
                                onBack = vm::closeSniffer,
                                onToggleCapture = vm::toggleCapture,
                                onClear = vm::clearCapture
                            )
                        }

                        AppScreen.Main -> WinArpScreen(
                            state = state,
                            onRefreshIfaces = vm::refreshIfaces,
                            onSelectIface = vm::selectIface,
                            onCidr = vm::updateCidr,
                            onWorkers = vm::updateWorkers,
                            onInterval = vm::updateInterval,
                            onGateway = vm::updateGateway,
                            onTarget = vm::updateTargetSpec,
                            onFrom = vm::updateFromIp,
                            onTo = vm::updateToIp,
                            onResolveName = vm::updateResolveName,
                            onOneWay = vm::updateOneWay,
                            onToggleMitm = vm::updateForwardMitm,
                            onOpenSniffer = vm::openSniffer,
                            onScan = vm::scan,
                            onSelectAll = vm::selectAllHosts,
                            onToggleHost = vm::toggleHost,
                            onAttackSelected = vm::attackSelected,
                            onAttackRange = vm::attackRange,
                            onStop = vm::stopAttack,
                            onClearLog = vm::clearLogs
                        )
                    }
                }
            }
        }
    }

    private fun requestNeededPermissions() {
        val need = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // nearby wifi devices for better iface discovery on new Android
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES)
                != PackageManager.PERMISSION_GRANTED
            ) {
                need += Manifest.permission.NEARBY_WIFI_DEVICES
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED
            ) {
                need += Manifest.permission.ACCESS_FINE_LOCATION
            }
        }
        if (need.isNotEmpty()) {
            permissionLauncher.launch(need.toTypedArray())
        }
    }
}

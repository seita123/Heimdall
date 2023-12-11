package de.tomcory.heimdall.ui.scanner.traffic

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import de.tomcory.heimdall.core.proxy.HeimdallHttpProxyServer
import de.tomcory.heimdall.core.proxy.littleshoot.mitm.CertificateSniffingMitmManager
import de.tomcory.heimdall.core.vpn.mitm.Authority
import de.tomcory.heimdall.service.HeimdallVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.net.InetSocketAddress
import javax.inject.Inject

@HiltViewModel
class TrafficScannerViewModel @Inject constructor(
    @SuppressLint("StaticFieldLeak") @ApplicationContext private val context: Context,
    private val repository: TrafficScannerRepository
) : ViewModel() {

    val scanActiveInitial = false
    val scanSetupInitial = false
    val lastUpdatedInitial = 0L

    private var proxyServer: HeimdallHttpProxyServer? = null

    // State variables
    private val _scanActive = MutableStateFlow(scanActiveInitial)
    val scanActive = _scanActive.asStateFlow()

    private val _scanSetup = MutableStateFlow(scanSetupInitial)
    val scanSetup = _scanSetup.asStateFlow()

    val lastUpdated = repository.vpnLastUpdated

    private val _vpnPermissionRequestEvent = MutableSharedFlow<Unit>()
    val vpnPermissionRequestEvent = _vpnPermissionRequestEvent.asSharedFlow()

    // Action functions
    fun onScan(onShowSnackbar: (String) -> Unit) {
        Timber.d("TrafficScannerViewModel.onScan()")
        viewModelScope.launch {
            if(!scanSetup.first()) {
                _scanSetup.emit(true)
                val useProxy = repository.vpnUseProxy.first()
                if((!repository.proxyActive.first() || !useProxy) && !repository.vpnActive.first()) {
                    Timber.d("Preparing VpnService...")
                    val vpnIntent = VpnService.prepare(context)
                    if (vpnIntent != null) {
                        // Need to ask for permission
                        _vpnPermissionRequestEvent.emit(Unit)
                    } else {
                        // Permission already granted, launch proxy and VPN
                        if(useProxy) {
                            Timber.d("Starting proxy server...")
                            proxyServer = try {
                                launchProxy(context)
                            } catch (e: Exception) {
                                null
                            }
                            repository.updateProxyActive(proxyServer != null)
                        }

                        if(!useProxy || repository.proxyActive.first()) {
                            Timber.d("Starting VpnService with existing VPN permission...")
                            if(launchVpn(context, useProxy) != null) {
                                repository.updateVpnActive(true)
                                _scanActive.emit(true)
                            }
                        }

                        _scanSetup.emit(false)
                        onShowSnackbar("Traffic scanner enabled")
                    }
                } else {
                    stopProxyAndVpn(context, proxyServer)
                    onShowSnackbar("VPN setup failed")
                }
            }

        }
    }

    fun onScanCancel() {
        Timber.d("TrafficScannerViewModel.onScanCancel()")
        viewModelScope.launch {
            stopProxyAndVpn(context, proxyServer)
        }
    }

    fun onShowSettings() {
        Timber.d("TrafficScannerViewModel.onShowSettings()")
        // TODO: Implement show settings logic
    }

    fun onShowDetails() {
        Timber.d("TrafficScannerViewModel.onShowDetails()")
        // TODO: Implement show details logic
    }

    private fun launchVpn(context: Context, useProxy: Boolean) : ComponentName? {
        Timber.d("TrafficScannerViewModel.launchVpn()")
        return context.startService(
            Intent(context, HeimdallVpnService::class.java)
                .putExtra(
                    HeimdallVpnService.VPN_ACTION,
                    if(useProxy) HeimdallVpnService.START_SERVICE_PROXY else HeimdallVpnService.START_SERVICE
                )
        )
    }

    private suspend fun launchProxy(context: Context) : HeimdallHttpProxyServer {
        Timber.d("TrafficScannerViewModel.launchProxy()")
        return withContext(Dispatchers.IO) {
            //TODO: fetch config from preferences
            val newAuth = Authority.getDefaultInstance(context)
            val oldAuth = de.tomcory.heimdall.core.proxy.littleshoot.mitm.Authority(
                newAuth.keyStoreDir,
                newAuth.alias,
                newAuth.password,
                newAuth.issuerCN,
                newAuth.issuerO,
                newAuth.issuerOU,
                newAuth.subjectO,
                newAuth.subjectOU
            )
            val proxyServer = HeimdallHttpProxyServer(
                //TODO: fetch config from preferences
                InetSocketAddress(
                    "127.0.0.1",
                    9090
                ), CertificateSniffingMitmManager(oldAuth), context
            )
            proxyServer.start()
            proxyServer
        }
    }

    private suspend fun stopProxyAndVpn(context: Context, proxyServer: HeimdallHttpProxyServer?) {
        Timber.d("TrafficScannerViewModel.stopProxyAndVpn()")
        _scanSetup.emit(true)
        context.startService(
            Intent(context, HeimdallVpnService::class.java).putExtra(
                HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE))
        withContext(Dispatchers.IO) {
            Timber.d("Stopping proxy")
            proxyServer?.stop()
        }

        repository.updateVpnLastUpdated(System.currentTimeMillis())

        repository.updateProxyActive(false)
        repository.updateVpnActive(false)
        _scanSetup.emit(false)
        _scanActive.emit(false)
    }

    fun onVpnPermissionResult(resultCode: Int, onShowSnackbar: (String) -> Unit) {
        Timber.d("TrafficScannerViewModel.onVpnPermissionResult()")
        viewModelScope.launch {
            if(resultCode == Activity.RESULT_OK) {
                val useProxy = repository.vpnUseProxy.first()
                if(useProxy) {
                    Timber.d("Starting proxy server...")
                    proxyServer = try {
                        launchProxy(context)
                    } catch (e: Exception) {
                        null
                    }
                    repository.updateProxyActive(proxyServer != null)
                }

                if(!useProxy || repository.proxyActive.first()) {
                    Timber.d("Starting VpnService with fresh VPN permission...")
                    if(launchVpn(context, useProxy) != null) {
                        repository.updateVpnActive(true)
                        _scanActive.emit(true)
                        onShowSnackbar("Traffic scanner enabled")
                    } else {
                        onShowSnackbar("VPN setup failed")
                    }
                } else {
                    onShowSnackbar("Proxy setup failed")
                }

                _scanSetup.emit(false)
            } else {
                Timber.e("VPN permission request returned result code %s", resultCode)
                onShowSnackbar("Error: result code %resultCode")
            }

            _scanSetup.emit(false)
        }
    }
}
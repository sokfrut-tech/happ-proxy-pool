package org.sokfrut.happclient.core

import android.net.VpnService
import libXray.DialerController
import libXray.LibXray
import org.json.JSONObject


/**
 * Typed adapter for the pinned gomobile API in libXray v26.10.29.
 * The package and method names are verified against classes.jar in the CI AAR.
 */
class LibXrayEngine(private val vpn: VpnService) : TunnelEngine {


    private val dialerController = object : DialerController {
        override fun protectFd(fd: Long): Boolean = vpn.protect(fd.toInt())
    }


    override fun start(configJson: String, tunFd: Int): String? {
        return try {
            require(tunFd >= 0) { "нет дескриптора VPN" }
            LibXray.registerDialerController(dialerController)
            LibXray.setDNS(dialerController, "8.8.8.8:53")
            // Xray-core's Android TUN inbound reads this from Go's process
            // environment; it is not a field in the Xray JSON document.
            LibXray.setTunFd(tunFd)
            val request = InvokeResponse.envelope(
                "runXray",
                JSONObject().put("xrayJson", configJson)
            )
            val error = InvokeResponse.errorOf(LibXray.invoke(request))
            if (error != null) {
                cleanupNativeState()
                error
            } else if (isRunning()) {
                null
            } else {
                cleanupNativeState()
                "ядро не подтвердило запуск"
            }
        } catch (e: Exception) {
            cleanupNativeState()
            "ошибка ядра: ${e.message ?: e.javaClass.simpleName}"
        }
    }


    override fun stop() {
        runCatching { LibXray.invoke(InvokeResponse.envelope("stopXray")) }
        cleanupNativeState()
    }


    override fun isRunning(): Boolean = runCatching {
        InvokeResponse.dataBoolean(
            LibXray.invoke(InvokeResponse.envelope("getXrayState"))
        ) == true
    }.getOrDefault(false)


    private fun cleanupNativeState() {
        runCatching { LibXray.resetTunFd() }
        runCatching { LibXray.resetDNS() }
    }
}

package org.sokfrut.happclient.core

import android.net.VpnService
import go.libXray.DialerController
import go.libXray.LibXray
import org.json.JSONObject

/**
 * Единственный файл, который знает про сгенерированные gomobile-классы libXray.
 * Если имена классов в AAR другие, правятся только импорты и вызовы здесь.
 */
class LibXrayEngine(private val vpn: VpnService) : TunnelEngine {

    private val protector = object : DialerController {
        override fun protectFd(fd: Long): Boolean = vpn.protect(fd.toInt())
    }

    override fun start(configJson: String, tunFd: Int): String? {
        LibXray.registerDialerController(protector)
        LibXray.setDNS(protector, "8.8.8.8:53")
        val payload = JSONObject().put("xrayJson", configJson)
        val response = LibXray.invoke(InvokeResponse.envelope("runXray", payload))
        val error = InvokeResponse.errorOf(response)
        if (error != null) {
            LibXray.resetDNS()
            return error
        }
        return if (isRunning()) null else "ядро не подтвердило запуск"
    }

    override fun stop() {
        runCatching { LibXray.invoke(InvokeResponse.envelope("stopXray")) }
        runCatching { LibXray.resetDNS() }
    }

    override fun isRunning(): Boolean =
        InvokeResponse.dataBoolean(LibXray.invoke(InvokeResponse.envelope("getXrayState"))) == true
}

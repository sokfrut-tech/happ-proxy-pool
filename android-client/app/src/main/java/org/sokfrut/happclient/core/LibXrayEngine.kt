package org.sokfrut.happclient.core

import android.net.VpnService
import org.json.JSONObject
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Proxy

/**
 * Обёртка над gomobile-классами libXray.
 * Имена классов пакета не угаданы заранее: они ищутся в AAR во время работы по списку вариантов.
 * Поэтому сборка не зависит от имён; если класс не найден, ошибка будет явной.
 */
class LibXrayEngine(private val vpn: VpnService) : TunnelEngine {

    private val lib: Class<*> by lazy {
        CANDIDATE_CLASSES.firstNotNullOfOrNull { name ->
            runCatching { Class.forName(name) }.getOrNull()
        } ?: throw IllegalStateException("libXray не найден в AAR (проверьте имя пакета)")
    }

    private val dialerClass: Class<*> by lazy {
        val base = lib.name.substringBeforeLast('.')
        Class.forName("$base.DialerController")
    }

    private fun protector(): Any = Proxy.newProxyInstance(
        lib.classLoader, arrayOf(dialerClass)
    ) { _, method, args ->
        when (method.name) {
            "protectFd" -> {
                val fd = (args?.get(0) as? Number)?.toInt() ?: -1
                vpn.protect(fd)
            }
            else -> null
        }
    }

    private fun call(name: String, vararg args: Any?): Any? {
        val method = lib.methods.firstOrNull { it.name == name && it.parameterTypes.size == args.size }
            ?: throw IllegalStateException("в libXray нет метода $name")
        return try {
            method.invoke(null, *args)
        } catch (e: InvocationTargetException) {
            throw e.targetException
        }
    }

    override fun start(configJson: String, tunFd: Int): String? {
        return try {
            val controller = protector()
            call("registerDialerController", controller)
            call("setDNS", controller, "8.8.8.8:53")
            val request = InvokeResponse.envelope("runXray", JSONObject().put("xrayJson", configJson))
            val error = InvokeResponse.errorOf(call("invoke", request) as? String)
            if (error != null) {
                runCatching { call("resetDNS") }
                error
            } else if (isRunning()) null else "ядро не подтвердило запуск"
        } catch (e: Exception) {
            runCatching { call("resetDNS") }
            "ошибка ядра: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    override fun stop() {
        runCatching { call("invoke", InvokeResponse.envelope("stopXray")) }
        runCatching { call("resetDNS") }
    }

    override fun isRunning(): Boolean = runCatching {
        InvokeResponse.dataBoolean(call("invoke", InvokeResponse.envelope("getXrayState")) as? String) == true
    }.getOrDefault(false)

    companion object {
        /** Возможные имена класса LibXray, который создаёт gomobile для пакета libXray. */
        private val CANDIDATE_CLASSES = listOf(
            "go.libXray.LibXray",
            "libXray.LibXray",
            "go.libxray.LibXray",
            "libxray.LibXray",
            "go.LibXray"
        )
    }
}

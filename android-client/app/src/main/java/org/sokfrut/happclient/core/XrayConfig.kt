package org.sokfrut.happclient.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Готовит конфиг для runXray: заменяет входящие подключения на один TUN-интерфейс,
 * а fd VPN-интерфейса передаёт через root.env["xray.tun.fd"] (так требует libXray).
 * Локальных SOCKS/HTTP-портов не открываем.
 */
object XrayConfig {
    const val MAX_CONFIG_CHARS = 512_000
    const val TUN_TAG = "tun-in"
    const val TUN_NAME = "xray0"
    const val MTU = 1500

    sealed class Result {
        data class Ok(val json: String) : Result()
        data class Invalid(val reason: String) : Result()
    }

    fun build(userJson: String, tunFd: Int): Result {
        if (userJson.isBlank()) return Result.Invalid("конфиг пустой")
        if (userJson.length > MAX_CONFIG_CHARS) return Result.Invalid("конфиг слишком большой")
        val root = try {
            JSONObject(userJson)
        } catch (e: Exception) {
            return Result.Invalid("это не JSON")
        }
        val outbounds: JSONArray? = root.optJSONArray("outbounds")
        if (outbounds == null || outbounds.length() == 0) {
            return Result.Invalid("нет outbounds")
        }
        if (tunFd < 0) return Result.Invalid("нет дескриптора VPN")

        root.put("inbounds", JSONArray().put(
            JSONObject()
                .put("tag", TUN_TAG)
                .put("protocol", "tun")
                .put("settings", JSONObject().put("name", TUN_NAME).put("mtu", MTU))
        ))
        root.put("env", JSONObject().put("xray.tun.fd", tunFd.toString()))
        return Result.Ok(root.toString())
    }
}

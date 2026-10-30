package org.sokfrut.happclient.core

import org.json.JSONArray
import org.json.JSONObject


/**
 * Подготавливает Xray JSON с одним Android TUN inbound.
 * Дескриптор передаётся отдельно через SetTunFd() в окружение процесса Go:
 * поле env в Xray JSON не устанавливает переменные окружения процесса.
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


        for (i in 0 until outbounds.length()) {
            val item = outbounds.optJSONObject(i) ?: return Result.Invalid("узел $i не объект")
            TransportPolicy.checkOutbound(item)?.let { return Result.Invalid("узел $i: $it") }
        }
        TransportPolicy.enforceGlobals(root)


        root.put("inbounds", JSONArray().put(
            JSONObject()
                .put("tag", TUN_TAG)
                .put("port", 0)
                .put("protocol", "tun")
                .put("settings", JSONObject().put("name", TUN_NAME).put("mtu", MTU))
        ))
        root.remove("env")
        return Result.Ok(root.toString())
    }
}

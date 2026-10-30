package org.sokfrut.happclient.core

import org.json.JSONObject

/** Абстракция над ядром. UI и сервис работают только с ней. */
interface TunnelEngine {
    /** Запускает ядро; возвращает null при успехе или текст ошибки. */
    fun start(configJson: String, tunFd: Int): String?
    /** Останавливает ядро. Не выбрасывает исключений. */
    fun stop()
    /** Спрашивает у ядра, работает ли оно сейчас. */
    fun isRunning(): Boolean
}

/** Разбор ответа libXray Invoke: {"success": bool, "data": ..., "error": "..."}. */
object InvokeResponse {
    fun envelope(method: String, payload: JSONObject? = null): String {
        val request = JSONObject().put("apiVersion", 3).put("method", method)
        if (payload != null) request.put("payload", payload)
        return request.toString()
    }

    /** Возвращает null при успехе, иначе текст ошибки. Ответ сам по себе не логируется. */
    fun errorOf(response: String?): String? {
        if (response.isNullOrBlank()) return "пустой ответ ядра"
        return try {
            val obj = JSONObject(response)
            if (obj.optBoolean("success", false)) null
            else obj.optString("error").ifBlank { "ядро вернуло ошибку" }
        } catch (e: Exception) {
            "некорректный ответ ядра"
        }
    }

    fun dataBoolean(response: String?): Boolean? {
        if (response.isNullOrBlank()) return null
        return try {
            val obj = JSONObject(response)
            if (!obj.optBoolean("success", false)) null else obj.opt("data") as? Boolean
        } catch (e: Exception) {
            null
        }
    }
}

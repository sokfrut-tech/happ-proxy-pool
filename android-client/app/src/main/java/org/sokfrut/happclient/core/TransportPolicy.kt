package org.sokfrut.happclient.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Политика защиты трафика до запуска ядра.
 * Публичные узлы считаем недоверенными: без шифрования и проверки сертификата не пускаем.
 * Оператор узла всё равно видит адреса, на которые вы ходите, поэтому для личных данных нужен свой сервер.
 */
object TransportPolicy {

    /** Шифры Shadowsocks только AEAD. Остальные (rc4, plain, none и т.п.) отклоняются. */
    private val aeadMethods = setOf(
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
    )

    private val encryptedProtocols = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http")

    /** Возвращает причину отказа для исходящего узла или null, если узел допустим. */
    fun checkOutbound(outbound: JSONObject): String? {
        val protocol = outbound.optString("protocol").lowercase()
        if (protocol == "freedom" || protocol == "blackhole") return null
        if (protocol !in encryptedProtocols) return "неизвестный протокол узла"

        if (protocol == "shadowsocks") {
            val method = firstServer(outbound, "servers")?.optString("method").orEmpty().lowercase()
            if (method !in aeadMethods) return "шифр Shadowsocks не AEAD: $method"
            return null
        }

        val stream = outbound.optJSONObject("streamSettings")
        val security = stream?.optString("security").orEmpty().lowercase()
        if (security != "tls" && security != "reality") {
            return "узел без TLS или REALITY (передача открытым текстом)"
        }
        if (security == "tls") {
            val tls = stream?.optJSONObject("tlsSettings")
            if (tls?.optBoolean("allowInsecure", false) == true) {
                return "в узле отключена проверка сертификата (allowInsecure)"
            }
        }
        if (security == "reality") {
            val reality = stream?.optJSONObject("realitySettings")
            if (reality == null || reality.optString("publicKey").isBlank()) {
                return "REALITY без публичного ключа"
            }
        }
        return null
    }

    /**
     * Приводит общий конфиг к безопасным настройкам: DNS только через DoH,
     * логи без записи в файлы. Существующие безопасные настройки пользователя не перезаписываем.
     * Возвращает список того, что было сделано (для журнала без секретов).
     */
    fun enforceGlobals(root: JSONObject): List<String> {
        val notes = mutableListOf<String>()

        val log = root.optJSONObject("log") ?: JSONObject()
        log.remove("access")
        log.remove("error")
        log.put("loglevel", "warning")
        root.put("log", log)
        notes += "логи: только предупреждения, без файлов"

        val dns = root.optJSONObject("dns")
        val servers = dns?.optJSONArray("servers")
        val hasEncryptedDns = servers != null && (0 until servers.length()).any { i ->
            servers.opt(i).toString().startsWith("https://")
        }
        if (!hasEncryptedDns) {
            val newDns = dns ?: JSONObject()
            newDns.put("servers", JSONArray()
                .put("https://1.1.1.1/dns-query")
                .put("https://8.8.8.8/dns-query"))
            root.put("dns", newDns)
            notes += "DNS: через зашифрованный DoH"
        }
        return notes
    }

    private fun firstServer(outbound: JSONObject, key: String): JSONObject? {
        val settings = outbound.optJSONObject("settings") ?: return null
        val list = settings.optJSONArray(key) ?: return null
        return list.optJSONObject(0)
    }
}

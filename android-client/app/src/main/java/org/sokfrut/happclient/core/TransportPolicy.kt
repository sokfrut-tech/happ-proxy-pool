package org.sokfrut.happclient.core

import org.json.JSONArray
import org.json.JSONObject


/**
 * Политика защиты трафика до запуска ядра.
 * DNS из Android TUN направляется в Xray DNS outbound, который использует только DoH-серверы.
 */
object TransportPolicy {


    private val aeadMethods = setOf(
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
    )


    private val encryptedProtocols = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http")


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
            // В актуальной документации Xray клиентский публичный ключ называется password (раньше publicKey).
            val publicKey = reality?.optString("password").orEmpty().ifBlank { reality?.optString("publicKey").orEmpty() }
            if (reality == null || publicKey.isBlank()) {
                return "REALITY без публичного ключа"
            }
        }
        return null
    }


    /** Removes plaintext DNS resolvers and forces port-53 packets from our TUN through DoH. */
    fun enforceGlobals(root: JSONObject): List<String> {
        val notes = mutableListOf<String>()

        val log = root.optJSONObject("log") ?: JSONObject()
        log.remove("access")
        log.remove("error")
        log.put("loglevel", "warning")
        root.put("log", log)
        notes += "логи: только предупреждения, без файлов"

        val dns = root.optJSONObject("dns") ?: JSONObject()
        val configuredServers = dns.optJSONArray("servers")
        val encryptedServers = JSONArray()
        if (configuredServers != null) {
            for (i in 0 until configuredServers.length()) {
                val server = configuredServers.opt(i)
                val address = when (server) {
                    is String -> server.trim()
                    is JSONObject -> server.optString("address").trim()
                    else -> ""
                }
                if (address.startsWith("https://", ignoreCase = true) ||
                    address.startsWith("https+local://", ignoreCase = true)) {
                    encryptedServers.put(server)
                }
            }
        }
        if (encryptedServers.length() == 0) {
            encryptedServers.put("https://1.1.1.1/dns-query")
            encryptedServers.put("https://8.8.8.8/dns-query")
            notes += "DNS: установлены DoH-серверы"
        } else if (configuredServers == null || encryptedServers.length() != configuredServers.length()) {
            notes += "DNS: удалены нешифрованные серверы"
        }
        dns.put("servers", encryptedServers)
        root.put("dns", dns)

        val outbounds = root.optJSONArray("outbounds") ?: JSONArray()
        var dnsTag = "happ-doh-dns"
        var suffix = 1
        while (containsOutboundTag(outbounds, dnsTag)) {
            dnsTag = "happ-doh-dns-$suffix"
            suffix++
        }
        outbounds.put(JSONObject().put("tag", dnsTag).put("protocol", "dns"))
        root.put("outbounds", outbounds)

        val routing = root.optJSONObject("routing") ?: JSONObject()
        val existingRules = routing.optJSONArray("rules") ?: JSONArray()
        val rules = JSONArray().put(
            JSONObject()
                .put("type", "field")
                .put("inboundTag", JSONArray().put(XrayConfig.TUN_TAG))
                .put("network", "tcp,udp")
                .put("port", "53")
                .put("outboundTag", dnsTag)
        )
        for (i in 0 until existingRules.length()) rules.put(existingRules.get(i))
        routing.put("rules", rules)
        root.put("routing", routing)
        notes += "DNS из VPN-туннеля направляется через DoH"
        return notes
    }


    private fun containsOutboundTag(outbounds: JSONArray, tag: String): Boolean {
        for (i in 0 until outbounds.length()) {
            if (outbounds.optJSONObject(i)?.optString("tag") == tag) return true
        }
        return false
    }


    private fun firstServer(outbound: JSONObject, key: String): JSONObject? {
        val settings = outbound.optJSONObject("settings") ?: return null
        val list = settings.optJSONArray(key) ?: return null
        return list.optJSONObject(0)
    }
}

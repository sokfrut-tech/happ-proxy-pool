package org.sokfrut.happclient

import java.net.URI
import java.util.Base64

data class ParseSummary(
    val supportedCount: Int,
    val rejectedCount: Int,
    val safeSummary: String
)

object SubscriptionLineParser {
    private val uriSchemes = setOf("vless", "trojan", "ss", "socks", "socks5")

    // Защита от слишком больших вставок: длинный текст не разбираем.
    private const val MAX_INPUT_CHARS = 512_000
    private const val MAX_LINE_CHARS = 8_192

    fun parse(text: String): ParseSummary {
        if (text.length > MAX_INPUT_CHARS) {
            return ParseSummary(0, 0, "Текст слишком большой: больше ${MAX_INPUT_CHARS / 1000} КБ")
        }
        var supported = 0
        var rejected = 0
        text.lineSequence()
            .map(String::trim)
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .forEach { line ->
                if (isSupportedProxyUri(line)) supported++ else rejected++
            }
        return ParseSummary(
            supportedCount = supported,
            rejectedCount = rejected,
            safeSummary = "Поддерживаемых строк: $supported; отклонено: $rejected"
        )
    }

    private fun isSupportedProxyUri(line: String): Boolean {
        if (line.length > MAX_LINE_CHARS) return false
        val scheme = line.substringBefore("://", missingDelimiterValue = "").lowercase()
        if (scheme == "ss") {
            val payload = line.substringAfter("://", "").substringBefore('#')
            if (!payload.contains('@')) {
                // Старый формат ss://: вся часть до '#' закодирована в base64 (метод:пароль@хост:порт).
                return runCatching {
                    val normalized = payload.replace('-', '+').replace('_', '/')
                    val legacy = Base64.getDecoder().decode(normalized).toString(Charsets.UTF_8)
                    val hostPort = legacy.substringAfterLast('@', "")
                    val port = hostPort.substringAfterLast(':', "").toIntOrNull()
                    hostPort.contains(':') && port != null && port in 1..65535
                }.getOrDefault(false)
            }
        }
        if (scheme == "vmess") {
            val payload = line.substringAfter("://", "").substringBefore('#')
            return runCatching {
                val normalized = payload.replace('-', '+').replace('_', '/')
                val decoded = Base64.getDecoder().decode(normalized).toString(Charsets.UTF_8)
                decoded.trimStart().startsWith("{") && decoded.contains("\"add\"")
            }.getOrDefault(false)
        }
        if (scheme !in uriSchemes) return false
        return runCatching {
            val uri = URI(line)
            !uri.host.isNullOrBlank() && uri.port in 1..65535
        }.getOrDefault(false)
    }
}

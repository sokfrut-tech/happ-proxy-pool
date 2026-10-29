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

    fun parse(text: String): ParseSummary {
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
        val scheme = line.substringBefore("://", missingDelimiterValue = "").lowercase()
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

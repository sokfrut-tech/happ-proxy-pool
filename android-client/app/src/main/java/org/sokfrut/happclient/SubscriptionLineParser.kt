package org.sokfrut.happclient

data class ParseSummary(
    val supportedCount: Int,
    val rejectedCount: Int,
    val safeSummary: String
)

object SubscriptionLineParser {
    private val supportedSchemes = setOf("vless", "vmess", "trojan", "ss", "socks", "socks5")

    fun parse(text: String): ParseSummary {
        var supported = 0
        var rejected = 0
        text.lineSequence()
            .map(String::trim)
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .forEach { line ->
                val scheme = line.substringBefore("://", missingDelimiterValue = "")
                    .lowercase()
                val hasPayload = line.substringAfter("://", "").isNotBlank()
                if (scheme in supportedSchemes && hasPayload) supported++ else rejected++
            }
        return ParseSummary(
            supportedCount = supported,
            rejectedCount = rejected,
            safeSummary = "Поддерживаемых строк: $supported; отклонено: $rejected"
        )
    }
}

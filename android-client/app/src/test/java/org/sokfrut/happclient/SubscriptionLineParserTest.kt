package org.sokfrut.happclient

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class SubscriptionLineParserTest {
    @Test fun recognizesSupportedSchemesWithoutExposingCredentials() {
        val lines = listOf(
            "vless://secret@example.org:443?security=reality#node",
            "vmess://eyJhZGQiOiJleGFtcGxlLm9yZyIsInBvcnQiOiI0NDMifQ==",
            "trojan://secret@example.org:443#node",
            "ss://YWVzLTI1Ni1nY206cGFzcw@example.org:8388#node",
            "socks://user:secret@example.org:1080"
        )
        val result = SubscriptionLineParser.parse(lines.joinToString("\n"))
        assertEquals(5, result.supportedCount)
        assertEquals(0, result.rejectedCount)
        assertFalse(result.safeSummary.contains("secret"))
        assertFalse(result.safeSummary.contains("cGFzcw"))
    }

    @Test fun rejectsUnsupportedAndMalformedLines() {
        val result = SubscriptionLineParser.parse(
            "https://example.org/config\nnot-a-proxy-link\nvless://missing-host"
        )
        assertEquals(0, result.supportedCount)
        assertEquals(3, result.rejectedCount)
    }

    @Test fun ignoresCommentsAndBlankLines() {
        val result = SubscriptionLineParser.parse("# subscription\n\nvless://id@example.org:443")
        assertEquals(1, result.supportedCount)
        assertEquals(0, result.rejectedCount)
    }

    @Test fun acceptsLegacyBase64ShadowsocksLink() {
        val payload = java.util.Base64.getEncoder().encodeToString("aes-256-gcm:pass@example.org:8388".toByteArray())
        val result = SubscriptionLineParser.parse("ss://$payload#node")
        assertEquals(1, result.supportedCount)
        assertEquals(0, result.rejectedCount)
    }

    @Test fun rejectsOversizedInput() {
        val result = SubscriptionLineParser.parse("vless://id@example.org:443\n".repeat(60_000))
        assertEquals(0, result.supportedCount)
        assertEquals(0, result.rejectedCount)
    }
}

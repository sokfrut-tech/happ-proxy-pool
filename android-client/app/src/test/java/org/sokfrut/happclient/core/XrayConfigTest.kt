package org.sokfrut.happclient.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayConfigTest {
    private val validConfig = """
        {"log":{"loglevel":"warning"},
         "inbounds":[{"protocol":"socks","port":10808}],
         "outbounds":[{"protocol":"freedom","tag":"direct"}]}
    """.trimIndent()

    @Test fun replacesInboundsWithSingleTunAndPassesFdInEnv() {
        val result = XrayConfig.build(validConfig, 42)
        assertTrue(result is XrayConfig.Result.Ok)
        val root = JSONObject((result as XrayConfig.Result.Ok).json)
        val inbounds = root.getJSONArray("inbounds")
        assertEquals(1, inbounds.length())
        assertEquals("tun", inbounds.getJSONObject(0).getString("protocol"))
        assertEquals("42", root.getJSONObject("env").getString("xray.tun.fd"))
    }

    @Test fun keepsUserOutboundsUnchanged() {
        val result = XrayConfig.build(validConfig, 7) as XrayConfig.Result.Ok
        val outbounds = JSONObject(result.json).getJSONArray("outbounds")
        assertEquals("freedom", outbounds.getJSONObject(0).getString("protocol"))
    }

    @Test fun rejectsEmptyNonJsonAndWithoutOutbounds() {
        assertTrue(XrayConfig.build("", 1) is XrayConfig.Result.Invalid)
        assertTrue(XrayConfig.build("не json", 1) is XrayConfig.Result.Invalid)
        assertTrue(XrayConfig.build("{\"inbounds\":[]}", 1) is XrayConfig.Result.Invalid)
        assertTrue(XrayConfig.build("{\"outbounds\":[]}", 1) is XrayConfig.Result.Invalid)
    }

    @Test fun rejectsMissingDescriptorAndOversizedInput() {
        assertTrue(XrayConfig.build(validConfig, -1) is XrayConfig.Result.Invalid)
        val big = validConfig + " ".repeat(XrayConfig.MAX_CONFIG_CHARS)
        assertTrue(XrayConfig.build(big, 1) is XrayConfig.Result.Invalid)
    }
}

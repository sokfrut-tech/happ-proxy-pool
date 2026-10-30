package org.sokfrut.happclient.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class TransportPolicyTest {
    private fun vless(security: String, extra: String = ""): JSONObject = JSONObject(
        """{"protocol":"vless","settings":{"vnext":[{"address":"a.example","port":443}]},
           "streamSettings":{"security":"$security"$extra}}"""
    )

    @Test fun acceptsTlsAndRealityWithValidation() {
        assertNull(TransportPolicy.checkOutbound(vless("tls", ""","tlsSettings":{"serverName":"a.example"}""")))
        assertNull(TransportPolicy.checkOutbound(vless("reality",
            ""","realitySettings":{"publicKey":"abc","serverName":"a.example"}""")))
    }

    @Test fun rejectsPlaintextNode() {
        assertNotNull(TransportPolicy.checkOutbound(vless("none")))
        assertNotNull(TransportPolicy.checkOutbound(JSONObject("""{"protocol":"vless","settings":{}}""")))
    }

    @Test fun rejectsInsecureCertificateAndRealityWithoutKey() {
        assertNotNull(TransportPolicy.checkOutbound(vless("tls", ""","tlsSettings":{"allowInsecure":true}""")))
        assertNotNull(TransportPolicy.checkOutbound(vless("reality", ""","realitySettings":{}""")))
    }

    @Test fun shadowsocksMustUseAead() {
        val good = JSONObject("""{"protocol":"shadowsocks","settings":{"servers":[{"method":"aes-256-gcm"}]}}""")
        val bad = JSONObject("""{"protocol":"shadowsocks","settings":{"servers":[{"method":"rc4-md5"}]}}""")
        assertNull(TransportPolicy.checkOutbound(good))
        assertNotNull(TransportPolicy.checkOutbound(bad))
    }

    @Test fun freedomIsAllowedAndUnknownProtocolIsNot() {
        assertNull(TransportPolicy.checkOutbound(JSONObject("""{"protocol":"freedom"}""")))
        assertNotNull(TransportPolicy.checkOutbound(JSONObject("""{"protocol":"mystery"}""")))
    }

    @Test fun globalsForceDohAndNoLogFiles() {
        val root = JSONObject("""{"log":{"access":"/data/x.log","error":"/data/e.log"}}""")
        val notes = TransportPolicy.enforceGlobals(root)
        assertEquals("warning", root.getJSONObject("log").getString("loglevel"))
        assertNull(root.getJSONObject("log").opt("access"))
        assertEquals(2, notes.size)
        assertEquals("https://1.1.1.1/dns-query", root.getJSONObject("dns").getJSONArray("servers").getString(0))
    }

    @Test fun keepsUserEncryptedDnsUnchanged() {
        val root = JSONObject("""{"dns":{"servers":["https://dns.example/dns-query"]}}""")
        TransportPolicy.enforceGlobals(root)
        assertEquals("https://dns.example/dns-query", root.getJSONObject("dns").getJSONArray("servers").getString(0))
    }
}

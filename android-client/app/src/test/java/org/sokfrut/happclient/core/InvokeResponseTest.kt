package org.sokfrut.happclient.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InvokeResponseTest {
    @Test fun successHasNoError() {
        assertNull(InvokeResponse.errorOf("""{"success":true,"data":null}"""))
    }

    @Test fun failureReturnsErrorText() {
        assertEquals("bad config", InvokeResponse.errorOf("""{"success":false,"error":"bad config"}"""))
    }

    @Test fun emptyOrBrokenResponseIsError() {
        assertEquals("пустой ответ ядра", InvokeResponse.errorOf(null))
        assertEquals("некорректный ответ ядра", InvokeResponse.errorOf("{broken"))
    }

    @Test fun readsRunningFlag() {
        assertEquals(true, InvokeResponse.dataBoolean("""{"success":true,"data":true}"""))
        assertEquals(false, InvokeResponse.dataBoolean("""{"success":true,"data":false}"""))
        assertNull(InvokeResponse.dataBoolean("""{"success":false,"data":true}"""))
    }

    @Test fun envelopeCarriesApiVersionThree() {
        val json = InvokeResponse.envelope("stopXray")
        assertTrue(json.contains("\"apiVersion\":3"))
        assertTrue(json.contains("\"method\":\"stopXray\""))
    }
}

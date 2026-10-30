package org.sokfrut.happclient.core

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelStateTest {
    @Test fun labelsAreHonest() {
        assertEquals("Не подключено", TunnelState.Disconnected.label)
        assertEquals("Подключение", TunnelState.Connecting.label)
        assertEquals("Подключено", TunnelState.Connected.label)
        assertEquals("Ошибка: нет конфига", TunnelState.Error("нет конфига").label)
    }
}

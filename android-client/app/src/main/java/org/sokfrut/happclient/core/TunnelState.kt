package org.sokfrut.happclient.core

/** Честные состояния туннеля. «Подключено» ставится только после подтверждения ядра. */
sealed class TunnelState {
    object Disconnected : TunnelState()
    object Connecting : TunnelState()
    object Connected : TunnelState()
    data class Error(val message: String) : TunnelState()

    val label: String
        get() = when (this) {
            Disconnected -> "Не подключено"
            Connecting -> "Подключение"
            Connected -> "Подключено"
            is Error -> "Ошибка: $message"
        }
}

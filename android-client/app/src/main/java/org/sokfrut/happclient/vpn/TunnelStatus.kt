package org.sokfrut.happclient.vpn

import android.os.Handler
import android.os.Looper
import org.sokfrut.happclient.core.TunnelState

/**
 * Общее состояние туннеля для сервиса и экрана.
 * pendingConfig хранится только в памяти процесса: на диск и в логи не пишется.
 */
object TunnelStatus {
    @Volatile var state: TunnelState = TunnelState.Disconnected
        private set
    @Volatile var pendingConfig: String? = null

    private val main = Handler(Looper.getMainLooper())
    private var listener: ((TunnelState) -> Unit)? = null

    fun update(newState: TunnelState) {
        state = newState
        main.post { listener?.invoke(newState) }
    }

    fun listen(callback: ((TunnelState) -> Unit)?) {
        listener = callback
        callback?.let { main.post { it.invoke(state) } }
    }
}

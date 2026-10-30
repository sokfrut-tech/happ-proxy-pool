package org.sokfrut.happclient.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import org.sokfrut.happclient.MainActivity
import org.sokfrut.happclient.core.LibXrayEngine
import org.sokfrut.happclient.core.TunnelEngine
import org.sokfrut.happclient.core.TunnelState
import org.sokfrut.happclient.core.XrayConfig
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Единственный VPN-сервис приложения. Android разрешает только один активный VpnService.
 * Состояние «Подключено» выставляется только после подтверждения ядра.
 */
class HappVpnService : VpnService() {

    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private var tun: ParcelFileDescriptor? = null
    private var engine: TunnelEngine? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopTunnel()
            else -> startTunnel()
        }
        return START_NOT_STICKY
    }

    private fun startTunnel() {
        if (TunnelStatus.state == TunnelState.Connected || TunnelStatus.state == TunnelState.Connecting) return
        showForeground()
        TunnelStatus.update(TunnelState.Connecting)
        val config = TunnelStatus.pendingConfig
        worker.execute {
            val error = bringUp(config)
            if (error != null) {
                teardown()
                TunnelStatus.update(TunnelState.Error(error))
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            } else {
                TunnelStatus.update(TunnelState.Connected)
            }
        }
    }

    /** Возвращает null при успехе или причину ошибки. */
    private fun bringUp(config: String?): String? {
        if (config.isNullOrBlank()) return "нет конфига"
        val builder = Builder()
            .setSession("Happ Compatible")
            .setMtu(XrayConfig.MTU)
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
        val established: ParcelFileDescriptor? = try {
            builder.establish()
        } catch (e: SecurityException) {
            null
        }
        val descriptor = established ?: return "VPN не разрешён или отозван системой"
        tun = descriptor

        val built = XrayConfig.build(config, descriptor.fd)
        if (built is XrayConfig.Result.Invalid) return built.reason

        val core = LibXrayEngine(this)
        engine = core
        return core.start((built as XrayConfig.Result.Ok).json, descriptor.fd)
    }

    private fun stopTunnel() {
        worker.execute {
            teardown()
            TunnelStatus.update(TunnelState.Disconnected)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun teardown() {
        runCatching { engine?.stop() }
        engine = null
        runCatching { tun?.close() }
        tun = null
    }

    /** Система отозвала разрешение VPN (например, другое VPN-приложение заняло слот). */
    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown()
        worker.shutdown()
        super.onDestroy()
    }

    private fun showForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "VPN", NotificationManager.IMPORTANCE_LOW)
        )
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Happ Compatible")
            .setContentText("VPN работает")
            .setOngoing(true)
            .setContentIntent(openApp)
            .build()
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID, notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        )
    }

    companion object {
        const val ACTION_START = "org.sokfrut.happclient.START"
        const val ACTION_STOP = "org.sokfrut.happclient.STOP"
        private const val CHANNEL_ID = "vpn"
        private const val NOTIFICATION_ID = 1
    }
}

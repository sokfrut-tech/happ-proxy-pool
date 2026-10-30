package org.sokfrut.happclient

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import android.content.Intent
import android.net.VpnService
import androidx.appcompat.app.AlertDialog
import org.sokfrut.happclient.core.TunnelState
import org.sokfrut.happclient.core.XrayConfig
import org.sokfrut.happclient.vpn.HappVpnService
import org.sokfrut.happclient.vpn.TunnelStatus

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var details: TextView
    private lateinit var connectButton: Button
    private lateinit var disconnectButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val title = TextView(this).apply {
            text = "Happ Compatible"
            textSize = 26f
            gravity = Gravity.CENTER
        }
        status = TextView(this).apply {
            text = "Туннель: ${TunnelStatus.state.label}"
            textSize = 16f
            gravity = Gravity.CENTER
        }
        details = TextView(this).apply {
            text = "Для подключения вставь полный конфиг Xray (JSON). Список ссылок пока только проверяется по формату."
            textSize = 14f
        }
        val pasteButton = Button(this).apply {
            text = "Вставить из буфера"
            setOnClickListener { importFromClipboard() }
        }
        val manualButton = Button(this).apply {
            text = "Вставить текст вручную"
            setOnClickListener { showManualImport() }
        }
        val configButton = Button(this).apply {
            text = "Вставить конфиг Xray (JSON)"
            setOnClickListener { showConfigInput() }
        }
        connectButton = Button(this).apply {
            text = "Подключить"
            isEnabled = false
            setOnClickListener { requestVpnAndConnect() }
        }
        disconnectButton = Button(this).apply {
            text = "Отключить"
            isEnabled = false
            setOnClickListener { sendVpnAction(HappVpnService.ACTION_STOP) }
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(24, 40, 24, 24)
            addView(title)
            addView(status)
            addView(details)
            addView(pasteButton)
            addView(manualButton)
            addView(configButton)
            addView(connectButton)
            addView(disconnectButton)
        }
        setContentView(ScrollView(this).apply { addView(layout) })
    }

    override fun onResume() {
        super.onResume()
        TunnelStatus.listen { state -> renderTunnel(state) }
    }

    override fun onPause() {
        TunnelStatus.listen(null)
        super.onPause()
    }

    private fun renderTunnel(state: TunnelState) {
        status.text = "Туннель: ${state.label}"
        val hasConfig = TunnelStatus.pendingConfig != null
        connectButton.isEnabled = hasConfig && state !is TunnelState.Connected && state !is TunnelState.Connecting
        disconnectButton.isEnabled = state is TunnelState.Connected || state is TunnelState.Connecting
    }

    /** Конфиг вставляется вручную и хранится только в памяти процесса: не на диск и не в логи. */
    private fun showConfigInput() {
        val editor = EditText(this).apply {
            hint = "Полный JSON-конфиг Xray с outbounds"
            minLines = 6
            gravity = Gravity.TOP
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Конфиг Xray")
            .setView(editor)
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Сохранить") { _, _ ->
                val text = editor.text.toString()
                val check = XrayConfig.build(text, 0)
                if (check is XrayConfig.Result.Invalid) {
                    Toast.makeText(this, "Не подходит: ${check.reason}", Toast.LENGTH_LONG).show()
                } else {
                    TunnelStatus.pendingConfig = text
                    details.text = "Конфиг сохранён в памяти приложения. Он не записывается на диск."
                    renderTunnel(TunnelStatus.state)
                }
            }
            .show()
    }

    private fun requestVpnAndConnect() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQUEST_VPN)
        } else {
            sendVpnAction(HappVpnService.ACTION_START)
        }
    }

    @Deprecated("Используется для запроса разрешения VPN")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) sendVpnAction(HappVpnService.ACTION_START)
            else TunnelStatus.update(TunnelState.Error("VPN не разрешён"))
        }
    }

    private fun sendVpnAction(action: String) {
        val intent = Intent(this, HappVpnService::class.java).setAction(action)
        if (action == HappVpnService.ACTION_START) startForegroundService(intent) else startService(intent)
    }

    companion object {
        private const val REQUEST_VPN = 41
    }

    private fun importFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip: ClipData? = clipboard.primaryClip
        val text = if (clip != null && clip.itemCount > 0) {
            clip.getItemAt(0).coerceToText(this)?.toString()
        } else null

        if (text.isNullOrBlank()) {
            Toast.makeText(this, "Буфер обмена пуст", Toast.LENGTH_SHORT).show()
            return
        }
        showImportResult(text)
    }

    private fun showManualImport() {
        val editor = EditText(this).apply {
            hint = "Вставь ссылки VLESS / VMess / Trojan / SS / SOCKS"
            minLines = 5
            gravity = Gravity.TOP
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Импорт списка")
            .setView(editor)
            .setNegativeButton("Отмена", null)
            .setPositiveButton("Проверить") { _, _ -> showImportResult(editor.text.toString()) }
            .show()
    }

    private fun showImportResult(text: String) {
        // Only the aggregate parse summary is retained in the UI; raw links and credentials are never logged or displayed.
        val summary = SubscriptionLineParser.parse(text)
        status.text = "Импорт проверен · VPN не запущен"
        details.text = summary.safeSummary + "\n\nПодключение пока отключено: сетевой движок ещё не интегрирован."
        Toast.makeText(this, "Проверка завершена", Toast.LENGTH_SHORT).show()
    }
}

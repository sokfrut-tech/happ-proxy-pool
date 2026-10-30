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
import androidx.appcompat.app.AlertDialog

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var details: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val title = TextView(this).apply {
            text = "Happ Compatible"
            textSize = 26f
            gravity = Gravity.CENTER
        }
        status = TextView(this).apply {
            text = "Прототип · VPN-движок ещё не подключён"
            textSize = 16f
            gravity = Gravity.CENTER
        }
        details = TextView(this).apply {
            text = "Импортируй список ссылок VLESS / VMess / Trojan / Shadowsocks / SOCKS.\nПока доступна только проверка формата."
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
        val connectButton = Button(this).apply {
            text = "VPN-движок ещё не подключён"
            isEnabled = false
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
            addView(connectButton)
        }
        setContentView(ScrollView(this).apply { addView(layout) })
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

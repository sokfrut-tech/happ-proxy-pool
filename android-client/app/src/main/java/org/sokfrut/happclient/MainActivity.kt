package org.sokfrut.happclient

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

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
        val importButton = Button(this).apply {
            text = "Вставить подписку"
            setOnClickListener {
                Toast.makeText(this@MainActivity, "Импорт из буфера добавим следующим этапом", Toast.LENGTH_SHORT).show()
            }
        }
        val connectButton = Button(this).apply {
            text = "Подключение пока недоступно"
            isEnabled = false
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(24, 40, 24, 24)
            addView(title)
            addView(status)
            addView(details)
            addView(importButton)
            addView(connectButton)
        }
        setContentView(layout)
    }
}

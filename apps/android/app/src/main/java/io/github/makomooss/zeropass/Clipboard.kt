package io.github.makomooss.zeropass

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies secrets (docs/spec/android.md §4): marked sensitive, so that the
 * keyboard and the system do not show them, and cleared after
 * [CLEAR_MILLIS] if nothing else was copied since.
 */
object Clipboard {
    const val CLEAR_MILLIS = 30_000L
    private const val LABEL = "ZeroPass"
    private val main = Handler(Looper.getMainLooper())
    private var copies = 0

    fun copy(context: Context, text: String) {
        val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(LABEL, text)
        clip.description.extras = PersistableBundle().apply {
            val key = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ClipDescription.EXTRA_IS_SENSITIVE
            } else {
                "android.content.extra.IS_SENSITIVE"
            }
            putBoolean(key, true)
        }
        clipboard.setPrimaryClip(clip)
        val copy = ++copies
        main.postDelayed({ clear(clipboard, copy) }, CLEAR_MILLIS)
    }

    private fun clear(clipboard: ClipboardManager, copy: Int) {
        // Something newer was copied, by ZeroPass or by someone else.
        if (copy != copies || clipboard.primaryClipDescription?.label != LABEL) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}

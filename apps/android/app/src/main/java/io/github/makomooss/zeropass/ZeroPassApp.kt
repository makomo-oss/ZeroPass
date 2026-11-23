package io.github.makomooss.zeropass

import android.app.Application
import android.os.Build
import android.os.Process

/**
 * The application. Android also creates it in the isolated vault process,
 * where it does nothing: that process only answers [VaultService].
 */
class ZeroPassApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (isolated()) return
        registerActivityLifecycleCallbacks(Prompts)
    }

    private fun isolated(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Process.isIsolated()
        } else {
            // Isolated processes get a user ID from this range (Process.FIRST_ISOLATED_UID).
            Process.myUid() % 100_000 in 99_000..99_999
        }
}

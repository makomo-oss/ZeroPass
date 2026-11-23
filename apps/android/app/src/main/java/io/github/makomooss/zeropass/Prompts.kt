package io.github.makomooss.zeropass

import android.app.Activity
import android.app.Application
import android.os.Bundle
import androidx.fragment.app.FragmentActivity

/**
 * Where the Keystore prompt can be shown: the app's screen in the foreground
 * (docs/spec/android.md §3). Registered by [ZeroPassApp].
 */
object Prompts : Application.ActivityLifecycleCallbacks {
    @Volatile var foreground: FragmentActivity? = null
        private set

    /** What the next prompt is for, set by the screen that asks. */
    @Volatile var reason: String? = null

    /** Whether a prompt is up: the app may look stopped meanwhile. */
    @Volatile var showing: Boolean = false

    override fun onActivityResumed(activity: Activity) {
        if (activity is FragmentActivity) foreground = activity
    }

    override fun onActivityPaused(activity: Activity) {
        if (foreground === activity) foreground = null
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
    override fun onActivityStarted(activity: Activity) {}
    override fun onActivityStopped(activity: Activity) {}
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
    override fun onActivityDestroyed(activity: Activity) {}
}

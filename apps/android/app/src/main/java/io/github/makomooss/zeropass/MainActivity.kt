package io.github.makomooss.zeropass

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.fragment.app.FragmentActivity
import io.github.makomooss.zeropass.ui.App
import io.github.makomooss.zeropass.ui.Tab
import io.github.makomooss.zeropass.ui.VaultModel

/**
 * The app's one screen (docs/spec/android.md §4). The vault itself is in the
 * isolated vault process ([VaultService], ADR-0012); [VaultModel] talks to it.
 */
class MainActivity : FragmentActivity() {
    private val model: VaultModel by viewModels()
    private var onScanned: ((String) -> Unit)? = null

    private val scanCode = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val code = result.data?.getStringExtra(QrScanActivity.EXTRA_CODE)
        val then = onScanned
        onScanned = null
        if (result.resultCode == RESULT_OK && code != null) then?.invoke(code)
    }

    private val askPermissions =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Nothing of the vault in screenshots or in the list of recent apps.
        // Debug builds allow screenshots for the tests on the emulator.
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        // No autofill service (ZeroPass's own included) reads or fills the vault's screens.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        setContent {
            App(model) { prefix, then ->
                onScanned = then
                scanCode.launch(Intent(this, QrScanActivity::class.java).putExtra(QrScanActivity.EXTRA_PREFIX, prefix))
            }
        }
        requestPermissions()
        runFromIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        runFromIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        model.onForeground()
    }

    override fun onStop() {
        super.onStop()
        model.onBackground()
    }

    private fun requestPermissions() {
        val wanted = buildList {
            add(Manifest.permission.CAMERA)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(Manifest.permission.BLUETOOTH_SCAN)
                add(Manifest.permission.BLUETOOTH_CONNECT)
            } else {
                add(Manifest.permission.ACCESS_FINE_LOCATION)
            }
        }.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (wanted.isNotEmpty()) askPermissions.launch(wanted.toTypedArray())
    }

    /**
     * Debug builds can be driven from a computer, for the tests on the
     * emulator and over Bluetooth without hands
     * (`adb shell am start -n <package>/.MainActivity -e do sync`). Release
     * builds ignore all of it.
     */
    private fun runFromIntent(intent: Intent?) {
        if (!BuildConfig.DEBUG || intent == null) return
        val action = intent.getStringExtra("do") ?: return
        val password = intent.getStringExtra("password") ?: ""
        val name = intent.getStringExtra("name") ?: VaultModel.defaultName
        when (action) {
            "create" -> model.create(password, password, name)
            "join" -> intent.getStringExtra("code")?.let { model.join(it, name, password, password) }
            "unlock" -> model.unlock(password)
            "lock" -> model.lock()
            "sync" -> {
                model.select(Tab.DEVICES)
                model.syncNow()
            }
            "codes" -> {
                model.select(Tab.CODES)
                model.showCodes()
            }
            "add-code" -> intent.getStringExtra("uri")?.let {
                model.select(Tab.CODES)
                model.addCode(it, "", "")
            }
            "tab" -> intent.getStringExtra("tab")?.let { model.select(Tab.valueOf(it.uppercase())) }
        }
    }
}

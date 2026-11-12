package io.github.makomooss.zeropass

import android.Manifest
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import java.io.File
import java.util.concurrent.Executors
import uniffi.zp_ffi.MobileVault
import uniffi.zp_ffi.announcesPairing
import uniffi.zp_ffi.bleUuids
import uniffi.zp_ffi.joinVault
import uniffi.zp_ffi.offerInfo
import uniffi.zp_ffi.recognisePeer
import uniffi.zp_ffi.syncWith

/**
 * The test app of the proximity-sync proof of concept (plan task P2-16): joins
 * a vault by scanning the code a desktop shows, and syncs with it, over
 * Bluetooth LE only. One plain screen; not the product UI.
 */
class MainActivity : ComponentActivity() {
    /** Everything that blocks (the Rust core, Bluetooth) runs here, in order. */
    private val worker = Executors.newSingleThreadExecutor()
    private val uuids = bleUuids()

    private lateinit var status: TextView
    private lateinit var deviceName: EditText
    private lateinit var password: EditText
    private lateinit var title: EditText
    private lateinit var username: EditText
    private lateinit var secret: EditText
    private lateinit var logView: TextView
    private val buttons = mutableListOf<Button>()

    private val vaultFile: File
        get() = File(filesDir, "vault.zpvault")

    private val scanCode = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val code = result.data?.getStringExtra(QrScanActivity.EXTRA_CODE)
        if (result.resultCode == RESULT_OK && code != null) join(code) else log("no code was scanned")
    }

    private val askPermissions =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
            val refused = granted.filterValues { !it }.keys
            if (refused.isNotEmpty()) log("not granted: ${refused.joinToString { it.substringAfterLast('.') }}")
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 48, 32, 32)
        }
        fun text(size: Float = 14f) = TextView(this).apply { textSize = size }.also(column::addView)
        fun field(hint: String, secret: Boolean = false) = EditText(this).apply {
            this.hint = hint
            inputType = InputType.TYPE_CLASS_TEXT or
                if (secret) InputType.TYPE_TEXT_VARIATION_PASSWORD else InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }.also(column::addView)
        fun button(label: String, action: () -> Unit) = Button(this).apply {
            text = label
            isAllCaps = false
            setOnClickListener { action() }
        }.also(column::addView).also(buttons::add)

        status = text(16f)
        deviceName = field("Name of this phone").apply { setText(Build.MODEL) }
        password = field("Master password of this phone (12+ characters)", secret = true)
        button("Scan a pairing code and join") { startScan() }
        button("Sync over Bluetooth") { sync() }
        button("Unlock and list logins") { list() }
        title = field("Title of a new login")
        username = field("User name")
        secret = field("Password to store", secret = true)
        button("Add the login") { addLogin() }
        button("Delete this phone's vault file") { deleteVault() }
        logView = text(12f).apply { setTextIsSelectable(true) }

        setContentView(
            ScrollView(this).apply {
                addView(column, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            },
        )
        refreshStatus()
        requestPermissions()
        runFromIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        runFromIntent(intent)
    }

    /**
     * Debug builds can be driven from a computer, so that the radio path can be
     * tested without hands:
     * `adb shell am start -n <package>/.MainActivity -e do sync -e password …`.
     * Release builds ignore all of it.
     */
    private fun runFromIntent(intent: Intent?) {
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val action = intent?.getStringExtra("do")
        if (!debuggable || intent == null || action == null) return
        intent.getStringExtra("password")?.let(password::setText)
        intent.getStringExtra("name")?.let(deviceName::setText)
        when (action) {
            "join" -> intent.getStringExtra("code")?.let(::join)
            "sync" -> sync()
            "list" -> list()
            "add" -> {
                title.setText(intent.getStringExtra("title") ?: "From the tablet")
                username.setText("tablet")
                secret.setText(intent.getStringExtra("secret") ?: "tablet-secret")
                addLogin()
            }
            "delete" -> deleteVault()
            else -> log("unknown debug action: $action")
        }
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

    private fun refreshStatus() {
        status.text = if (vaultFile.exists()) {
            "This phone has a vault file."
        } else {
            "No vault yet. On the PC run `zp-cli pair`, then scan the code."
        }
    }

    private fun log(line: String) {
        Log.i("ZeroPass", line)
        runOnUiThread { logView.text = "$line\n${logView.text}" }
    }

    /** Runs [task] on the worker thread with the buttons disabled meanwhile. */
    private fun work(what: String, task: () -> Unit) {
        buttons.forEach { it.isEnabled = false }
        log("— $what")
        worker.execute {
            val started = System.currentTimeMillis()
            try {
                task()
                log("done in ${System.currentTimeMillis() - started} ms")
            } catch (error: Exception) {
                log("failed: ${error.message ?: error.javaClass.simpleName}")
            }
            runOnUiThread {
                buttons.forEach { it.isEnabled = true }
                refreshStatus()
            }
        }
    }

    private fun startScan() {
        if (vaultFile.exists()) return log("this phone already has a vault; delete it first to join again")
        if (password.text.length < 12) return log("choose a master password of at least 12 characters first")
        if (deviceName.text.isBlank()) return log("give this phone a name first")
        scanCode.launch(Intent(this, QrScanActivity::class.java))
    }

    private fun join(code: String) {
        val masterPassword = password.text.toString()
        val name = deviceName.text.toString().trim()
        work("joining over Bluetooth") {
            val offer = offerInfo(code)
            val desktops = scanForDesktops(this, uuids, 4_000)
            log("${desktops.size} ZeroPass device(s) nearby")
            val (session, _) = connectToDesktop(this, uuids, desktops, ::log) { tag ->
                if (announcesPairing(tag, offer.pairingTag)) Unit else null
            } ?: throw BleException("the device showing the code was not found nearby")
            try {
                log("confirm \"$name\" on the PC")
                val outcome = joinVault(vaultFile.path, masterPassword, name, code, GattLink(session))
                log("joined vault ${outcome.vaultId.take(8)}… as device ${outcome.deviceId.take(8)}…")
                outcome.firstSync?.let { log("first sync: sent ${it.sent}, received ${it.received}") }
                outcome.firstSyncError?.let { log("first sync did not complete: $it") }
            } finally {
                session.close()
            }
        }
    }

    private fun sync() {
        if (!vaultFile.exists()) return log("join a vault first")
        work("syncing over Bluetooth") {
            val desktops = scanForDesktops(this, uuids, 4_000)
            log("${desktops.size} ZeroPass device(s) nearby")
            val (session, peer) = connectToDesktop(this, uuids, desktops, ::log) { tag ->
                recognisePeer(vaultFile.path, tag)
            } ?: throw BleException("no device of this vault was found nearby (is zp-syncd running on the PC?)")
            try {
                val outcome = syncWith(vaultFile.path, peer.deviceId, GattLink(session))
                log("synced with \"${peer.name}\": sent ${outcome.sent}, received ${outcome.received}")
            } finally {
                session.close()
            }
        }
    }

    private fun <T> withVault(action: (MobileVault) -> T): T {
        if (!vaultFile.exists()) throw IllegalStateException("join a vault first")
        return MobileVault.open(vaultFile.path).use { vault ->
            vault.unlock(password.text.toString())
            try {
                action(vault)
            } finally {
                vault.lock()
            }
        }
    }

    private fun list() {
        work("unlocking") {
            val lines = withVault { vault ->
                val logins = vault.logins().map { "  ${it.title} / ${it.username} / ${vault.loginPassword(it.id)}" }
                val devices = vault.devices().map {
                    "  ${it.name}${if (it.isThisDevice) " (this phone)" else ""}${if (it.revoked) " (revoked)" else ""}"
                }
                listOf("${logins.size} login(s):") + logins + listOf("${devices.size} device(s):") + devices
            }
            log(lines.joinToString("\n"))
        }
    }

    private fun addLogin() {
        val (newTitle, newUser, newSecret) = Triple(title.text.toString(), username.text.toString(), secret.text.toString())
        if (newTitle.isBlank()) return log("give the login a title")
        work("adding a login") {
            withVault { it.addLogin(newTitle, newUser, newSecret) }
            log("added \"$newTitle\"; sync to send it to the PC")
            runOnUiThread { listOf(title, username, secret).forEach { it.text.clear() } }
        }
    }

    private fun deleteVault() {
        work("deleting the vault file") {
            listOf("", "-wal", "-shm", "-journal").forEach { File(vaultFile.path + it).delete() }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        worker.shutdown()
        status.visibility = View.GONE
    }
}

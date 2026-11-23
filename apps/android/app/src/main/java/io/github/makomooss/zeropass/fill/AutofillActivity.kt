package io.github.makomooss.zeropass.fill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.View
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import io.github.makomooss.zeropass.BuildConfig
import io.github.makomooss.zeropass.Vault
import java.util.concurrent.Executors
import uniffi.zp_ffi.Domain
import uniffi.zp_ffi.VaultClient

/**
 * What the autofill service hands to a screen (docs/spec/android.md §6.2):
 * unlocking for the list of logins, the one login the user picked, and saving
 * what the user typed. It asks for the master password only when the vault is
 * locked; otherwise it does its work and closes at once.
 */
class AutofillActivity : FragmentActivity() {
    private val work = Executors.newSingleThreadExecutor()
    private var busy by mutableStateOf(false)
    private var error by mutableStateOf<String?>(null)
    private var asking by mutableStateOf(false)

    private val vault: VaultClient get() = Vault.client(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        setContent {
            if (asking) {
                UnlockForOthers(
                    why = if (intent.getStringExtra(MODE) == SAVE) "Unlock to save this login." else "Unlock to fill a login of ${shown(page)}.",
                    busy = busy,
                    error = error,
                    onUnlock = ::unlock,
                    onCancel = ::cancel,
                )
            }
        }
        whenUnlocked { proceed() }
    }

    private val page: String get() = intent.getStringExtra(PAGE).orEmpty()

    private fun shown(page: String) = page.removePrefix("https://").removePrefix("androidapp://")

    @Suppress("DEPRECATION")
    private fun id(name: String): AutofillId? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(name, AutofillId::class.java)
        } else {
            intent.getParcelableExtra(name)
        }

    /** Runs [block] off the main thread; asks for the master password if the vault is locked. */
    private fun whenUnlocked(block: () -> Unit) {
        busy = true
        work.execute {
            try {
                val unlocked = vault.status().domains.firstOrNull { it.domain == Domain.PASSWORD }?.unlocked == true
                if (!unlocked) {
                    runOnUiThread {
                        asking = true
                        busy = false
                    }
                    return@execute
                }
                block()
            } catch (failure: Exception) {
                runOnUiThread {
                    error = describe(failure)
                    asking = true
                    busy = false
                }
            }
        }
    }

    private fun unlock(password: String) {
        busy = true
        work.execute {
            try {
                vault.unlockPassword(password)
                runOnUiThread { error = null }
                proceed()
            } catch (failure: Exception) {
                runOnUiThread {
                    error = describe(failure)
                    busy = false
                }
            }
        }
    }

    /** The work of this screen, with the vault unlocked. Runs off the main thread. */
    private fun proceed() {
        when (intent.getStringExtra(MODE)) {
            UNLOCK -> {
                val form = Form(
                    packageName = "", webDomain = null, webScheme = null,
                    username = id(USERNAME_ID), password = id(PASSWORD_ID),
                    newPassword = false, usernameValue = null, passwordValue = null,
                )
                val builder = FillResponse.Builder()
                val logins = vault.pageLogins(page)
                for (login in logins.take(8)) builder.addDataset(ZeroPassAutofillService.dataset(this, form, page, login))
                if (logins.isEmpty()) {
                    finishWith(null, "No login of ZeroPass belongs to ${shown(page)}.")
                    return
                }
                finishWith(builder.build())
            }
            FILL -> {
                val credential = vault.pageCredential(page, intent.getStringExtra(ITEM).orEmpty())
                val dataset = Dataset.Builder()
                id(USERNAME_ID)?.let { dataset.setValue(it, AutofillValue.forText(credential.username)) }
                id(PASSWORD_ID)?.let { dataset.setValue(it, AutofillValue.forText(credential.password)) }
                finishWith(dataset.build())
            }
            SAVE -> {
                val save = PendingSaves.take(intent.getStringExtra(TOKEN))
                if (save == null) {
                    finishWith(null)
                    return
                }
                val comparison = vault.compareLoginOf(save)
                val message = when {
                    comparison.same -> "Already in ZeroPass."
                    comparison.id != null -> {
                        vault.updatePageLogin(save.page, comparison.id!!, save.password)
                        "Password updated in ZeroPass."
                    }
                    else -> {
                        vault.savePageLogin(save.page, save.title, save.username, save.password)
                        "Saved to ZeroPass."
                    }
                }
                finishWith(null, message)
            }
            else -> finishWith(null)
        }
    }

    private fun VaultClient.compareLoginOf(save: PendingSaves.Save) =
        comparePageLogin(save.page, save.username, save.password)

    /** Hands [result] (a dataset or a response) to the system and closes. */
    private fun finishWith(result: android.os.Parcelable?, message: String? = null) {
        runOnUiThread {
            if (result != null) {
                setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, result))
            } else {
                setResult(RESULT_CANCELED)
            }
            message?.let { Toast.makeText(this, it, Toast.LENGTH_SHORT).show() }
            finish()
        }
    }

    private fun cancel() {
        PendingSaves.take(intent.getStringExtra(TOKEN))
        setResult(RESULT_CANCELED)
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        work.shutdown()
    }

    companion object {
        private const val MODE = "mode"
        private const val UNLOCK = "unlock"
        private const val FILL = "fill"
        private const val SAVE = "save"
        private const val PAGE = "page"
        private const val ITEM = "item"
        private const val TOKEN = "token"
        private const val USERNAME_ID = "username-id"
        private const val PASSWORD_ID = "password-id"

        private fun intent(context: Context, mode: String) =
            Intent(context, AutofillActivity::class.java).putExtra(MODE, mode)

        fun unlock(context: Context, page: String, username: AutofillId?, password: AutofillId): PendingIntent =
            pending(context, intent(context, UNLOCK).putExtra(PAGE, page).putIds(username, password))

        fun fill(context: Context, page: String, item: String, username: AutofillId?, password: AutofillId?): PendingIntent =
            pending(context, intent(context, FILL).putExtra(PAGE, page).putExtra(ITEM, item).putIds(username, password))

        fun saveIntent(context: Context, token: String): Intent = intent(context, SAVE).putExtra(TOKEN, token)

        fun save(context: Context, token: String): PendingIntent = pending(context, saveIntent(context, token))
    }
}

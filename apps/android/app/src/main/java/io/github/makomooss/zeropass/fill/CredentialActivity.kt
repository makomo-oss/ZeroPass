package io.github.makomooss.zeropass.fill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.fragment.app.FragmentActivity
import io.github.makomooss.zeropass.BuildConfig
import io.github.makomooss.zeropass.Prompts
import io.github.makomooss.zeropass.Vault
import java.util.concurrent.Executors
import uniffi.zp_ffi.Domain
import uniffi.zp_ffi.Problem
import uniffi.zp_ffi.VaultClient
import uniffi.zp_ffi.ZpException

/**
 * The screens Credential Manager opens for ZeroPass (docs/spec/android.md
 * §6.3): unlocking to list, one picked passkey or password, and making a
 * passkey or saving a password. The Keystore prompt verifies the user for
 * passkeys; the master password is asked only when a password is needed and
 * the vault is locked.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialActivity : FragmentActivity() {
    private val work = Executors.newSingleThreadExecutor()
    private var busy by mutableStateOf(false)
    private var error by mutableStateOf<String?>(null)
    private var asking by mutableStateOf(false)

    private val vault: VaultClient get() = Vault.client(this)
    private val mode: String get() = intent.getStringExtra(MODE).orEmpty()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        setContent {
            if (asking) {
                UnlockForOthers(
                    why = "Unlock ZeroPass to use your saved passwords.",
                    busy = busy,
                    error = error,
                    onUnlock = ::unlock,
                    onCancel = ::cancel,
                )
            }
        }
        start()
    }

    private fun start() {
        busy = true
        work.execute {
            try {
                if (needsPassword() && !passwordUnlocked()) {
                    runOnUiThread {
                        asking = true
                        busy = false
                    }
                    return@execute
                }
                proceed()
            } catch (failure: Exception) {
                fail(failure)
            }
        }
    }

    private fun passwordUnlocked() =
        vault.status().domains.any { it.domain == Domain.PASSWORD && it.unlocked }

    /** Whether this screen's work needs the password domain. */
    private fun needsPassword(): Boolean = when (mode) {
        GET_PASSWORD, CREATE_PASSWORD -> true
        UNLOCK -> PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
            ?.beginGetCredentialOptions?.any { it is androidx.credentials.provider.BeginGetPasswordOption } == true
        else -> false
    }

    private fun unlock(password: String) {
        busy = true
        work.execute {
            try {
                vault.unlockPassword(password)
            } catch (failure: Exception) {
                runOnUiThread {
                    error = describe(failure)
                    busy = false
                }
                return@execute
            }
            runOnUiThread {
                asking = false
                error = null
            }
            try {
                proceed()
            } catch (failure: Exception) {
                fail(failure)
            }
        }
    }

    /** The work, with what it needs unlocked. Runs off the main thread. */
    private fun proceed() {
        val result = Intent()
        when (mode) {
            UNLOCK -> {
                val request = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent) ?: return cancel()
                Prompts.reason = "Use a passkey"
                val response = ZeroPassCredentialService.beginGet(
                    this,
                    request,
                    passkeys = { option, origin ->
                        val wanted = WebAuthnJson.request(option.requestJson, origin, option.clientDataHash)
                        vault.passkeyChoices(wanted).map { choice ->
                            PublicKeyCredentialEntry.Builder(
                                this,
                                choice.userName,
                                getPasskey(this, choice.credentialId),
                                option,
                            ).setDisplayName(choice.userDisplayName.ifEmpty { null }).build()
                        }
                    },
                    unlocked = true,
                )
                PendingIntentHandler.setBeginGetCredentialResponse(result, response)
            }
            GET_PASSKEY -> {
                val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return cancel()
                val option = request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull() ?: return cancel()
                val origin = browserOrigin(this, request.callingAppInfo) ?: return cancel()
                Prompts.reason = "Use a passkey"
                val wanted = WebAuthnJson.request(option.requestJson, origin, option.clientDataHash)
                val signed = vault.signWithPasskey(wanted, intent.getByteArrayExtra(CREDENTIAL) ?: return cancel())
                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(WebAuthnJson.assertion(signed))))
            }
            GET_PASSWORD -> {
                val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return cancel()
                val page = callerPage(this, request.callingAppInfo) ?: return cancel()
                if (page != intent.getStringExtra(PAGE)) return cancel()
                val credential = vault.pageCredential(page, intent.getStringExtra(ITEM).orEmpty())
                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PasswordCredential(credential.username, credential.password)))
            }
            CREATE_PASSKEY -> {
                val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: return cancel()
                val create = request.callingRequest as? CreatePublicKeyCredentialRequest ?: return cancel()
                val origin = browserOrigin(this, request.callingAppInfo) ?: return cancel()
                Prompts.reason = "Make a passkey"
                val made = vault.createPasskey(WebAuthnJson.creation(create.requestJson, origin, create.clientDataHash))
                PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(WebAuthnJson.registration(made)))
            }
            CREATE_PASSWORD -> {
                val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: return cancel()
                val create = request.callingRequest as? CreatePasswordRequest ?: return cancel()
                val page = callerPage(this, request.callingAppInfo) ?: return cancel()
                val comparison = vault.comparePageLogin(page, create.id, create.password)
                when {
                    comparison.same -> {}
                    comparison.id != null -> vault.updatePageLogin(page, comparison.id!!, create.password)
                    else -> vault.savePageLogin(page, "", create.id, create.password)
                }
                PendingIntentHandler.setCreateCredentialResponse(result, CreatePasswordResponse())
            }
            else -> return cancel()
        }
        runOnUiThread {
            setResult(RESULT_OK, result)
            finish()
        }
    }

    private fun fail(failure: Exception) {
        val cancelled = failure is ZpException.Failure && failure.problem == Problem.CANCELLED
        val result = Intent()
        when (mode) {
            CREATE_PASSKEY, CREATE_PASSWORD -> PendingIntentHandler.setCreateCredentialException(
                result,
                if (cancelled) CreateCredentialCancellationException(describe(failure)) else CreateCredentialUnknownException(describe(failure)),
            )
            UNLOCK -> {}
            else -> PendingIntentHandler.setGetCredentialException(
                result,
                if (cancelled) GetCredentialCancellationException(describe(failure)) else GetCredentialUnknownException(describe(failure)),
            )
        }
        runOnUiThread {
            setResult(if (mode == UNLOCK) RESULT_CANCELED else RESULT_OK, result)
            finish()
        }
    }

    private fun cancel() {
        runOnUiThread {
            setResult(RESULT_CANCELED)
            finish()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        work.shutdown()
    }

    companion object {
        private const val MODE = "mode"
        private const val UNLOCK = "unlock"
        private const val GET_PASSKEY = "get-passkey"
        private const val GET_PASSWORD = "get-password"
        private const val CREATE_PASSKEY = "create-passkey"
        private const val CREATE_PASSWORD = "create-password"
        private const val CREDENTIAL = "credential"
        private const val PAGE = "page"
        private const val ITEM = "item"

        private fun intent(context: Context, mode: String) =
            Intent(context, CredentialActivity::class.java).putExtra(MODE, mode)

        fun unlock(context: Context): PendingIntent = pending(context, intent(context, UNLOCK))

        fun getPasskey(context: Context, credentialId: ByteArray): PendingIntent =
            pending(context, intent(context, GET_PASSKEY).putExtra(CREDENTIAL, credentialId))

        fun getPassword(context: Context, page: String, item: String): PendingIntent =
            pending(context, intent(context, GET_PASSWORD).putExtra(PAGE, page).putExtra(ITEM, item))

        fun createPasskey(context: Context): PendingIntent = pending(context, intent(context, CREATE_PASSKEY))

        fun createPassword(context: Context): PendingIntent = pending(context, intent(context, CREATE_PASSWORD))
    }
}

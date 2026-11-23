package io.github.makomooss.zeropass.fill

import android.content.Context
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import io.github.makomooss.zeropass.Vault
import java.util.concurrent.Executors
import uniffi.zp_ffi.Domain
import uniffi.zp_ffi.VaultStatus

/** The web origin a privileged browser vouches for, or `null` (docs/spec/android.md §6.1). */
fun browserOrigin(context: Context, app: CallingAppInfo?): String? {
    if (app == null || app.packageName == context.packageName) return null
    return runCatching { app.getOrigin(Browsers.allowlist(context)) }.getOrNull()?.trimEnd('/')
}

/** The page of a caller: the origin a browser vouches for, or the app itself. */
fun callerPage(context: Context, app: CallingAppInfo?): String? {
    if (app == null || app.packageName == context.packageName) return null
    return browserOrigin(context, app) ?: Pages.app(app.packageName)
}

private fun VaultStatus.has(domain: Domain) = domains.any { it.domain == domain && it.available }

private fun VaultStatus.unlocked(domain: Domain) = domains.any { it.domain == domain && it.unlocked }

/**
 * ZeroPass as a Credential Manager provider (docs/spec/android.md §6.3):
 * passkeys for privileged browsers, passwords for browsers and apps. Nothing
 * secret is read here; the screens that the user picks do that.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class ZeroPassCredentialService : CredentialProviderService() {
    private val work = Executors.newSingleThreadExecutor()

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        work.execute {
            try {
                callback.onResult(beginGet(this, request))
            } catch (error: Exception) {
                Log.w(TAG, "credentials: ${error.message}")
                callback.onError(GetCredentialUnknownException(error.message))
            }
        }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        work.execute {
            try {
                callback.onResult(beginCreate(request))
            } catch (error: Exception) {
                Log.w(TAG, "credentials: ${error.message}")
                callback.onError(CreateCredentialUnknownException(error.message))
            }
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // ZeroPass keeps no sign-in state of other apps.
        callback.onResult(null)
    }

    private fun beginCreate(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse {
        val status = Vault.client(this).status()
        if (!status.exists) return BeginCreateCredentialResponse()
        val entry = when (request) {
            is BeginCreatePublicKeyCredentialRequest -> {
                if (browserOrigin(this, request.callingAppInfo) == null || !status.has(Domain.PASSKEY)) return BeginCreateCredentialResponse()
                CreateEntry.Builder("ZeroPass", CredentialActivity.createPasskey(this))
                    .setDescription("The passkey is kept in your ZeroPass vault and synced to your devices.")
                    .build()
            }
            is BeginCreatePasswordCredentialRequest -> {
                if (callerPage(this, request.callingAppInfo) == null) return BeginCreateCredentialResponse()
                CreateEntry.Builder("ZeroPass", CredentialActivity.createPassword(this)).build()
            }
            else -> return BeginCreateCredentialResponse()
        }
        return BeginCreateCredentialResponse(createEntries = listOf(entry))
    }

    override fun onDestroy() {
        super.onDestroy()
        work.shutdown()
    }

    companion object {
        private const val TAG = "ZeroPass"

        /**
         * What the selector lists for [request]. Passwords appear at once while
         * the password domain is open; anything else needs the user, behind
         * "Unlock ZeroPass". With [unlocked] (after the user did), the passkeys
         * are listed too, the user having just been verified.
         */
        fun beginGet(
            context: Context,
            request: BeginGetCredentialRequest,
            passkeys: (BeginGetPublicKeyCredentialOption, String) -> List<CredentialEntry> = { _, _ -> emptyList() },
            unlocked: Boolean = false,
        ): BeginGetCredentialResponse {
            val app = request.callingAppInfo
            val page = callerPage(context, app) ?: return BeginGetCredentialResponse()
            val origin = browserOrigin(context, app)
            val vault = Vault.client(context)
            val status = vault.status()
            if (!status.exists) return BeginGetCredentialResponse()
            val entries = mutableListOf<CredentialEntry>()
            var needsUser = false
            for (option in request.beginGetCredentialOptions) {
                when (option) {
                    is BeginGetPasswordOption -> {
                        if (!status.unlocked(Domain.PASSWORD)) {
                            needsUser = true
                            continue
                        }
                        for (login in vault.pageLogins(page)) {
                            entries += PasswordCredentialEntry.Builder(
                                context,
                                login.username.ifEmpty { login.title },
                                CredentialActivity.getPassword(context, page, login.id),
                                option,
                            ).setDisplayName(login.title).build()
                        }
                    }
                    is BeginGetPublicKeyCredentialOption -> {
                        if (origin == null || !status.has(Domain.PASSKEY)) continue
                        if (unlocked) entries += passkeys(option, origin) else needsUser = true
                    }
                }
            }
            val actions = if (needsUser && !unlocked) {
                listOf(AuthenticationAction("Unlock ZeroPass", CredentialActivity.unlock(context)))
            } else {
                emptyList()
            }
            return BeginGetCredentialResponse(credentialEntries = entries, authenticationActions = actions)
        }
    }
}

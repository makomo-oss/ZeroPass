package io.github.makomooss.zeropass.fill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import io.github.makomooss.zeropass.BuildConfig
import io.github.makomooss.zeropass.Vault
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import uniffi.zp_ffi.Domain
import uniffi.zp_ffi.PageLogin

/**
 * The page a form belongs to (docs/spec/android.md §6.1): the web page a
 * trusted browser reports, or the app itself. `null` for ZeroPass's own screens.
 */
fun pageOf(context: Context, form: Form): String? {
    if (form.packageName == context.packageName) return null
    if (form.webDomain != null && Browsers.isTrusted(context, form.packageName)) {
        Pages.web(form.webDomain, form.webScheme)?.let { return it }
    }
    return Pages.app(form.packageName)
}

/** What the user typed and agreed to save, kept in this process only. */
object PendingSaves {
    data class Save(val page: String, val title: String, val username: String, val password: String)

    private val saves = ConcurrentHashMap<String, Save>()
    private val random = SecureRandom()

    fun put(save: Save): String {
        val token = ByteArray(16).also(random::nextBytes).joinToString("") { "%02x".format(it) }
        saves[token] = save
        return token
    }

    fun take(token: String?): Save? = token?.let(saves::remove)
}

/**
 * ZeroPass as Android's autofill service (docs/spec/android.md §6.2). Offers
 * the logins of the page without their passwords; a password leaves the vault
 * process only for the login the user picks.
 */
class ZeroPassAutofillService : AutofillService() {
    private val work = Executors.newSingleThreadExecutor()

    override fun onFillRequest(request: FillRequest, cancellation: CancellationSignal, callback: FillCallback) {
        val form = readForm(request.fillContexts.last().structure)
        val page = pageOf(this, form)
        if (form.password == null || page == null) {
            callback.onSuccess(null)
            return
        }
        work.execute {
            val response = try {
                respond(this, form, page)
            } catch (error: Exception) {
                Log.w(TAG, "autofill: ${error.message}")
                null
            }
            if (!cancellation.isCanceled) callback.onSuccess(response)
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val form = readForm(request.fillContexts.last().structure)
        val page = pageOf(this, form)
        val password = form.passwordValue
        if (BuildConfig.DEBUG) Log.i(TAG, "save for $page: ${if (password.isNullOrEmpty()) "no password" else "a password"}")
        if (page == null || password.isNullOrEmpty()) {
            callback.onSuccess()
            return
        }
        val token = PendingSaves.put(PendingSaves.Save(page, "", form.usernameValue.orEmpty(), password))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            callback.onSuccess(AutofillActivity.save(this, token).intentSender)
        } else {
            startActivity(AutofillActivity.saveIntent(this, token).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            callback.onSuccess()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        work.shutdown()
    }

    companion object {
        private const val TAG = "ZeroPass"
        /** At most this many logins are offered. */
        private const val MAX_LOGINS = 8

        fun presentation(context: Context, text: String): RemoteViews =
            RemoteViews(context.packageName, android.R.layout.simple_list_item_1).apply {
                setTextViewText(android.R.id.text1, text)
            }

        /** One login to offer: no value until the user picks it. */
        fun dataset(context: Context, form: Form, page: String, login: PageLogin): Dataset {
            val label = listOf(login.title, login.username).filter { it.isNotBlank() }.joinToString(" · ")
            val builder = Dataset.Builder(presentation(context, label))
            for (id in form.ids) builder.setValue(id, null)
            builder.setAuthentication(AutofillActivity.fill(context, page, login.id, form.username, form.password).intentSender)
            return builder.build()
        }

        /** What to offer for [form] of [page]: the logins, or a way to unlock. */
        fun respond(context: Context, form: Form, page: String): FillResponse? {
            val password = form.password ?: return null
            val vault = Vault.client(context)
            val status = vault.status()
            if (!status.exists) return null
            val builder = FillResponse.Builder()
            val types = SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (form.username != null) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
            builder.setSaveInfo(
                SaveInfo.Builder(types, arrayOf(password))
                    .apply { form.username?.let { setOptionalIds(arrayOf(it)) } }
                    .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
                    .build(),
            )
            // A sign-up form: nothing to fill, only something to save.
            if (form.newPassword) return builder.build()
            val unlocked = status.domains.firstOrNull { it.domain == Domain.PASSWORD }?.unlocked == true
            if (BuildConfig.DEBUG) Log.i(TAG, "autofill for $page: ${if (unlocked) "unlocked" else "locked"}")
            if (!unlocked) {
                builder.setAuthentication(
                    form.ids.toTypedArray(),
                    AutofillActivity.unlock(context, page, form.username, password).intentSender,
                    presentation(context, "Unlock ZeroPass"),
                )
                return builder.build()
            }
            for (login in vault.pageLogins(page).take(MAX_LOGINS)) builder.addDataset(dataset(context, form, page, login))
            return builder.build()
        }
    }
}

/** Distinct request codes, so that the system keeps every pending intent. */
internal object RequestCodes {
    private var next = 0

    @Synchronized
    fun next(): Int = next++
}

internal fun pending(context: Context, intent: Intent): PendingIntent =
    PendingIntent.getActivity(
        context,
        RequestCodes.next(),
        intent,
        PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
    )

internal fun Intent.putIds(username: AutofillId?, password: AutofillId?): Intent =
    putExtra("username-id", username).putExtra("password-id", password)

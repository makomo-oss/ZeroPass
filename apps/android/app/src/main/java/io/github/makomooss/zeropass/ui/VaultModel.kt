package io.github.makomooss.zeropass.ui

import android.app.Application
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.makomooss.zeropass.Nearby
import io.github.makomooss.zeropass.Prompts
import io.github.makomooss.zeropass.SyncRecord
import io.github.makomooss.zeropass.SyncWorker
import io.github.makomooss.zeropass.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.zp_ffi.DeviceInfo
import uniffi.zp_ffi.Domain
import uniffi.zp_ffi.DomainState
import uniffi.zp_ffi.ItemContent
import uniffi.zp_ffi.ItemKind
import uniffi.zp_ffi.ItemList
import uniffi.zp_ffi.ItemSummary
import uniffi.zp_ffi.Problem
import uniffi.zp_ffi.VaultClient
import uniffi.zp_ffi.VaultStatus
import uniffi.zp_ffi.ZpException

/** The tabs of an unlocked vault (docs/spec/android.md §4). */
enum class Tab { VAULT, CODES, PASSKEYS, DEVICES, SETTINGS }

/** A one-time code on screen. */
data class Code(val id: String, val title: String, val account: String, val code: String, val secondsLeft: Int)

/** An item being read. */
data class OpenItem(val id: String, val content: ItemContent, val showPassword: Boolean = false)

/** A login or note being written; [id] is null for a new one. */
data class Draft(
    val id: String?,
    val kind: ItemKind,
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val urls: String = "",
    val notes: String = "",
)

/** A question for the user before going on. */
data class Question(val text: String, val yes: String, val onYes: () -> Unit)

/** Everything the screens show. */
data class UiState(
    /** `null` until the vault process answered. */
    val status: VaultStatus? = null,
    /** What is running, if anything. */
    val busy: String? = null,
    /** A message for the user, shown once. */
    val message: String? = null,
    val question: Question? = null,
    val tab: Tab = Tab.VAULT,
    val query: String = "",
    val items: ItemList? = null,
    val open: OpenItem? = null,
    val draft: Draft? = null,
    val codes: List<Code>? = null,
    val passkeys: List<ItemSummary>? = null,
    val devices: List<DeviceInfo> = emptyList(),
    /** What the last sync or pairing did. */
    val log: List<String> = emptyList(),
    /** A recovery key that was just made: shown once. */
    val recoveryKey: String? = null,
    /** When the last sync ran and what it did, for the Devices tab. */
    val lastSync: String = "",
    val backgroundSync: Boolean = true,
) {
    fun domain(domain: Domain): DomainState? = status?.domains?.firstOrNull { it.domain == domain }
    val unlocked: Boolean get() = domain(Domain.PASSWORD)?.unlocked == true
}

/**
 * The state of the screens and what they do with the vault. Every call to the
 * vault blocks (it is a request to the vault process), so it runs off the
 * main thread; one operation at a time.
 */
class VaultModel(application: Application) : AndroidViewModel(application) {
    var state by mutableStateOf(UiState())
        private set

    private val app get() = getApplication<Application>()
    private var polling: Job? = null
    private var codeTicker: Job? = null
    private var passwordHider: Job? = null
    private var backgroundLock: Job? = null
    private var syncing: Job? = null
    private var pendingSync: Job? = null

    private fun vault(): VaultClient = Vault.client(app)

    private suspend fun update(change: (UiState) -> UiState) = withContext(Dispatchers.Main) {
        state = change(state)
    }

    fun dismissMessage() {
        state = state.copy(message = null)
    }

    fun dismissQuestion() {
        state = state.copy(question = null)
    }

    fun ask(text: String, yes: String, onYes: () -> Unit) {
        state = state.copy(question = Question(text, yes) { state = state.copy(question = null); onYes() })
    }

    private fun describe(error: Throwable): String = when (error) {
        is ZpException.Failure -> when (error.problem) {
            Problem.WRONG_PASSWORD -> "Wrong master password."
            Problem.WEAK_PASSWORD -> "The master password needs at least 12 characters."
            Problem.CANCELLED -> "Not confirmed."
            Problem.HARDWARE_UNAVAILABLE -> "This phone cannot protect one-time codes and passkeys: ${error.detail}"
            Problem.LOCKED -> "Locked again; unlock and try once more."
            else -> error.detail.replaceFirstChar { it.uppercase() }
        }
        else -> error.message ?: error.javaClass.simpleName
    }.lineSequence().first()

    /**
     * Runs [block] off the main thread, one operation at a time, and reports
     * what went wrong. [failed] may handle a failure itself (return true).
     */
    private fun run(what: String, failed: (ZpException.Failure) -> Boolean = { false }, block: suspend () -> Unit) {
        if (state.busy != null) return
        state = state.copy(busy = what)
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { block() }
            } catch (error: ZpException.Failure) {
                if (!failed(error)) state = state.copy(message = describe(error))
            } catch (error: Exception) {
                Log.w(TAG, "$what failed", error)
                state = state.copy(message = describe(error))
            } finally {
                state = state.copy(busy = null)
                refresh()
            }
        }
    }

    // --- Status ---------------------------------------------------------------

    /** Reads the state of the vault (needs no key) and what the screens show of it. */
    fun refresh() {
        viewModelScope.launch {
            val status = try {
                withContext(Dispatchers.IO) { vault().status() }
            } catch (error: Exception) {
                Log.w(TAG, "status", error)
                return@launch
            }
            val wasUnlocked = state.unlocked
            state = state.copy(status = status)
            val unlocked = status.domains.firstOrNull { it.domain == Domain.PASSWORD }?.unlocked == true
            if (!unlocked) {
                // Locked (perhaps by the vault process): forget what was shown.
                state = state.copy(items = null, open = null, draft = null, codes = null, passkeys = null)
            } else if (!wasUnlocked || state.items == null) {
                loadItems()
            }
            if (state.codes != null && state.domain(Domain.TOTP)?.unlocked != true) state = state.copy(codes = null)
            if (state.passkeys != null && state.domain(Domain.PASSKEY)?.unlocked != true) state = state.copy(passkeys = null)
        }
    }

    /** The screen is shown: follow the vault's state. */
    fun onForeground() {
        backgroundLock?.cancel()
        showLastSync()
        if (System.currentTimeMillis() - SyncRecord.lastAt(app) > FOREGROUND_SYNC_MILLIS) quietSync()
        polling?.cancel()
        polling = viewModelScope.launch {
            while (isActive) {
                refresh()
                delay(POLL_MILLIS)
            }
        }
    }

    /**
     * The screen is hidden: the one-time codes and passkeys lock soon, unless
     * it was only the system's prompt that covered the screen.
     */
    fun onBackground() {
        polling?.cancel()
        backgroundLock?.cancel()
        backgroundLock = viewModelScope.launch {
            delay(BACKGROUND_LOCK_MILLIS)
            if (Prompts.showing) return@launch
            codeTicker?.cancel()
            state = state.copy(codes = null, passkeys = null, open = state.open?.copy(showPassword = false))
            withContext(Dispatchers.IO) {
                try {
                    val client = vault()
                    client.lock(Domain.TOTP)
                    client.lock(Domain.PASSKEY)
                } catch (_: Exception) {
                    // No vault, or those domains are not on this phone.
                }
            }
        }
    }

    fun select(tab: Tab) {
        state = state.copy(tab = tab, open = null, draft = null)
        when (tab) {
            Tab.DEVICES -> loadDevices()
            Tab.VAULT -> loadItems()
            else -> {}
        }
    }

    // --- Creating, joining, unlocking ---------------------------------------

    fun create(masterPassword: String, repeated: String, name: String, withoutHardware: Boolean = false) {
        if (masterPassword != repeated) {
            state = state.copy(message = "The two passwords differ.")
            return
        }
        run("Creating the vault", failed = { error ->
            if (error.problem != Problem.HARDWARE_UNAVAILABLE || withoutHardware) return@run false
            ask(
                "${describe(error)}\n\nCreate the vault without them? This phone can get them later from another device, or make them once a screen lock is set.",
                "Create without them",
            ) { create(masterPassword, repeated, name, withoutHardware = true) }
            true
        }) {
            Prompts.reason = "Protect the one-time codes and passkeys of the new vault"
            vault().create(masterPassword, name.trim(), withoutHardware)
            SyncWorker.schedule(app)
            update { it.copy(tab = Tab.VAULT) }
        }
    }

    fun join(code: String, name: String, masterPassword: String, repeated: String, withoutHardware: Boolean = false) {
        if (masterPassword != repeated) {
            state = state.copy(message = "The two passwords differ.")
            return
        }
        state = state.copy(log = emptyList())
        run("Joining over Bluetooth", failed = { error ->
            if (error.problem != Problem.HARDWARE_UNAVAILABLE || withoutHardware) return@run false
            ask(
                "${describe(error)}\n\nJoin without them? This phone can get them later.",
                "Join without them",
            ) { join(code, name, masterPassword, repeated, withoutHardware = true) }
            true
        }) {
            Prompts.reason = "Keep the one-time codes and passkeys on this phone"
            val outcome = Nearby.join(app, vault(), code, name.trim(), masterPassword, withoutHardware, ::log)
            outcome.firstSync?.let { log("first sync: received ${it.received} change(s)") }
            outcome.firstSyncError?.let { log("the first sync did not complete ($it); sync again later") }
            vault().lock(null)
            SyncWorker.schedule(app)
            update { it.copy(tab = Tab.VAULT) }
        }
    }

    fun unlock(masterPassword: String) {
        run("Unlocking") {
            vault().unlockPassword(masterPassword)
        }
    }

    fun lock() {
        run("Locking") { vault().lock(null) }
    }

    private fun log(line: String) {
        Log.i(TAG, line)
        viewModelScope.launch(Dispatchers.Main) { state = state.copy(log = state.log + line) }
    }

    // --- Logins and notes ---------------------------------------------------

    fun search(query: String) {
        state = state.copy(query = query)
        loadItems()
    }

    fun loadItems() {
        val query = state.query
        viewModelScope.launch {
            try {
                val items = withContext(Dispatchers.IO) { vault().list(Domain.PASSWORD, query) }
                if (state.query == query) state = state.copy(items = items)
            } catch (error: ZpException.Failure) {
                if (error.problem != Problem.LOCKED && error.problem != Problem.NO_VAULT) {
                    state = state.copy(message = describe(error))
                }
            } catch (error: Exception) {
                Log.w(TAG, "list", error)
            }
        }
    }

    fun openItem(id: String) {
        run("Opening") {
            val content = vault().get(id)
            update { it.copy(open = OpenItem(id, content)) }
        }
    }

    fun closeItem() {
        passwordHider?.cancel()
        state = state.copy(open = null)
    }

    /** Shows the password for [Clipboard.CLEAR_MILLIS] at most. */
    fun showPassword(show: Boolean) {
        val open = state.open ?: return
        state = state.copy(open = open.copy(showPassword = show))
        passwordHider?.cancel()
        if (show) {
            passwordHider = viewModelScope.launch {
                delay(SHOW_MILLIS)
                state = state.copy(open = state.open?.copy(showPassword = false))
            }
        }
    }

    fun newDraft(kind: ItemKind) {
        state = state.copy(draft = Draft(id = null, kind = kind), open = null)
    }

    fun editOpenItem() {
        val open = state.open ?: return
        state = state.copy(
            draft = when (val content = open.content) {
                is ItemContent.Login -> Draft(open.id, ItemKind.LOGIN, content.title, content.username, content.password, content.urls.joinToString("\n"), content.notes)
                is ItemContent.Note -> Draft(open.id, ItemKind.NOTE, content.title, notes = content.body)
                else -> return
            },
        )
    }

    fun changeDraft(draft: Draft) {
        state = state.copy(draft = draft)
    }

    fun cancelDraft() {
        state = state.copy(draft = null)
    }

    fun saveDraft() {
        val draft = state.draft ?: return
        if (draft.title.isBlank()) {
            state = state.copy(message = "Give it a title.")
            return
        }
        run("Saving") {
            val client = vault()
            val urls = draft.urls.lines().map { it.trim() }.filter { it.isNotEmpty() }
            val id = when (draft.kind) {
                ItemKind.NOTE -> draft.id?.also { client.updateNote(it, draft.title, draft.notes) }
                    ?: client.addNote(draft.title, draft.notes)
                else -> draft.id?.also { client.updateLogin(it, draft.title, draft.username, draft.password, urls, draft.notes) }
                    ?: client.addLogin(draft.title, draft.username, draft.password, urls, draft.notes)
            }
            val content = client.get(id)
            update { it.copy(draft = null, open = OpenItem(id, content)) }
            loadItems()
            changed()
        }
    }

    fun deleteOpenItem() {
        val open = state.open ?: return
        ask("Delete this item? The other devices delete it too when they sync.", "Delete") {
            run("Deleting") {
                vault().delete(open.id)
                update { it.copy(open = null) }
                loadItems()
                changed()
            }
        }
    }

    // --- One-time codes -------------------------------------------------------

    /** Opens the TOTP domain with the user (the Keystore prompt) and shows the codes. */
    fun showCodes() {
        run("Showing one-time codes") {
            Prompts.reason = "Show the one-time codes"
            val client = vault()
            client.lock(Domain.TOTP)
            client.unlock(Domain.TOTP)
            val codes = readCodes(client)
            update { it.copy(codes = codes) }
            startCodeTicker()
        }
    }

    private fun readCodes(client: VaultClient): List<Code> =
        client.list(Domain.TOTP, "").items.map { item ->
            val code = client.totpCode(item.id)
            Code(item.id, item.title, item.username, code.code, code.secondsRemaining.toInt())
        }

    private fun startCodeTicker() {
        codeTicker?.cancel()
        codeTicker = viewModelScope.launch {
            var shownFor = 0L
            while (isActive) {
                delay(1_000)
                shownFor += 1_000
                val codes = state.codes ?: break
                if (shownFor >= CODES_MILLIS) {
                    hideCodes()
                    break
                }
                if (codes.any { it.secondsLeft <= 1 }) {
                    val fresh = try {
                        withContext(Dispatchers.IO) { readCodes(vault()) }
                    } catch (_: Exception) {
                        null
                    }
                    state = state.copy(codes = fresh)
                    if (fresh == null) break
                } else {
                    state = state.copy(codes = codes.map { it.copy(secondsLeft = it.secondsLeft - 1) })
                }
            }
        }
    }

    fun hideCodes() {
        codeTicker?.cancel()
        state = state.copy(codes = null)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                vault().lock(Domain.TOTP)
            } catch (_: Exception) {
            }
        }
    }

    /**
     * Adds a one-time code from an `otpauth://` URI, or from a Base32 secret
     * with an issuer and an account.
     */
    fun addCode(secretOrUri: String, issuer: String, account: String) {
        val input = secretOrUri.trim()
        val uri = if (input.startsWith("otpauth://", ignoreCase = true)) {
            input
        } else {
            val secret = input.replace(" ", "").uppercase()
            val label = Uri.encode(if (issuer.isBlank()) account.trim() else "${issuer.trim()}:${account.trim()}")
            "otpauth://totp/$label?secret=$secret" + if (issuer.isBlank()) "" else "&issuer=${Uri.encode(issuer.trim())}"
        }
        run("Adding a one-time code") {
            Prompts.reason = "Add a one-time code"
            val client = vault()
            if (state.domain(Domain.TOTP)?.unlocked != true) client.unlock(Domain.TOTP)
            client.addTotp(uri, null)
            changed()
            val codes = readCodes(client)
            update { it.copy(codes = codes) }
            startCodeTicker()
        }
    }

    fun deleteCode(id: String) {
        ask("Delete this one-time code? The other devices delete it too when they sync.", "Delete") {
            run("Deleting") {
                vault().delete(id)
                changed()
                val codes = readCodes(vault())
            update { it.copy(codes = codes) }
            }
        }
    }

    // --- Passkeys -------------------------------------------------------------

    fun showPasskeys() {
        run("Showing passkeys") {
            Prompts.reason = "Show the passkeys"
            val client = vault()
            client.lock(Domain.PASSKEY)
            client.unlock(Domain.PASSKEY)
            val passkeys = client.list(Domain.PASSKEY, "").items
            update { it.copy(passkeys = passkeys) }
        }
    }

    fun hidePasskeys() {
        state = state.copy(passkeys = null)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                vault().lock(Domain.PASSKEY)
            } catch (_: Exception) {
            }
        }
    }

    fun deletePasskey(id: String) {
        ask("Delete this passkey? You can no longer sign in to the site with it, on any device.", "Delete") {
            run("Deleting") {
                val client = vault()
                client.delete(id)
                changed()
                val passkeys = client.list(Domain.PASSKEY, "").items
                update { it.copy(passkeys = passkeys) }
            }
        }
    }

    // --- Domains this phone does not have (ADR-0011) --------------------------

    fun setUp(domain: Domain) {
        run("Setting up") {
            Prompts.reason = "Protect the new keys"
            vault().setUpDomain(domain)
        }
    }

    fun receiveKeys(code: String) {
        state = state.copy(log = emptyList())
        run("Getting the keys over Bluetooth") {
            Prompts.reason = "Keep the one-time codes and passkeys on this phone"
            val outcome = Nearby.receiveKeys(app, vault(), code, ::log)
            log("received the keys of ${outcome.domains.size} domain(s)")
        }
    }

    // --- Devices ----------------------------------------------------------------

    fun loadDevices() {
        viewModelScope.launch {
            try {
                val devices = withContext(Dispatchers.IO) { vault().devices() }
                state = state.copy(devices = devices)
            } catch (error: Exception) {
                Log.w(TAG, "devices", error)
            }
        }
    }

    fun syncNow() {
        state = state.copy(log = emptyList())
        run("Syncing") {
            val synced = Nearby.sync(app, vault(), ::log)
            log(if (synced == 0) "nothing synced" else "synced with $synced device(s)")
            SyncRecord.save(app, synced, state.log.lastOrNull())
            withContext(Dispatchers.Main) { showLastSync() }
            loadItems()
            loadDevices()
        }
    }

    /** Unlocks the hardware-bound domains this phone has, for what needs them all. */
    private fun unlockEveryDomain(client: VaultClient) {
        for (domain in listOf(Domain.TOTP, Domain.PASSKEY)) {
            val domainState = client.status().domains.firstOrNull { it.domain == domain }
            if (domainState?.available == true && !domainState.unlocked) client.unlock(domain)
        }
    }

    fun revoke(device: DeviceInfo, evenWithoutKeys: Boolean = false) {
        run("Revoking", failed = { error ->
            if (error.problem != Problem.KEYS_AT_RISK || evenWithoutKeys) return@run false
            ask("${describe(error)}\n\nRevoke it anyway?", "Revoke anyway") { revoke(device, evenWithoutKeys = true) }
            true
        }) {
            Prompts.reason = "Revoke a device"
            val client = vault()
            unlockEveryDomain(client)
            client.revoke(device.id, evenWithoutKeys)
            loadDevices()
        }
    }

    // --- Settings -----------------------------------------------------------------

    fun createRecoveryKit(replace: Boolean = false) {
        run("Making a recovery kit", failed = { error ->
            if (error.problem != Problem.RECOVERY_KIT_EXISTS || replace) return@run false
            ask("A recovery kit exists. A new one makes the old recovery key useless.", "Make a new one") { createRecoveryKit(replace = true) }
            true
        }) {
            Prompts.reason = "Make a recovery kit"
            val client = vault()
            unlockEveryDomain(client)
            val key = client.createRecoveryKit(replace)
            update { it.copy(recoveryKey = key) }
        }
    }

    fun forgetRecoveryKey() {
        state = state.copy(recoveryKey = null)
    }

    fun changeMasterPassword(current: String, new: String, repeated: String) {
        if (new != repeated) {
            state = state.copy(message = "The two new passwords differ.")
            return
        }
        run("Changing the master password") {
            vault().changeMasterPassword(current, new)
            update { it.copy(message = "Changed. Unlock with the new master password.") }
        }
    }

    fun deleteVault() {
        ask("Delete the vault on this phone? The other devices keep theirs; join again to get it back.", "Delete") {
            run("Deleting the vault") {
                Vault.close()
                val file = Vault.file(app)
                listOf("", ".tmp").forEach { java.io.File(file.path + it).delete() }
                SyncWorker.schedule(app)
                update { UiState() }
            }
        }
    }

    // --- Sync without asking -------------------------------------------------

    private fun showLastSync() {
        val at = SyncRecord.lastAt(app)
        val text = if (at == 0L) {
            "Not synced yet."
        } else {
            val minutes = (System.currentTimeMillis() - at) / 60_000
            val ago = if (minutes < 1) "just now" else "$minutes min ago"
            "Last sync $ago: ${SyncRecord.lastSummary(app)}"
        }
        state = state.copy(lastSync = text, backgroundSync = SyncRecord.background(app))
    }

    /** Syncs without showing progress: when the app opens, and after a change. */
    private fun quietSync() {
        if (!Vault.file(app).exists() || syncing?.isActive == true) return
        syncing = viewModelScope.launch {
            val lines = mutableListOf<String>()
            try {
                val synced = withContext(Dispatchers.IO) { Nearby.sync(app, vault()) { lines += it } }
                SyncRecord.save(app, synced, lines.lastOrNull())
                if (synced > 0 && state.unlocked) loadItems()
            } catch (error: Exception) {
                Log.i(TAG, "sync: ${error.message}")
            }
            showLastSync()
        }
    }

    /** Something changed here: send it to the devices nearby soon. */
    private fun changed() {
        pendingSync?.cancel()
        pendingSync = viewModelScope.launch {
            delay(CHANGE_SYNC_MILLIS)
            quietSync()
        }
    }

    fun setBackgroundSync(on: Boolean) {
        SyncRecord.setBackground(app, on)
        showLastSync()
    }

    companion object {
        private const val TAG = "ZeroPass"
        /** Sync when the app opens if the last sync is older than this. */
        private const val FOREGROUND_SYNC_MILLIS = 60_000L
        /** How long after a change to sync it. */
        private const val CHANGE_SYNC_MILLIS = 10_000L
        private const val POLL_MILLIS = 5_000L
        /** How long the app may be away before the one-time codes and passkeys lock. */
        private const val BACKGROUND_LOCK_MILLIS = 10_000L
        private const val SHOW_MILLIS = 30_000L
        /** How long one-time codes stay on screen. */
        private const val CODES_MILLIS = 60_000L

        /** A name for this phone in the vault. */
        val defaultName: String = Build.MODEL ?: "Android"
    }
}

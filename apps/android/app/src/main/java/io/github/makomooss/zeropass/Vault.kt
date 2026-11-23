package io.github.makomooss.zeropass

import android.content.Context
import java.io.File
import uniffi.zp_ffi.VaultClient

/**
 * The vault, as the app process holds it: a client of the vault process, which
 * stores the vault file in [file] for it. Open it off the main thread.
 */
object Vault {
    private var binding: VaultBinding? = null
    private var client: VaultClient? = null

    fun file(context: Context) = File(context.filesDir, "vault.zpvault")

    /** The client, connecting to the vault process on first use. */
    @Synchronized
    fun client(context: Context): VaultClient {
        client?.let { return it }
        val app = context.applicationContext
        val binding = VaultBinding(app).also { binding = it }
        return VaultClient.open(binding, file(app).path, null).also { client = it }
    }

    /** Closes the vault: the vault process wipes its keys and ends. */
    @Synchronized
    fun close() {
        client?.close()
        client = null
        binding?.unbind()
        binding = null
    }
}

package io.github.makomooss.zeropass

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.ParcelFileDescriptor
import uniffi.zp_ffi.serveVaultConnection

/**
 * The vault process (ADR-0012): an isolated process without permissions,
 * files or network. It runs the vault daemon of the Rust core, which keeps the
 * vault in memory; the app process stores the file and answers for the
 * Android Keystore. Only the app itself can bind it (not exported).
 */
class VaultService : Service() {
    private val binder = object : IVaultService.Stub() {
        override fun connect(socket: ParcelFileDescriptor) {
            // The core owns the descriptor from here on and closes it.
            serveVaultConnection(socket.detachFd())
        }
    }

    override fun onBind(intent: Intent): IBinder = binder
}

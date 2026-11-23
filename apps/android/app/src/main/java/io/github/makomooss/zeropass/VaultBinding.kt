package io.github.makomooss.zeropass

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import uniffi.zp_ffi.LinkException
import uniffi.zp_ffi.VaultConnector

/**
 * The app process's way to the vault process (docs/spec/android.md §2): keeps
 * the isolated [VaultService] bound and opens connections to it, one socket
 * pair per connection.
 */
class VaultBinding(private val context: Context) : VaultConnector {
    @Volatile private var service: IVaultService? = null
    @Volatile private var bound = CountDownLatch(1)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = IVaultService.Stub.asInterface(binder)
            bound.countDown()
        }

        override fun onServiceDisconnected(name: ComponentName) {
            // The vault process died (and with it the keys); Android starts a
            // new one, which knows no vault until the image host attaches.
            service = null
            bound = CountDownLatch(1)
        }
    }

    init {
        val intent = Intent(context, VaultService::class.java)
        check(context.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            "the vault service cannot be bound"
        }
    }

    override fun connect(): Int {
        check(Looper.myLooper() != Looper.getMainLooper()) { "connect off the main thread" }
        if (!bound.await(10, TimeUnit.SECONDS)) throw LinkException.Unexpected("the vault process did not start")
        val vault = service ?: throw LinkException.Closed()
        val pair = ParcelFileDescriptor.createSocketPair()
        val (mine, theirs) = pair[0] to pair[1]
        try {
            vault.connect(theirs)
        } catch (error: Exception) {
            mine.close()
            throw LinkException.Unexpected("the vault process: ${error.message}")
        } finally {
            theirs.close()
        }
        return mine.detachFd()
    }

    /** Lets the vault process go: Android ends it, and its keys with it. */
    fun unbind() {
        context.unbindService(connection)
    }
}

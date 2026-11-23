package io.github.makomooss.zeropass

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import uniffi.zp_ffi.JoinOutcome
import uniffi.zp_ffi.VaultClient
import uniffi.zp_ffi.announcesPairing
import uniffi.zp_ffi.bleUuids
import uniffi.zp_ffi.offerInfo

/**
 * The other devices (docs/spec/android.md §5): pairing over Bluetooth LE, and
 * sync over the local network first and Bluetooth LE for the devices not
 * reached there. The app process holds the connections; the vault process
 * handles what passes through them. Every function blocks: call it off the
 * main thread.
 */
object Nearby {
    private val uuids = bleUuids()

    /** How long to scan for the devices of the vault. */
    private const val SCAN_MILLIS = 4_000L

    /** How long to listen for the devices on the local network. */
    private const val DISCOVER_MILLIS = 2_500u

    /** Finds the device that shows [code] and runs [pairing] over a link to it. */
    private fun <T> withOfferingDevice(context: Context, code: String, log: (String) -> Unit, pairing: (GattLink) -> T): T {
        val offer = offerInfo(code)
        val desktops = scanForDesktops(context, uuids, SCAN_MILLIS)
        log("${desktops.size} ZeroPass device(s) nearby")
        val (session, _) = connectToDesktop(context, uuids, desktops, log) { tag ->
            if (announcesPairing(tag, offer.pairingTag)) Unit else null
        } ?: throw BleException("the device showing the code was not found nearby; is its Bluetooth on?")
        try {
            return pairing(GattLink(session))
        } finally {
            session.close()
        }
    }

    /**
     * Joins the vault of the device that shows [code]. Its user confirms
     * [name]; this phone's vault gets [masterPassword]. Unless
     * [withoutHardware], the Keystore protects the TOTP and passkey keys.
     */
    fun join(
        context: Context,
        vault: VaultClient,
        code: String,
        name: String,
        masterPassword: String,
        withoutHardware: Boolean,
        log: (String) -> Unit,
    ): JoinOutcome = withOfferingDevice(context, code, log) { link ->
        log("confirm \"$name\" on the other device")
        vault.join(code, name, masterPassword, withoutHardware, link)
    }

    /** Receives the TOTP and passkey keys from the device that shows [code] (ADR-0011). */
    fun receiveKeys(context: Context, vault: VaultClient, code: String, log: (String) -> Unit): JoinOutcome =
        withOfferingDevice(context, code, log) { link ->
            log("confirm on the other device")
            vault.receiveKeys(code, link)
        }

    /** Whether this device is on a Wi-Fi network (the local network of docs/spec/lan.md). */
    private fun onWifi(context: Context): Boolean {
        val connectivity = context.getSystemService(ConnectivityManager::class.java) ?: return false
        val network = connectivity.activeNetwork ?: return false
        return connectivity.getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
    }

    /**
     * Syncs with the devices found on the local network. Android drops
     * multicast packets (mDNS) unless an app holds a multicast lock.
     */
    private fun syncOnWifi(context: Context, vault: VaultClient, log: (String) -> Unit): Set<String> {
        val wifi = context.applicationContext.getSystemService(WifiManager::class.java)
        val lock = wifi?.createMulticastLock("zeropass-discovery")
        lock?.acquire()
        try {
            val synced = mutableSetOf<String>()
            for (result in vault.syncOnLan(DISCOVER_MILLIS)) {
                val outcome = result.outcome
                if (outcome != null) {
                    synced += result.peer.deviceId
                    log("Wi-Fi: synced with \"${result.peer.name}\": sent ${outcome.sent}, received ${outcome.received}")
                } else {
                    log("Wi-Fi: \"${result.peer.name}\" did not answer: ${result.error}")
                }
            }
            return synced
        } finally {
            lock?.release()
        }
    }

    /**
     * One round of sync (docs/spec/lan.md §6): the local network first,
     * Bluetooth for the devices that were not reached there, never both for
     * the same device. Returns how many devices were synced with.
     */
    @Synchronized
    fun sync(context: Context, vault: VaultClient, log: (String) -> Unit): Int {
        val others = vault.otherDevices()
        if (others.isEmpty()) {
            log("this vault has no other device")
            return 0
        }
        val synced = if (onWifi(context)) syncOnWifi(context, vault, log) else emptySet<String>().also { log("no Wi-Fi: Bluetooth only") }
        if (others.all { it.deviceId in synced }) return synced.size

        // Bluetooth may be off: what the local network did still counts.
        val desktops = try {
            scanForDesktops(context, uuids, SCAN_MILLIS)
        } catch (error: BleException) {
            log("Bluetooth: ${error.message}")
            return synced.size
        }
        val found = connectToDesktop(context, uuids, desktops, log) { tag ->
            vault.recognisePeer(tag)?.takeIf { it.deviceId !in synced }
        }
        if (found == null) {
            log(if (synced.isEmpty()) "no device of this vault is nearby" else "the other devices of this vault are not nearby")
            return synced.size
        }
        val (session, peer) = found
        try {
            val outcome = vault.syncWith(peer.deviceId, GattLink(session))
            log("Bluetooth: synced with \"${peer.name}\": sent ${outcome.sent}, received ${outcome.received}")
        } finally {
            session.close()
        }
        return synced.size + 1
    }
}

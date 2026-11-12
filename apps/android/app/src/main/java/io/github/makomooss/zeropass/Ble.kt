package io.github.makomooss.zeropass

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import java.util.UUID
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import uniffi.zp_ffi.BleUuids
import uniffi.zp_ffi.ByteLink
import uniffi.zp_ffi.LinkException

/** Something went wrong on the radio. The message is shown to the user. */
class BleException(message: String) : Exception(message)

private val CLIENT_CONFIG: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

/**
 * Scans for desktops that offer the ZeroPass service (docs/spec/ble.md §3.1).
 * Blocks for [millis] and returns the devices seen, strongest signal first.
 */
@SuppressLint("MissingPermission")
fun scanForDesktops(context: Context, uuids: BleUuids, millis: Long): List<BluetoothDevice> {
    val manager = context.getSystemService(BluetoothManager::class.java)
    val adapter = manager?.adapter ?: throw BleException("this device has no Bluetooth")
    if (!adapter.isEnabled) throw BleException("Bluetooth is switched off")
    val scanner = adapter.bluetoothLeScanner ?: throw BleException("Bluetooth LE scanning is unavailable")

    val seen = LinkedHashMap<String, Pair<BluetoothDevice, Int>>()
    var failure: Int? = null
    val callback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            synchronized(seen) {
                val known = seen[result.device.address]
                if (known == null || known.second < result.rssi) {
                    seen[result.device.address] = result.device to result.rssi
                }
            }
        }

        override fun onScanFailed(errorCode: Int) {
            failure = errorCode
        }
    }
    val filter = ScanFilter.Builder()
        .setServiceUuid(ParcelUuid(UUID.fromString(uuids.service)))
        .build()
    val settings = ScanSettings.Builder()
        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
        .build()
    scanner.startScan(listOf(filter), settings, callback)
    try {
        Thread.sleep(millis)
    } finally {
        scanner.stopScan(callback)
    }
    failure?.let { throw BleException("the scan failed (code $it)") }
    return synchronized(seen) { seen.values.sortedByDescending { it.second }.map { it.first } }
}

/**
 * One GATT connection to a desktop, driven with blocking calls from a worker
 * thread. The link of docs/spec/ble.md §5: bytes written to `Rx` and notified
 * on `Tx`.
 */
@SuppressLint("MissingPermission")
class GattSession(
    private val context: Context,
    private val device: BluetoothDevice,
    private val uuids: BleUuids,
) : BluetoothGattCallback() {

    private sealed interface Event
    private data class Connection(val connected: Boolean, val status: Int) : Event
    private data class Mtu(val mtu: Int, val status: Int) : Event
    private data class Services(val status: Int) : Event
    private class Read(val value: ByteArray, val status: Int) : Event
    private data class Subscribed(val status: Int) : Event
    private data class Written(val status: Int) : Event

    private val events = LinkedBlockingQueue<Event>()
    private val incoming = LinkedBlockingQueue<ByteArray>()

    @Volatile
    var isClosed = false
        private set

    private var gatt: BluetoothGatt? = null
    private var tag: BluetoothGattCharacteristic? = null
    private var rx: BluetoothGattCharacteristic? = null
    private var tx: BluetoothGattCharacteristic? = null

    /** The largest packet: ATT MTU − 3. */
    var packetSize = 20
        private set

    private inline fun <reified T : Event> await(timeoutMs: Long, what: String): T {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0) throw BleException("timed out waiting for $what")
            val event = events.poll(remaining, TimeUnit.MILLISECONDS) ?: continue
            if (event is T) return event
            if (event is Connection && !event.connected) {
                throw BleException("disconnected while waiting for $what (status ${event.status})")
            }
            // Anything else is left over from an earlier step.
        }
    }

    private fun gatt(): BluetoothGatt = gatt ?: throw BleException("not connected")

    /** Connects, asks for a large MTU and finds the three characteristics. */
    fun connect() {
        gatt = device.connectGatt(context, false, this, BluetoothDevice.TRANSPORT_LE)
            ?: throw BleException("the connection could not be started")
        val connection = await<Connection>(15_000, "the connection")
        if (!connection.connected) throw BleException("could not connect (status ${connection.status})")

        if (gatt().requestMtu(517)) {
            val mtu = await<Mtu>(5_000, "the MTU")
            if (mtu.status == BluetoothGatt.GATT_SUCCESS) packetSize = mtu.mtu - 3
        }
        if (!gatt().discoverServices()) throw BleException("service discovery could not be started")
        val services = await<Services>(15_000, "service discovery")
        if (services.status != BluetoothGatt.GATT_SUCCESS) {
            throw BleException("service discovery failed (status ${services.status})")
        }
        val service = gatt().getService(UUID.fromString(uuids.service))
            ?: throw BleException("the device does not offer the ZeroPass service")
        tag = service.getCharacteristic(UUID.fromString(uuids.tag))
        rx = service.getCharacteristic(UUID.fromString(uuids.rx))
        tx = service.getCharacteristic(UUID.fromString(uuids.tx))
        if (tag == null || rx == null || tx == null) {
            throw BleException("the ZeroPass service is incomplete")
        }
    }

    /** Reads the `Tag` characteristic: which device this is (ble.md §4). */
    fun readTag(): ByteArray {
        if (!gatt().readCharacteristic(tag)) throw BleException("the tag could not be read")
        val read = await<Read>(5_000, "the tag")
        if (read.status != BluetoothGatt.GATT_SUCCESS) throw BleException("reading the tag failed (status ${read.status})")
        return read.value
    }

    /** Subscribes to `Tx`, which opens the link on the desktop's side. */
    fun subscribe() {
        val tx = tx ?: throw BleException("not connected")
        if (!gatt().setCharacteristicNotification(tx, true)) throw BleException("notifications could not be enabled")
        val descriptor = tx.getDescriptor(CLIENT_CONFIG)
            ?: throw BleException("the Tx characteristic cannot be subscribed to")
        val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt().writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) ==
                BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            @Suppress("DEPRECATION")
            gatt().writeDescriptor(descriptor)
        }
        if (!started) throw BleException("the subscription could not be started")
        val subscribed = await<Subscribed>(5_000, "the subscription")
        if (subscribed.status != BluetoothGatt.GATT_SUCCESS) {
            throw BleException("subscribing failed (status ${subscribed.status})")
        }
    }

    private fun startWrite(chunk: ByteArray): Boolean {
        val rx = rx ?: throw BleException("not connected")
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt().writeCharacteristic(
                rx,
                chunk,
                BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE,
            ) == BluetoothStatusCodes.SUCCESS
        } else {
            rx.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            @Suppress("DEPRECATION")
            rx.value = chunk
            @Suppress("DEPRECATION")
            gatt().writeCharacteristic(rx)
        }
    }

    /**
     * Sends [bytes] in packets, each only after the stack has taken the one
     * before (ble.md §5.2).
     */
    fun write(bytes: ByteArray) {
        var offset = 0
        while (offset < bytes.size) {
            if (isClosed) throw BleException("the link is closed")
            val end = minOf(offset + packetSize, bytes.size)
            val chunk = bytes.copyOfRange(offset, end)
            // The stack refuses a write while it is busy with the previous one.
            var attempts = 0
            while (!startWrite(chunk)) {
                if (isClosed || ++attempts > 200) throw BleException("the packet could not be sent")
                Thread.sleep(10)
            }
            val written = await<Written>(10_000, "a packet to be sent")
            if (written.status != BluetoothGatt.GATT_SUCCESS) {
                throw BleException("sending failed (status ${written.status})")
            }
            offset = end
        }
    }

    /** The next packet from the desktop, or `null` if none arrived in time. */
    fun read(timeoutMs: Long): ByteArray? = incoming.poll(timeoutMs, TimeUnit.MILLISECONDS)

    /** Unsubscribes and disconnects (ble.md §5.3). */
    fun close() {
        if (isClosed) return
        isClosed = true
        val gatt = gatt ?: return
        runCatching { tx?.let { gatt.setCharacteristicNotification(it, false) } }
        runCatching { gatt.disconnect() }
        runCatching { gatt.close() }
    }

    // Callbacks from the Bluetooth stack (binder threads).

    override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
        val connected = newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS
        if (!connected) isClosed = true
        events.add(Connection(connected, status))
    }

    override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
        events.add(Mtu(mtu, status))
    }

    override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
        events.add(Services(status))
    }

    // Android 13 and later.
    override fun onCharacteristicRead(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
        status: Int,
    ) {
        events.add(Read(value, status))
    }

    // Android 12 and earlier.
    @Deprecated("Deprecated in Java")
    override fun onCharacteristicRead(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        status: Int,
    ) {
        @Suppress("DEPRECATION")
        events.add(Read(characteristic.value ?: ByteArray(0), status))
    }

    override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
        events.add(Subscribed(status))
    }

    override fun onCharacteristicWrite(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        status: Int,
    ) {
        events.add(Written(status))
    }

    // Android 13 and later.
    override fun onCharacteristicChanged(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
    ) {
        if (value.isNotEmpty()) incoming.add(value)
    }

    // Android 12 and earlier.
    @Deprecated("Deprecated in Java")
    override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
        @Suppress("DEPRECATION")
        val value = characteristic.value
        if (value != null && value.isNotEmpty()) incoming.add(value.copyOf())
    }
}

/** The byte stream the Rust core runs pairing and sync on. */
class GattLink(private val session: GattSession) : ByteLink {
    override fun read(timeoutMs: UInt): ByteArray {
        val packet = session.read(timeoutMs.toLong())
        if (packet != null) return packet
        if (session.isClosed) throw LinkException.Closed("the Bluetooth link is closed")
        return ByteArray(0)
    }

    override fun write(bytes: ByteArray) {
        try {
            session.write(bytes)
        } catch (error: BleException) {
            throw LinkException.Closed(error.message ?: "the Bluetooth link is closed")
        }
    }
}

/**
 * Connects to the desktops found by a scan, one after the other, and returns
 * the first whose tag [wanted] accepts, subscribed and ready to be used as a
 * link. Desktops of other vaults are disconnected without sending anything
 * (ble.md §4). Returns `null` if none matches.
 */
fun <T> connectToDesktop(
    context: Context,
    uuids: BleUuids,
    devices: List<BluetoothDevice>,
    log: (String) -> Unit,
    wanted: (ByteArray) -> T?,
): Pair<GattSession, T>? {
    for (device in devices) {
        val session = GattSession(context, device, uuids)
        try {
            session.connect()
            val match = wanted(session.readTag())
            if (match != null) {
                session.subscribe()
                log("connected (packets of ${session.packetSize} bytes)")
                return session to match
            }
            log("a ZeroPass device of another vault is nearby; skipped")
        } catch (error: BleException) {
            log("a nearby device did not answer: ${error.message}")
        }
        session.close()
    }
    return null
}

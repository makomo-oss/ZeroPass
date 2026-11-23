package io.github.makomooss.zeropass

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Sync in the background (docs/spec/android.md §5): every 15 minutes at most,
 * when the battery is not low, the local network first and Bluetooth LE for
 * the devices not reached there. Needs no key: only ciphertext passes.
 */
class SyncWorker(context: Context, parameters: WorkerParameters) : Worker(context, parameters) {
    override fun doWork(): Result {
        val context = applicationContext
        if (!Vault.file(context).exists()) return Result.success()
        val lines = mutableListOf<String>()
        try {
            val synced = Nearby.sync(context, Vault.client(context)) { line ->
                Log.i(TAG, "background sync: $line")
                lines += line
            }
            SyncRecord.save(context, synced, lines.lastOrNull())
        } catch (error: Exception) {
            Log.w(TAG, "background sync failed", error)
            SyncRecord.save(context, 0, error.message)
        } finally {
            // Nobody is looking: let the vault process go, keys and all.
            if (Prompts.foreground == null) Vault.close()
        }
        return Result.success()
    }

    companion object {
        private const val TAG = "ZeroPass"
        private const val WORK = "background-sync"

        /** Starts or stops syncing in the background, as the settings say. */
        fun schedule(context: Context) {
            val work = WorkManager.getInstance(context)
            if (!SyncRecord.background(context) || !Vault.file(context).exists()) {
                work.cancelUniqueWork(WORK)
                return
            }
            val request = PeriodicWorkRequestBuilder<SyncWorker>(15, TimeUnit.MINUTES)
                .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
                .build()
            work.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.KEEP, request)
        }
    }
}

/** When the last sync ran and what it did, and whether to sync in the background. */
object SyncRecord {
    private const val PREFERENCES = "sync"

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun save(context: Context, devices: Int, summary: String?) {
        preferences(context).edit()
            .putLong("at", System.currentTimeMillis())
            .putInt("devices", devices)
            .putString("summary", summary ?: "")
            .apply()
    }

    /** When the last sync ran, in milliseconds since the epoch; 0 if never. */
    fun lastAt(context: Context): Long = preferences(context).getLong("at", 0)

    fun lastSummary(context: Context): String = preferences(context).getString("summary", "") ?: ""

    fun background(context: Context): Boolean = preferences(context).getBoolean("background", true)

    fun setBackground(context: Context, on: Boolean) {
        preferences(context).edit().putBoolean("background", on).apply()
        SyncWorker.schedule(context)
    }
}

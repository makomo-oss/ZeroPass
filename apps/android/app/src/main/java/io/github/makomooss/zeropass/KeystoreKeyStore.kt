package io.github.makomooss.zeropass

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import uniffi.zp_ffi.HardwareException
import uniffi.zp_ffi.PlatformKeyStore

/**
 * The hardware key store of docs/spec/crypto.md §7.2: an HMAC-SHA256 key in the
 * Android Keystore that needs the user (biometrics or the screen lock) for
 * every use. The vault process asks through the key agent relay; the HMAC of
 * its challenge goes back sealed to it (docs/spec/android.md §3).
 *
 * Both calls block the calling thread (the Rust key agent's) while the user
 * answers a prompt on the foreground screen ([Prompts]).
 */
class KeystoreKeyStore(context: Context) : PlatformKeyStore {
    private val context = context.applicationContext

    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun key(): SecretKey? = keyStore().getKey(ALIAS, null) as SecretKey?

    private fun ensureSecureLockScreen() {
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        if (keyguard?.isDeviceSecure != true) {
            throw HardwareException.Unavailable("set a screen lock (PIN, pattern or password) first")
        }
    }

    override fun probe(create: Boolean): UByte {
        ensureSecureLockScreen()
        if (key() != null) return IMPLEMENTATION_ID
        if (!create) throw HardwareException.Unavailable("this device has no ZeroPass key in its Keystore")
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        try {
            generate(strongBox)
        } catch (error: StrongBoxUnavailableException) {
            generate(false)
        } catch (error: Exception) {
            if (!strongBox) throw HardwareException.Failed("the key cannot be made: ${error.message}")
            generate(false)
        }
        Log.i(TAG, "made the hardware key (${where()})")
        return IMPLEMENTATION_ID
    }

    @Suppress("DEPRECATION") // The duration setter is the only way before Android 11.
    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        } else if (BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS) {
            // Every use, with strong biometrics only.
            spec.setUserAuthenticationValidityDurationSeconds(-1)
        } else {
            // No strong biometrics: the screen lock, used at once.
            spec.setUserAuthenticationValidityDurationSeconds(TIME_BOUND_SECONDS)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) spec.setIsStrongBoxBacked(true)
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE).apply {
            init(spec.build())
            generateKey()
        }
    }

    private fun info(key: SecretKey): KeyInfo =
        SecretKeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo

    /** Where the key lives, for the log. */
    @Suppress("DEPRECATION")
    private fun where(): String {
        val key = key() ?: return "missing"
        val info = info(key)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software only"
                else -> "level ${info.securityLevel}"
            }
        }
        return if (info.isInsideSecureHardware) "secure hardware" else "software only"
    }

    override fun sign(challenge: ByteArray): ByteArray {
        ensureSecureLockScreen()
        val key = key() ?: throw HardwareException.Unavailable("this device has no ZeroPass key in its Keystore")
        val mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256)
        @Suppress("DEPRECATION")
        val timeBound = info(key).userAuthenticationValidityDurationSeconds > 0
        if (timeBound) {
            // Android 9–10 without strong biometrics: the screen lock first,
            // then the key works for a few seconds.
            prompt(null, DEVICE_CREDENTIAL)
            initialise(mac, key)
            return mac.doFinal(challenge)
        }
        initialise(mac, key)
        val authenticators = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        } else {
            BIOMETRIC_STRONG
        }
        val confirmed = prompt(BiometricPrompt.CryptoObject(mac), authenticators)
        val authorised = confirmed?.mac ?: throw HardwareException.Failed("the prompt returned no key")
        return authorised.doFinal(challenge)
    }

    private fun initialise(mac: Mac, key: SecretKey) {
        try {
            mac.init(key)
        } catch (error: KeyPermanentlyInvalidatedException) {
            throw HardwareException.Unavailable("the key was invalidated (was the screen lock removed?)")
        } catch (error: Exception) {
            throw HardwareException.Failed("the key cannot be used: ${error.message}")
        }
    }

    /**
     * Shows the prompt on the foreground screen and waits for the user.
     * Returns the authorised crypto object, if one was given.
     */
    private fun prompt(crypto: BiometricPrompt.CryptoObject?, authenticators: Int): BiometricPrompt.CryptoObject? {
        val activity = Prompts.foreground ?: throw HardwareException.Failed("open ZeroPass to confirm")
        val done = CountDownLatch(1)
        var result: BiometricPrompt.AuthenticationResult? = null
        var failure: HardwareException? = null
        activity.runOnUiThread {
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(outcome: BiometricPrompt.AuthenticationResult) {
                    result = outcome
                    done.countDown()
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    failure = when (code) {
                        BiometricPrompt.ERROR_HW_NOT_PRESENT, BiometricPrompt.ERROR_HW_UNAVAILABLE,
                        BiometricPrompt.ERROR_NO_BIOMETRICS, BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                        -> HardwareException.Unavailable(message.toString())
                        else -> HardwareException.Cancelled()
                    }
                    done.countDown()
                }
            }
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(activity.getString(R.string.prompt_title))
                .setSubtitle(Prompts.reason ?: activity.getString(R.string.prompt_reason))
                .setAllowedAuthenticators(authenticators)
                .apply {
                    if (authenticators and DEVICE_CREDENTIAL == 0) setNegativeButtonText(activity.getString(android.R.string.cancel))
                }
                .build()
            val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            if (crypto != null) prompt.authenticate(info, crypto) else prompt.authenticate(info)
        }
        if (!done.await(PROMPT_SECONDS, TimeUnit.SECONDS)) throw HardwareException.Cancelled()
        failure?.let { throw it }
        return result?.cryptoObject
    }

    companion object {
        private const val TAG = "ZeroPass"
        private const val KEYSTORE = "AndroidKeyStore"
        /** The key, one for all vaults of this Android user (crypto.md §7.2). */
        const val ALIAS = "zeropass-hardware-v1"
        /** The first byte of the key slots it protects (crypto.md §7). */
        val IMPLEMENTATION_ID: UByte = 0x04u
        private const val TIME_BOUND_SECONDS = 5
        private const val PROMPT_SECONDS = 180L
    }
}

package io.github.makomooss.zeropass.fill

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import org.json.JSONObject

/**
 * The browsers whose word ZeroPass takes for the web page they show
 * (docs/spec/android.md §6.1): Google's published list of privileged
 * browsers, with their signing certificates, bundled with the app.
 */
object Browsers {
    private const val ASSET = "privileged_browsers.json"

    @Volatile private var json: String? = null
    @Volatile private var certificates: Map<String, Set<String>>? = null

    /** The list, as `CallingAppInfo.getOrigin` takes it. */
    fun allowlist(context: Context): String =
        json ?: context.assets.open(ASSET).bufferedReader().use { it.readText() }.also { json = it }

    private fun certificates(context: Context): Map<String, Set<String>> {
        certificates?.let { return it }
        val apps = JSONObject(allowlist(context)).getJSONArray("apps")
        val map = mutableMapOf<String, MutableSet<String>>()
        for (index in 0 until apps.length()) {
            val app = apps.getJSONObject(index)
            if (app.optString("type") != "android") continue
            val info = app.getJSONObject("info")
            val signatures = info.getJSONArray("signatures")
            val set = map.getOrPut(info.getString("package_name")) { mutableSetOf() }
            for (s in 0 until signatures.length()) {
                set += signatures.getJSONObject(s).getString("cert_fingerprint_sha256").uppercase()
            }
        }
        return map.also { certificates = it }
    }

    /** Whether [packageName] is a listed browser, signed as listed. */
    fun isTrusted(context: Context, packageName: String): Boolean {
        val wanted = certificates(context)[packageName] ?: return false
        return signingFingerprints(context, packageName).any { it in wanted }
    }

    @SuppressLint("PackageManagerGetSignatures")
    @Suppress("DEPRECATION")
    private fun signingFingerprints(context: Context, packageName: String): List<String> {
        val manager = context.packageManager
        val signatures = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = manager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signing = info.signingInfo ?: return emptyList()
                if (signing.hasMultipleSigners()) signing.apkContentsSigners else signing.signingCertificateHistory
            } else {
                manager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
            }
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } ?: return emptyList()
        val sha256 = MessageDigest.getInstance("SHA-256")
        return signatures.map { signature ->
            sha256.digest(signature.toByteArray()).joinToString(":") { "%02X".format(it) }
        }
    }
}

/** The page a request is for (docs/spec/android.md §6.1). */
object Pages {
    /** The address of an app's own logins. */
    fun app(packageName: String) = "androidapp://$packageName"

    /** A web page's origin from what a browser reported, or `null`. */
    fun web(domain: String?, scheme: String?): String? {
        val host = domain?.trim()?.trimEnd('.')?.lowercase() ?: return null
        if (host.isEmpty() || host.any { it.isWhitespace() || it == '/' }) return null
        val protocol = scheme?.lowercase()?.takeIf { it == "http" || it == "https" } ?: "https"
        return "$protocol://$host"
    }
}

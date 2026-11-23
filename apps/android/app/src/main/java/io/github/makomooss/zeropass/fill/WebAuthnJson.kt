package io.github.makomooss.zeropass.fill

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import uniffi.zp_ffi.PasskeyCreation
import uniffi.zp_ffi.PasskeyMade
import uniffi.zp_ffi.PasskeyRequest
import uniffi.zp_ffi.PasskeySignature

/**
 * The JSON forms of WebAuthn that Credential Manager passes
 * (`PublicKeyCredentialCreationOptionsJSON`, `…RequestOptionsJSON`) and wants
 * back (`RegistrationResponseJSON`, `AuthenticationResponseJSON`).
 */
object WebAuthnJson {
    private const val FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

    fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, FLAGS)

    fun decode(text: String): ByteArray = Base64.decode(text, FLAGS)

    private fun ids(array: JSONArray?): List<ByteArray> =
        (0 until (array?.length() ?: 0)).map { decode(array!!.getJSONObject(it).getString("id")) }

    /** A request to make a passkey, from `navigator.credentials.create`'s options. */
    fun creation(requestJson: String, origin: String, clientDataHash: ByteArray?): PasskeyCreation {
        val options = JSONObject(requestJson)
        val rp = options.getJSONObject("rp")
        val user = options.getJSONObject("user")
        val params = options.optJSONArray("pubKeyCredParams")
        val algorithms = (0 until (params?.length() ?: 0))
            .map { params!!.getJSONObject(it) }
            .filter { it.optString("type", "public-key") == "public-key" }
            .map { it.getInt("alg") }
        return PasskeyCreation(
            origin = origin,
            rpId = rp.optString("id", ""),
            rpName = rp.optString("name", ""),
            userHandle = decode(user.getString("id")),
            userName = user.optString("name", ""),
            userDisplayName = user.optString("displayName", ""),
            challenge = decode(options.getString("challenge")),
            algorithms = algorithms,
            exclude = ids(options.optJSONArray("excludeCredentials")),
            clientDataHash = clientDataHash,
        )
    }

    /** A request to sign in, from `navigator.credentials.get`'s options. */
    fun request(requestJson: String, origin: String, clientDataHash: ByteArray?): PasskeyRequest {
        val options = JSONObject(requestJson)
        return PasskeyRequest(
            origin = origin,
            rpId = options.optString("rpId", ""),
            challenge = decode(options.getString("challenge")),
            allow = ids(options.optJSONArray("allowCredentials")),
            clientDataHash = clientDataHash,
        )
    }

    /** The client data, or a stand-in when the browser made it and replaces it. */
    private fun clientData(json: ByteArray): String = encode(if (json.isEmpty()) "{}".toByteArray() else json)

    fun registration(made: PasskeyMade): String {
        val id = encode(made.credentialId)
        return JSONObject()
            .put("id", id)
            .put("rawId", id)
            .put("type", "public-key")
            .put("authenticatorAttachment", "platform")
            .put(
                "response",
                JSONObject()
                    .put("clientDataJSON", clientData(made.clientDataJson))
                    .put("attestationObject", encode(made.attestationObject))
                    .put("authenticatorData", encode(made.authenticatorData))
                    .put("publicKey", encode(made.publicKey))
                    .put("publicKeyAlgorithm", made.algorithm)
                    .put("transports", JSONArray().put("internal").put("hybrid")),
            )
            .put("clientExtensionResults", JSONObject().put("credProps", JSONObject().put("rk", true)))
            .toString()
    }

    fun assertion(signed: PasskeySignature): String {
        val id = encode(signed.credentialId)
        return JSONObject()
            .put("id", id)
            .put("rawId", id)
            .put("type", "public-key")
            .put("authenticatorAttachment", "platform")
            .put(
                "response",
                JSONObject()
                    .put("clientDataJSON", clientData(signed.clientDataJson))
                    .put("authenticatorData", encode(signed.authenticatorData))
                    .put("signature", encode(signed.signature))
                    .put("userHandle", encode(signed.userHandle)),
            )
            .put("clientExtensionResults", JSONObject())
            .toString()
    }
}

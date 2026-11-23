package io.github.makomooss.zeropass.fill

import android.app.assist.AssistStructure
import android.os.Build
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** What a screen asks for, as the autofill service sees it (docs/spec/android.md §6.2). */
data class Form(
    /** The app that shows the screen. */
    val packageName: String,
    /** The web page's domain and scheme, if a browser reported them. */
    val webDomain: String?,
    val webScheme: String?,
    val username: AutofillId?,
    val password: AutofillId?,
    /** Whether the password field is for a new password only (a sign-up form). */
    val newPassword: Boolean,
    /** What was typed, for saving. */
    val usernameValue: String?,
    val passwordValue: String?,
) {
    val ids: List<AutofillId> get() = listOfNotNull(username, password)
}

private val USERNAME_WORDS = listOf("user", "login", "email", "e-mail", "mail", "account", "identifier", "phone")


/** Reads the fields of the screen in [structure]. */
fun readForm(structure: AssistStructure): Form {
    val nodes = mutableListOf<AssistStructure.ViewNode>()
    for (index in 0 until structure.windowNodeCount) {
        collect(structure.getWindowNodeAt(index).rootViewNode, nodes)
    }
    var webDomain: String? = null
    var webScheme: String? = null
    for (node in nodes) {
        if (webDomain == null && !node.webDomain.isNullOrBlank()) {
            webDomain = node.webDomain
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) webScheme = node.webScheme
        }
    }
    val texts = nodes.filter { it.autofillId != null && isEditable(it) }
    val passwordIndex = texts.indexOfFirst { isPassword(it) }
    val password = texts.getOrNull(passwordIndex)
    val username = texts.firstOrNull { isUsername(it) && !isPassword(it) }
        ?: if (passwordIndex > 0) texts.subList(0, passwordIndex).lastOrNull { !isPassword(it) } else null
    return Form(
        packageName = structure.activityComponent.packageName,
        webDomain = webDomain,
        webScheme = webScheme,
        username = username?.autofillId,
        password = password?.autofillId,
        newPassword = password != null && isNewPassword(password),
        usernameValue = username?.autofillValue?.takeIf { it.isText }?.textValue?.toString(),
        passwordValue = password?.autofillValue?.takeIf { it.isText }?.textValue?.toString(),
    )
}

private fun collect(node: AssistStructure.ViewNode, out: MutableList<AssistStructure.ViewNode>) {
    out += node
    for (index in 0 until node.childCount) collect(node.getChildAt(index), out)
}

private fun hints(node: AssistStructure.ViewNode): List<String> =
    node.autofillHints?.map { it.lowercase() }.orEmpty()

private fun html(node: AssistStructure.ViewNode, name: String): String? =
    node.htmlInfo?.attributes?.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second?.lowercase()

private fun isEditable(node: AssistStructure.ViewNode): Boolean =
    node.autofillType == View.AUTOFILL_TYPE_TEXT ||
        node.className?.contains("EditText") == true ||
        node.htmlInfo?.tag.equals("input", ignoreCase = true)

private fun isPassword(node: AssistStructure.ViewNode): Boolean {
    if (hints(node).any { it.contains("password") }) return true
    if (html(node, "type") == "password") return true
    val type = node.inputType
    val textClass = type and InputType.TYPE_MASK_CLASS
    val variation = type and InputType.TYPE_MASK_VARIATION
    return (textClass == InputType.TYPE_CLASS_TEXT &&
        variation in setOf(
            InputType.TYPE_TEXT_VARIATION_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
        )) ||
        (textClass == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD)
}

private fun isNewPassword(node: AssistStructure.ViewNode): Boolean =
    hints(node).any { it.contains("new") } || html(node, "autocomplete") == "new-password"

private fun isUsername(node: AssistStructure.ViewNode): Boolean {
    val hints = hints(node)
    if (hints.any { it == "username" || it == "emailaddress" || it == "email" || it == "phone" }) return true
    val autocomplete = html(node, "autocomplete")
    if (autocomplete == "username" || autocomplete == "email") return true
    if (html(node, "type") == "email") return true
    val variation = node.inputType and InputType.TYPE_MASK_VARIATION
    if (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS) return true
    val words = listOfNotNull(node.idEntry, node.hint, html(node, "name"), html(node, "id")).joinToString(" ").lowercase()
    return USERNAME_WORDS.any { it in words }
}

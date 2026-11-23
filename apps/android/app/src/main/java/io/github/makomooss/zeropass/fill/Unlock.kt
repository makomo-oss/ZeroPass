package io.github.makomooss.zeropass.fill

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.github.makomooss.zeropass.BuildConfig
import io.github.makomooss.zeropass.ui.ZeroPassTheme

/**
 * What the autofill and Credential Manager screens show when they need the
 * master password: why, the field, and a way out. [error] is the last failure.
 */
@Composable
fun UnlockForOthers(why: String, busy: Boolean, error: String?, onUnlock: (String) -> Unit, onCancel: () -> Unit) {
    var password by rememberSaveable { mutableStateOf("") }
    ZeroPassTheme {
        Surface(Modifier.fillMaxSize().semantics { testTagsAsResourceId = BuildConfig.DEBUG }) {
            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("ZeroPass", style = MaterialTheme.typography.headlineSmall)
                Text(why)
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Master password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                    modifier = Modifier.fillMaxWidth().testTag("other-password"),
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(
                    onClick = { onUnlock(password) },
                    enabled = password.isNotEmpty() && !busy,
                    modifier = Modifier.testTag("other-unlock"),
                ) { Text("Unlock") }
                TextButton(onClick = onCancel) { Text("Cancel") }
            }
        }
    }
}

/** A short line about a failure for these screens. */
fun describe(error: Throwable): String = when (error) {
    is uniffi.zp_ffi.ZpException.Failure -> when (error.problem) {
        uniffi.zp_ffi.Problem.WRONG_PASSWORD -> "Wrong master password."
        uniffi.zp_ffi.Problem.CANCELLED -> "Not confirmed."
        else -> error.detail
    }
    else -> error.message ?: error.javaClass.simpleName
}.lineSequence().first()

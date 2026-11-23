package io.github.makomooss.zeropass.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import io.github.makomooss.zeropass.BuildConfig
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/** Starts the camera to read a QR code whose text starts with a prefix. */
typealias Scanner = (prefix: String, onCode: (String) -> Unit) -> Unit

@Composable
fun ZeroPassTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && dark -> dynamicDarkColorScheme(context)
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors, content = content)
}

/** The whole app: what the state of the vault calls for. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(model: VaultModel, scan: Scanner) {
    val state = model.state
    ZeroPassTheme {
        Scaffold(
            // Debug builds: the tags are resource IDs, for the tests driven over adb.
            modifier = Modifier.semantics { testTagsAsResourceId = BuildConfig.DEBUG },
            topBar = { TopAppBar(title = { Text("ZeroPass") }) },
            bottomBar = {
                if (state.unlocked) {
                    NavigationBar {
                        for ((tab, label) in TABS) {
                            NavigationBarItem(
                                selected = state.tab == tab,
                                onClick = { model.select(tab) },
                                icon = { Text(label.take(1)) },
                                label = { Text(label) },
                                modifier = Modifier.testTag("tab-$label"),
                            )
                        }
                    }
                }
            },
        ) { padding ->
            Column(Modifier.padding(padding).fillMaxSize()) {
                state.busy?.let { busy ->
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text(busy, Modifier.padding(horizontal = 16.dp, vertical = 4.dp), style = MaterialTheme.typography.bodySmall)
                }
                Box(Modifier.weight(1f)) {
                    val status = state.status
                    when {
                        status == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                        !status.exists -> StartScreen(model, scan)
                        !state.unlocked -> UnlockScreen(model)
                        else -> when (state.tab) {
                            Tab.VAULT -> VaultTab(model)
                            Tab.CODES -> CodesTab(model, scan)
                            Tab.PASSKEYS -> PasskeysTab(model, scan)
                            Tab.DEVICES -> DevicesTab(model)
                            Tab.SETTINGS -> SettingsTab(model)
                        }
                    }
                }
            }
        }
        state.message?.let { message ->
            AlertDialog(
                onDismissRequest = model::dismissMessage,
                confirmButton = { TextButton(onClick = model::dismissMessage) { Text("OK") } },
                text = { Text(message) },
            )
        }
        state.question?.let { question ->
            AlertDialog(
                onDismissRequest = model::dismissQuestion,
                confirmButton = { TextButton(onClick = question.onYes, modifier = Modifier.testTag("confirm")) { Text(question.yes) } },
                dismissButton = { TextButton(onClick = model::dismissQuestion) { Text("Cancel") } },
                text = { Text(question.text) },
            )
        }
    }
}

private val TABS = listOf(
    Tab.VAULT to "Vault",
    Tab.CODES to "Codes",
    Tab.PASSKEYS to "Passkeys",
    Tab.DEVICES to "Devices",
    Tab.SETTINGS to "Settings",
)

/** A text field for a secret: never suggested, never shown. */
@Composable
fun SecretField(value: String, onChange: (String) -> Unit, label: String, tag: String, modifier: Modifier = Modifier) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
        modifier = modifier.fillMaxWidth().testTag(tag),
    )
}

@Composable
fun PlainField(value: String, onChange: (String) -> Unit, label: String, tag: String, singleLine: Boolean = true, modifier: Modifier = Modifier) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = singleLine,
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
        modifier = modifier.fillMaxWidth().testTag(tag),
    )
}

/** A scrolling column with the usual margins. */
@Composable
fun Page(content: @Composable () -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) { content() }
}

@Composable
fun Lines(lines: List<String>) {
    if (lines.isEmpty()) return
    Column(Modifier.fillMaxWidth().padding(top = 8.dp)) {
        lines.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun StartScreen(model: VaultModel, scan: Scanner) {
    var joining by rememberSaveable { mutableStateOf(false) }
    var password by rememberSaveable { mutableStateOf("") }
    var repeated by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf(VaultModel.defaultName) }
    Page {
        Text(
            if (joining) "Join the vault of another device" else "Create a vault",
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            if (joining) {
                "On the other device, choose “Add a device” to show a code. This phone gets its own master password."
            } else {
                "The master password opens your logins on this phone. Nobody can reset it: keep it, and make a recovery kit."
            },
        )
        PlainField(name, { name = it }, "Name of this phone", "name")
        SecretField(password, { password = it }, "Master password (12 characters or more)", "password")
        SecretField(repeated, { repeated = it }, "Master password again", "password-again")
        if (joining) {
            Button(
                onClick = { scan("ZP1:") { code -> model.join(code, name, password, repeated) } },
                enabled = password.length >= 12 && name.isNotBlank(),
                modifier = Modifier.testTag("scan-and-join"),
            ) { Text("Scan the code and join") }
            Lines(model.state.log)
            TextButton(onClick = { joining = false }) { Text("Create a new vault instead") }
        } else {
            Button(
                onClick = { model.create(password, repeated, name) },
                enabled = password.length >= 12,
                modifier = Modifier.testTag("create"),
            ) { Text("Create the vault") }
            TextButton(onClick = { joining = true }, modifier = Modifier.testTag("join-instead")) {
                Text("Join a vault from another device instead")
            }
        }
    }
}

@Composable
private fun UnlockScreen(model: VaultModel) {
    var password by rememberSaveable { mutableStateOf("") }
    Page {
        Text("Locked", style = MaterialTheme.typography.headlineSmall)
        SecretField(password, { password = it }, "Master password", "unlock-password")
        Row(verticalAlignment = Alignment.CenterVertically) {
            Button(
                onClick = {
                    model.unlock(password)
                    password = ""
                },
                enabled = password.isNotEmpty(),
                modifier = Modifier.testTag("unlock"),
            ) { Text("Unlock") }
            Spacer(Modifier.width(12.dp))
        }
        Spacer(Modifier.height(8.dp))
    }
}

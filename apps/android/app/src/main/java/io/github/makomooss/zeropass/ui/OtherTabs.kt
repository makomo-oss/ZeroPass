package io.github.makomooss.zeropass.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.makomooss.zeropass.Clipboard
import uniffi.zp_ffi.DeviceState
import uniffi.zp_ffi.Domain

/**
 * What to show when this phone lacks a hardware-bound domain (ADR-0011):
 * why, and how to get it. Returns whether the domain is there.
 */
@Composable
private fun DomainPresent(model: VaultModel, domain: Domain, what: String, scan: Scanner): Boolean {
    val state = model.state.domain(domain)
    if (state?.available == true) return true
    if (state?.elsewhere == true) {
        Text("Another device of this vault has the $what. This phone gets their keys from it: on that device choose “Add a device” and scan its code here.")
        Button(onClick = { scan("ZP1:") { code -> model.receiveKeys(code) } }, modifier = Modifier.testTag("get-keys")) {
            Text("Get the keys")
        }
        Lines(model.state.log)
    } else {
        Text("This vault has no $what yet. This phone can make them, protected by its screen lock or biometrics.")
        Button(onClick = { model.setUp(domain) }, modifier = Modifier.testTag("set-up")) { Text("Set up $what on this phone") }
    }
    return false
}

/** One-time codes (docs/spec/android.md §4). */
@Composable
fun CodesTab(model: VaultModel, scan: Scanner) {
    val context = LocalContext.current
    val codes = model.state.codes
    var adding by rememberSaveable { mutableStateOf(false) }
    var secret by rememberSaveable { mutableStateOf("") }
    var issuer by rememberSaveable { mutableStateOf("") }
    var account by rememberSaveable { mutableStateOf("") }
    Page {
        Text("One-time codes", style = MaterialTheme.typography.headlineSmall)
        if (!DomainPresent(model, Domain.TOTP, "one-time codes", scan)) return@Page
        if (codes == null) {
            Text("The codes open with your screen lock or biometrics, every time.")
            Button(onClick = model::showCodes, modifier = Modifier.testTag("show-codes")) { Text("Show one-time codes") }
        } else {
            if (codes.isEmpty()) Text("No one-time codes yet.")
            codes.forEach { code ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(listOf(code.title, code.account).filter { it.isNotEmpty() }.joinToString(" · "))
                        Text(
                            code.code.chunked(3).joinToString(" "),
                            style = MaterialTheme.typography.headlineMedium,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.testTag("code-${code.title}"),
                        )
                        Text("${code.secondsLeft} s", style = MaterialTheme.typography.bodySmall)
                    }
                    TextButton(onClick = { Clipboard.copy(context, code.code) }) { Text("Copy") }
                    TextButton(onClick = { model.deleteCode(code.id) }) { Text("Delete") }
                }
                HorizontalDivider()
            }
            OutlinedButton(onClick = model::hideCodes, modifier = Modifier.testTag("hide-codes")) { Text("Hide codes") }
        }
        TextButton(onClick = { adding = !adding }, modifier = Modifier.testTag("add-code")) {
            Text(if (adding) "Cancel" else "Add a one-time code")
        }
        if (adding) {
            OutlinedButton(onClick = {
                scan("otpauth://") { uri ->
                    adding = false
                    model.addCode(uri, "", "")
                }
            }) { Text("Scan the site's QR code") }
            Text("Or type the secret the site shows:")
            SecretField(secret, { secret = it }, "Secret (Base32) or otpauth:// address", "code-secret")
            PlainField(issuer, { issuer = it }, "Site", "code-issuer")
            PlainField(account, { account = it }, "Account", "code-account")
            Button(
                onClick = {
                    model.addCode(secret, issuer, account)
                    adding = false
                    secret = ""
                },
                enabled = secret.isNotBlank(),
                modifier = Modifier.testTag("save-code"),
            ) { Text("Add") }
        }
    }
}

/** Passkeys (docs/spec/android.md §4): never their private keys. */
@Composable
fun PasskeysTab(model: VaultModel, scan: Scanner) {
    val passkeys = model.state.passkeys
    Page {
        Text("Passkeys", style = MaterialTheme.typography.headlineSmall)
        if (!DomainPresent(model, Domain.PASSKEY, "passkeys", scan)) return@Page
        if (passkeys == null) {
            Button(onClick = model::showPasskeys, modifier = Modifier.testTag("show-passkeys")) { Text("Show passkeys") }
        } else {
            if (passkeys.isEmpty()) Text("No passkeys yet. Sites offer to make one when you sign in.")
            passkeys.forEach { passkey ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(passkey.title, style = MaterialTheme.typography.titleMedium)
                        Text(passkey.username)
                    }
                    TextButton(onClick = { model.deletePasskey(passkey.id) }) { Text("Delete") }
                }
                HorizontalDivider()
            }
            OutlinedButton(onClick = model::hidePasskeys) { Text("Hide passkeys") }
        }
    }
}

/** The devices of the vault and sync (docs/spec/android.md §4, §5). */
@Composable
fun DevicesTab(model: VaultModel) {
    val state = model.state
    Page {
        Text("Devices", style = MaterialTheme.typography.headlineSmall)
        Button(onClick = model::syncNow, modifier = Modifier.testTag("sync-now")) { Text("Sync now") }
        Text("Syncs over Wi-Fi with the devices on the same network, and over Bluetooth with the others nearby.", style = MaterialTheme.typography.bodySmall)
        Text(state.lastSync, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("last-sync"))
        Lines(state.log)
        state.devices.forEach { device ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(device.name, style = MaterialTheme.typography.titleMedium)
                    Text(
                        when (device.state) {
                            DeviceState.THIS_DEVICE -> "This phone"
                            DeviceState.ACTIVE -> "Syncs · ${device.changesHeld} change(s) from it here"
                            DeviceState.REVOKED -> "Revoked"
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (device.state == DeviceState.ACTIVE) {
                    TextButton(onClick = {
                        model.ask(
                            "Revoke “${device.name}”? It can no longer sync, and the vault keys are replaced on the devices that remain.",
                            "Revoke",
                        ) { model.revoke(device) }
                    }) { Text("Revoke") }
                }
            }
            HorizontalDivider()
        }
    }
}

/** The recovery kit, the master password, locking and leaving (docs/spec/android.md §4). */
@Composable
fun SettingsTab(model: VaultModel) {
    val context = LocalContext.current
    val state = model.state
    var current by rememberSaveable { mutableStateOf("") }
    var new by rememberSaveable { mutableStateOf("") }
    var repeated by rememberSaveable { mutableStateOf("") }
    Page {
        Text("Settings", style = MaterialTheme.typography.headlineSmall)
        Button(onClick = model::lock, modifier = Modifier.testTag("lock")) { Text("Lock now") }

        Text("Recovery kit", style = MaterialTheme.typography.titleMedium)
        Text(
            if (state.status?.hasRecoveryKit == true) {
                "This vault has a recovery kit. Making a new one makes the old recovery key useless."
            } else {
                "No recovery kit yet. Without one, a forgotten master password cannot be undone."
            },
        )
        val key = state.recoveryKey
        if (key == null) {
            OutlinedButton(onClick = { model.createRecoveryKit() }, modifier = Modifier.testTag("recovery-kit")) { Text("Make a recovery kit") }
        } else {
            Text("Write this recovery key down and keep it apart from your devices. It is shown only now.")
            Text(key, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium, modifier = Modifier.testTag("recovery-key"))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { Clipboard.copy(context, key) }) { Text("Copy") }
                Button(onClick = model::forgetRecoveryKey) { Text("I wrote it down") }
            }
        }

        Text("Master password", style = MaterialTheme.typography.titleMedium)
        SecretField(current, { current = it }, "Current master password", "current-password")
        SecretField(new, { new = it }, "New master password", "new-password")
        SecretField(repeated, { repeated = it }, "New master password again", "new-password-again")
        OutlinedButton(
            onClick = {
                model.changeMasterPassword(current, new, repeated)
                current = ""
                new = ""
                repeated = ""
            },
            enabled = current.isNotEmpty() && new.length >= 12,
        ) { Text("Change the master password") }

        Text("Sync", style = MaterialTheme.typography.titleMedium)
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("Sync in the background every 15 minutes or so, when the battery is not low", Modifier.weight(1f))
            Switch(checked = state.backgroundSync, onCheckedChange = model::setBackgroundSync, modifier = Modifier.testTag("background-sync"))
        }

        Text("This phone", style = MaterialTheme.typography.titleMedium)
        Text("The vault runs in an isolated process without network access; this app stores the encrypted vault file for it.", style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = model::deleteVault, modifier = Modifier.testTag("delete-vault")) { Text("Delete the vault on this phone") }
    }
}


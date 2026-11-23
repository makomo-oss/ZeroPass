package io.github.makomooss.zeropass.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.makomooss.zeropass.Clipboard
import io.github.makomooss.zeropass.PasswordGenerator
import uniffi.zp_ffi.ItemContent
import uniffi.zp_ffi.ItemKind

/** Logins and notes (docs/spec/android.md §4). */
@Composable
fun VaultTab(model: VaultModel) {
    val state = model.state
    val draft = state.draft
    val open = state.open
    when {
        draft != null -> DraftScreen(model, draft)
        open != null -> ItemScreen(model, open)
        else -> ItemList(model)
    }
}

@Composable
private fun ItemList(model: VaultModel) {
    val state = model.state
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            PlainField(state.query, model::search, "Search", "search")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { model.newDraft(ItemKind.LOGIN) }, modifier = Modifier.testTag("add-login")) { Text("Add a login") }
                OutlinedButton(onClick = { model.newDraft(ItemKind.NOTE) }, modifier = Modifier.testTag("add-note")) { Text("Add a note") }
            }
            val unreadable = state.items?.unreadable ?: 0u
            if (unreadable > 0u) {
                Text("$unreadable item(s) were written with keys this phone has not received yet.", style = MaterialTheme.typography.bodySmall)
            }
        }
        val items = state.items?.items.orEmpty()
        if (items.isEmpty()) {
            Text(
                if (state.query.isEmpty()) "Nothing here yet." else "Nothing matches.",
                Modifier.padding(16.dp),
            )
        }
        LazyColumn(Modifier.fillMaxSize()) {
            items(items, key = { it.id }) { item ->
                Column(
                    Modifier
                        .fillMaxWidth()
                        .clickable { model.openItem(item.id) }
                        .padding(horizontal = 16.dp, vertical = 12.dp)
                        .testTag("item-${item.title}"),
                ) {
                    Text(item.title, style = MaterialTheme.typography.titleMedium)
                    val detail = if (item.kind == ItemKind.NOTE) "Note" else item.username
                    if (detail.isNotEmpty()) Text(detail, style = MaterialTheme.typography.bodyMedium)
                }
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun Field(label: String, value: String, tag: String, copyable: Boolean = true, monospace: Boolean = false) {
    if (value.isEmpty()) return
    val context = LocalContext.current
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium)
            Text(
                value,
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = if (monospace) FontFamily.Monospace else null,
                modifier = Modifier.testTag(tag),
            )
        }
        if (copyable) TextButton(onClick = { Clipboard.copy(context, value) }) { Text("Copy") }
    }
}

@Composable
private fun ItemScreen(model: VaultModel, open: OpenItem) {
    val context = LocalContext.current
    Page {
        TextButton(onClick = model::closeItem) { Text("‹ Back") }
        when (val content = open.content) {
            is ItemContent.Login -> {
                Text(content.title, style = MaterialTheme.typography.headlineSmall)
                Field("User name", content.username, "username")
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Password", style = MaterialTheme.typography.labelMedium)
                        Text(
                            if (open.showPassword) content.password else "••••••••••",
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.testTag("password"),
                        )
                    }
                    TextButton(onClick = { model.showPassword(!open.showPassword) }, modifier = Modifier.testTag("show-password")) {
                        Text(if (open.showPassword) "Hide" else "Show")
                    }
                    TextButton(onClick = { Clipboard.copy(context, content.password) }) { Text("Copy") }
                }
                content.urls.forEach { Field("Address", it, "url", copyable = false) }
                Field("Notes", content.notes, "notes", copyable = false)
            }
            is ItemContent.Note -> {
                Text(content.title, style = MaterialTheme.typography.headlineSmall)
                Text(content.body, modifier = Modifier.testTag("note-body"))
            }
            else -> Text("This item is shown in its own tab.")
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = model::editOpenItem, modifier = Modifier.testTag("edit")) { Text("Edit") }
            OutlinedButton(onClick = model::deleteOpenItem, modifier = Modifier.testTag("delete")) { Text("Delete") }
        }
    }
}

@Composable
private fun DraftScreen(model: VaultModel, draft: Draft) {
    var generating by remember { mutableStateOf(false) }
    var options by remember { mutableStateOf(PasswordGenerator.Options()) }
    Page {
        TextButton(onClick = model::cancelDraft) { Text("‹ Cancel") }
        Text(
            when {
                draft.kind == ItemKind.NOTE && draft.id == null -> "New note"
                draft.kind == ItemKind.NOTE -> "Edit note"
                draft.id == null -> "New login"
                else -> "Edit login"
            },
            style = MaterialTheme.typography.headlineSmall,
        )
        PlainField(draft.title, { model.changeDraft(draft.copy(title = it)) }, "Title", "draft-title")
        if (draft.kind == ItemKind.NOTE) {
            PlainField(draft.notes, { model.changeDraft(draft.copy(notes = it)) }, "Text", "draft-body", singleLine = false)
        } else {
            PlainField(draft.username, { model.changeDraft(draft.copy(username = it)) }, "User name", "draft-username")
            SecretField(draft.password, { model.changeDraft(draft.copy(password = it)) }, "Password", "draft-password")
            TextButton(onClick = { generating = !generating }, modifier = Modifier.testTag("generator")) {
                Text(if (generating) "Hide the generator" else "Generate a password")
            }
            if (generating) {
                Text("Length ${options.length} · about ${PasswordGenerator.bits(options)} bits")
                Slider(
                    value = options.length.toFloat(),
                    onValueChange = { options = options.copy(length = it.toInt()) },
                    valueRange = PasswordGenerator.MIN_LENGTH.toFloat()..64f,
                )
                Check("Capital letters", options.upper) { options = options.copy(upper = it) }
                Check("Digits", options.digits) { options = options.copy(digits = it) }
                Check("Symbols", options.symbols) { options = options.copy(symbols = it) }
                Check("No look-alike characters", options.avoidLookAlike) { options = options.copy(avoidLookAlike = it) }
                OutlinedButton(
                    onClick = { model.changeDraft(draft.copy(password = PasswordGenerator.generate(options))) },
                    modifier = Modifier.testTag("use-generated"),
                ) { Text("Use a new password") }
            }
            PlainField(draft.urls, { model.changeDraft(draft.copy(urls = it)) }, "Addresses (one per line)", "draft-urls", singleLine = false)
            PlainField(draft.notes, { model.changeDraft(draft.copy(notes = it)) }, "Notes", "draft-notes", singleLine = false)
        }
        Button(onClick = model::saveDraft, modifier = Modifier.testTag("save")) { Text("Save") }
    }
}

@Composable
private fun Check(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Spacer(Modifier.width(4.dp))
        Text(label)
    }
}

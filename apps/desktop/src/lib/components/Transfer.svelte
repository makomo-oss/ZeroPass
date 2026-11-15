<script lang="ts">
  import {
    errorMessage,
    isCommandError,
    MIN_MASTER_PASSWORD_CHARS,
    transfer,
    type ImportPreview,
    type ImportResult,
  } from "../api";

  let { onchanged }: { onchanged: () => void } = $props();

  // Import.
  let preview: ImportPreview | null = $state(null);
  let importPassphrase = $state("");
  let importBusy = $state(false);
  let importError = $state("");
  let imported: ImportResult | null = $state(null);

  async function choose() {
    importError = "";
    imported = null;
    try {
      const chosen = await transfer.choose();
      preview = chosen.kind === "cancelled" ? null : chosen;
    } catch (caught) {
      preview = null;
      importError = errorMessage(caught);
    }
  }

  async function confirmImport(event: SubmitEvent) {
    event.preventDefault();
    importBusy = true;
    importError = "";
    try {
      imported = await transfer.confirm(preview?.kind === "zeropass" ? importPassphrase : undefined);
      preview = null;
      importPassphrase = "";
      onchanged();
    } catch (caught) {
      importError =
        isCommandError(caught) && caught.code === "WrongPassword"
          ? "That passphrase does not open the file."
          : errorMessage(caught);
    } finally {
      importBusy = false;
    }
  }

  async function cancelImport() {
    await transfer.cancel();
    preview = null;
    importPassphrase = "";
  }

  // Export.
  let passphrase = $state("");
  let again = $state("");
  let exportBusy = $state(false);
  let exportError = $state("");
  let exported = $state("");
  let exportReady = $derived(
    [...passphrase].length >= MIN_MASTER_PASSWORD_CHARS && passphrase === again && !exportBusy,
  );

  async function exportVault(event: SubmitEvent) {
    event.preventDefault();
    if (!exportReady) return;
    exportBusy = true;
    exportError = "";
    exported = "";
    try {
      const result = await transfer.export(passphrase);
      if (result.path) {
        exported = `Exported ${result.logins} login(s), ${result.notes} note(s), ${result.totp} one-time code(s) and ${result.passkeys} passkey(s) to ${result.path}.`;
        passphrase = "";
        again = "";
      }
    } catch (caught) {
      exportError =
        isCommandError(caught) && caught.code === "UserCancelled"
          ? "Windows Hello was cancelled. Every part of the vault must be open to export it."
          : errorMessage(caught);
    } finally {
      exportBusy = false;
    }
  }
</script>

<section class="card block">
  <h3>Import</h3>
  <p class="muted small">
    From an export of Chrome, Edge, Firefox, Bitwarden (JSON or CSV), 1Password
    (CSV) or ZeroPass. The file is read by ZeroPass on this device only.
  </p>
  {#if preview === null}
    <div><button class="button" onclick={() => void choose()}>Choose a file…</button></div>
  {:else}
    <form class="form" onsubmit={confirmImport}>
      {#if preview.kind === "zeropass"}
        <p><strong>{preview.file}</strong>: an encrypted ZeroPass export.</p>
        <label class="field">
          <span>Its passphrase</span>
          <input class="input" type="password" autocomplete="off" bind:value={importPassphrase} />
        </label>
        <p class="muted small">Windows Hello may ask: the export can hold one-time codes and passkeys.</p>
      {:else if preview.kind === "other"}
        <p>
          <strong>{preview.file}</strong> ({preview.format}): {preview.logins} login(s)
          {#if preview.totp > 0}with {preview.totp} one-time code(s){/if}, {preview.notes} note(s){#if preview.skipped > 0},
            {preview.skipped} entry(ies) ZeroPass does not keep{/if}.
        </p>
        <p class="notice warn small">
          The file holds your passwords in the clear. Delete it once the import is done.
        </p>
      {/if}
      <div class="actions">
        <button class="button primary" type="submit" disabled={importBusy || (preview.kind === "zeropass" && importPassphrase === "")}>
          {importBusy ? "Importing…" : "Import"}
        </button>
        <button class="button ghost" type="button" onclick={() => void cancelImport()} disabled={importBusy}>Cancel</button>
      </div>
    </form>
  {/if}
  {#if imported}
    <p class="notice ok" role="status">
      Added {imported.logins} login(s), {imported.notes} note(s), {imported.totp} one-time code(s){#if imported.passkeys > 0}
        and {imported.passkeys} passkey(s){/if}.
    </p>
    {#each imported.failures as failure, index (index)}
      <p class="muted small">Not added: {failure}</p>
    {/each}
  {/if}
  {#if importError}
    <p class="notice error" role="alert">{importError}</p>
  {/if}
</section>

<section class="card block">
  <h3>Encrypted export</h3>
  <p class="muted small">
    Every item of the vault, one-time codes and passkeys included, in one file
    protected by a passphrase you choose now. Keep the passphrase apart from the
    file: whoever has both can read everything.
  </p>
  <form class="form" onsubmit={exportVault}>
    <label class="field">
      <span>Passphrase for the file (at least {MIN_MASTER_PASSWORD_CHARS} characters)</span>
      <input class="input" type="password" autocomplete="new-password" bind:value={passphrase} />
    </label>
    <label class="field">
      <span>Repeat the passphrase</span>
      <input class="input" type="password" autocomplete="new-password" bind:value={again} />
    </label>
    {#if again.length > 0 && passphrase !== again}
      <p class="notice warn">The two passphrases differ.</p>
    {/if}
    <div>
      <button class="button" type="submit" disabled={!exportReady}>{exportBusy ? "Exporting…" : "Export…"}</button>
    </div>
  </form>
  {#if exported}
    <p class="notice ok" role="status">{exported}</p>
  {/if}
  {#if exportError}
    <p class="notice error" role="alert">{exportError}</p>
  {/if}
</section>

<style>
  .block {
    padding: 18px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    box-shadow: none;
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .actions {
    display: flex;
    gap: 8px;
  }

  .small {
    font-size: 12px;
  }
</style>

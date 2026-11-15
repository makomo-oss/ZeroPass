<script lang="ts">
  import {
    errorMessage,
    isCommandError,
    items,
    MIN_MASTER_PASSWORD_CHARS,
    type AppInfo,
    type Status,
  } from "../api";
  import Transfer from "./Transfer.svelte";

  let {
    status,
    info,
    onchanged,
  }: { status: Status; info: AppInfo | null; onchanged: () => void } = $props();

  // Recovery kit.
  let recoveryKey = $state("");
  let kitBusy = $state(false);
  let kitError = $state("");

  async function createKit() {
    kitBusy = true;
    kitError = "";
    try {
      recoveryKey = await items.createRecoveryKit(status.has_recovery_kit);
    } catch (caught) {
      kitError =
        isCommandError(caught) && caught.code === "UserCancelled"
          ? "Windows Hello was cancelled. Every part of the vault must be open to make a recovery kit."
          : errorMessage(caught);
    } finally {
      kitBusy = false;
    }
  }

  function writtenDown() {
    recoveryKey = "";
    onchanged();
  }

  // Master password.
  let current = $state("");
  let next = $state("");
  let again = $state("");
  let passwordBusy = $state(false);
  let passwordError = $state("");
  let passwordDone = $state(false);
  let passwordReady = $derived(
    current.length > 0 &&
      [...next].length >= MIN_MASTER_PASSWORD_CHARS &&
      next === again &&
      !passwordBusy,
  );

  async function changePassword(event: SubmitEvent) {
    event.preventDefault();
    if (!passwordReady) return;
    passwordBusy = true;
    passwordError = "";
    passwordDone = false;
    try {
      await items.changeMasterPassword(current, next);
      current = "";
      next = "";
      again = "";
      passwordDone = true;
      // The password domain locked: the new password opens it.
      onchanged();
    } catch (caught) {
      passwordError =
        isCommandError(caught) && caught.code === "WrongPassword"
          ? "The current master password is not right."
          : errorMessage(caught);
    } finally {
      passwordBusy = false;
    }
  }
</script>

<div class="settings">
  <h2>Settings</h2>

  <section class="card block">
    <h3>Recovery kit</h3>
    {#if recoveryKey}
      <p class="notice warn">
        Write this recovery key down and keep it offline, away from this
        device. It is shown only now. With it and a copy of the vault file you
        can get back into the vault if you forget the master password or lose
        this device's Windows Hello.
      </p>
      <p class="key mono" aria-label="recovery key">{recoveryKey}</p>
      <div>
        <button class="button primary" onclick={writtenDown}>I have written it down</button>
      </div>
    {:else}
      {#if status.has_recovery_kit}
        <p class="muted">
          This vault has a recovery kit. Making a new one makes the old
          recovery key stop working.
        </p>
      {:else}
        <p class="notice warn">
          This vault has no recovery kit. Without one, a forgotten master
          password or a lost device means the vault is lost.
        </p>
      {/if}
      <p class="muted small">
        Every part of the vault must be open: Windows Hello may ask for your
        one-time codes and your passkeys.
      </p>
      <div>
        <button class="button" class:primary={!status.has_recovery_kit} onclick={() => void createKit()} disabled={kitBusy}>
          {kitBusy ? "Waiting…" : status.has_recovery_kit ? "Make a new recovery kit" : "Make a recovery kit"}
        </button>
      </div>
    {/if}
    {#if kitError}
      <p class="notice error" role="alert">{kitError}</p>
    {/if}
  </section>

  <section class="card block">
    <h3>Master password</h3>
    <form class="password" onsubmit={changePassword}>
      <label class="field">
        <span>Current master password</span>
        <input class="input" type="password" autocomplete="current-password" bind:value={current} />
      </label>
      <label class="field">
        <span>New master password (at least {MIN_MASTER_PASSWORD_CHARS} characters)</span>
        <input class="input" type="password" autocomplete="new-password" bind:value={next} />
      </label>
      <label class="field">
        <span>Repeat the new master password</span>
        <input class="input" type="password" autocomplete="new-password" bind:value={again} />
      </label>
      {#if again.length > 0 && next !== again}
        <p class="notice warn">The two new passwords differ.</p>
      {/if}
      {#if passwordError}
        <p class="notice error" role="alert">{passwordError}</p>
      {/if}
      {#if passwordDone}
        <p class="notice ok">The master password was changed. Unlock with the new one.</p>
      {/if}
      <div>
        <button class="button" type="submit" disabled={!passwordReady}>
          {passwordBusy ? "Changing…" : "Change master password"}
        </button>
      </div>
    </form>
  </section>

  <Transfer {onchanged} />

  <section class="card block">
    <h3>About</h3>
    <dl>
      <dt>Version</dt>
      <dd>{info?.version ?? ""}</dd>
      <dt>Vault file</dt>
      <dd class="mono">{info?.vault_path ?? ""}</dd>
      <dt>Vault daemon</dt>
      <dd>{status.sandboxed ? "Runs in a sandbox without network access" : "Runs WITHOUT its sandbox"}</dd>
      <dt>This device</dt>
      <dd class="mono">{status.device_id}</dd>
    </dl>
  </section>
</div>

<style>
  .settings {
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 680px;
  }

  .block {
    padding: 18px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    box-shadow: none;
  }

  .password {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .key {
    padding: 14px;
    border: 2px dashed var(--warn);
    border-radius: var(--radius);
    font-size: 18px;
    text-align: center;
    word-break: break-all;
    user-select: all;
  }

  .small {
    font-size: 12px;
  }

  dl {
    margin: 0;
    display: grid;
    grid-template-columns: 120px 1fr;
    gap: 8px 16px;
    font-size: 13px;
  }

  dt {
    color: var(--text-3);
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }
</style>

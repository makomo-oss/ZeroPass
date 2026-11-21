<script lang="ts">
  import { api, devices, errorMessage, isCommandError } from "../api";
  import ConfirmButton from "../components/ConfirmButton.svelte";

  let { onunlocked, onreset }: { onunlocked: () => void; onreset: () => void } = $props();

  let password = $state("");
  let busy = $state(false);
  let resetting = $state(false);
  let error = $state("");
  let input: HTMLInputElement | undefined = $state();

  $effect(() => {
    input?.focus();
  });

  async function unlock(event: SubmitEvent) {
    event.preventDefault();
    if (password.length === 0 || busy || resetting) return;
    busy = true;
    error = "";
    try {
      await api.unlock("password", password);
      password = "";
      onunlocked();
    } catch (caught) {
      error =
        isCommandError(caught) && caught.code === "WrongPassword"
          ? "That is not the master password."
          : errorMessage(caught);
      password = "";
      input?.focus();
    } finally {
      busy = false;
    }
  }

  async function resetAndRepair() {
    if (busy || resetting) return;
    resetting = true;
    error = "";
    try {
      await devices.resetLocalVault();
      onreset();
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      resetting = false;
    }
  }
</script>

<main class="center">
  <form class="card panel" onsubmit={unlock}>
    <div class="logo" aria-hidden="true"></div>
    <h1>ZeroPass is locked</h1>
    <label class="field">
      <span>Master password</span>
      <input
        bind:this={input}
        class="input"
        type="password"
        autocomplete="current-password"
        bind:value={password}
        disabled={busy || resetting}
      />
    </label>
    {#if error}
      <p class="notice error" role="alert">{error}</p>
    {/if}
    <button class="button primary" type="submit" disabled={busy || resetting || password.length === 0}>
      {busy ? "Unlocking…" : "Unlock"}
    </button>
    <div class="repair">
      <ConfirmButton
        label={resetting ? "Resetting…" : "Reset and re-pair with another device"}
        question="Delete this local vault and join as a new device? Unsynced changes on this device will be lost."
        confirmLabel="Delete and re-pair"
        disabled={busy || resetting}
        onconfirm={() => void resetAndRepair()}
      />
    </div>
  </form>
</main>

<style>
  .center {
    height: 100%;
    display: grid;
    place-items: center;
    padding: 24px;
  }

  .panel {
    width: min(380px, 100%);
    padding: 28px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .logo {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    background: linear-gradient(135deg, #1e40af, #0e7490);
  }

  .repair {
    padding-top: 8px;
    border-top: 1px solid var(--border);
  }
</style>

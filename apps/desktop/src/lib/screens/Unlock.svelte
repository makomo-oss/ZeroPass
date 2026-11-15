<script lang="ts">
  import { api, errorMessage, isCommandError } from "../api";

  let { onunlocked }: { onunlocked: () => void } = $props();

  let password = $state("");
  let busy = $state(false);
  let error = $state("");
  let input: HTMLInputElement | undefined = $state();

  $effect(() => {
    input?.focus();
  });

  async function unlock(event: SubmitEvent) {
    event.preventDefault();
    if (password.length === 0 || busy) return;
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
        disabled={busy}
      />
    </label>
    {#if error}
      <p class="notice error" role="alert">{error}</p>
    {/if}
    <button class="button primary" type="submit" disabled={busy || password.length === 0}>
      {busy ? "Unlocking…" : "Unlock"}
    </button>
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
</style>

<script lang="ts">
  import { api, errorMessage, MIN_MASTER_PASSWORD_CHARS, type Status } from "../api";
  import Join from "../components/Join.svelte";

  let {
    vaultPath,
    startInJoin = false,
    oncreated,
    onjoined,
  }: {
    vaultPath: string;
    startInJoin?: boolean;
    oncreated: (status: Status) => void;
    onjoined: () => void;
  } = $props();

  let joinChoice: boolean | null = $state(null);
  let joining = $derived(joinChoice ?? startInJoin);

  let password = $state("");
  let again = $state("");
  let busy = $state(false);
  let error = $state("");

  let tooShort = $derived(
    password.length > 0 && [...password].length < MIN_MASTER_PASSWORD_CHARS,
  );
  let mismatch = $derived(again.length > 0 && password !== again);
  let ready = $derived(
    [...password].length >= MIN_MASTER_PASSWORD_CHARS && password === again && !busy,
  );

  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    error = "";
    try {
      const status = await api.createVault(password);
      password = "";
      again = "";
      oncreated(status);
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }
</script>

<main class="center">
  {#if joining}
  <div class="card panel">
    <Join {onjoined} oncancel={() => (joinChoice = false)} />
  </div>
  {:else}
  <form class="card panel" onsubmit={create}>
    <div class="head">
      <div class="logo" aria-hidden="true"></div>
      <h1>Create your vault</h1>
      <p class="muted">
        Your vault stays on this device. Nothing is sent to a server; other
        devices get it only by pairing with this one nearby.
      </p>
    </div>

    <label class="field">
      <span>Master password</span>
      <input
        class="input"
        type="password"
        autocomplete="new-password"
        bind:value={password}
        disabled={busy}
      />
    </label>
    <label class="field">
      <span>Repeat the master password</span>
      <input
        class="input"
        type="password"
        autocomplete="new-password"
        bind:value={again}
        disabled={busy}
      />
    </label>

    {#if tooShort}
      <p class="notice warn">
        Use at least {MIN_MASTER_PASSWORD_CHARS} characters. A few unrelated words
        are easier to remember than a short password.
      </p>
    {:else if mismatch}
      <p class="notice warn">The two passwords differ.</p>
    {/if}
    {#if error}
      <p class="notice error" role="alert">{error}</p>
    {/if}
    {#if busy}
      <p class="notice info">
        Creating the vault… Windows Hello may ask you to confirm twice: once for
        your one-time codes, once for your passkeys.
      </p>
    {/if}

    <p class="muted small">
      The master password cannot be recovered. After this, create a recovery
      kit and keep it somewhere safe.
    </p>

    <button class="button primary" type="submit" disabled={!ready}>
      Create vault
    </button>
    <button class="button ghost" type="button" onclick={() => (joinChoice = true)} disabled={busy}>
      Join a vault from another device instead
    </button>
    <p class="muted small path" title={vaultPath}>{vaultPath}</p>
  </form>
  {/if}
</main>

<style>
  .center {
    height: 100%;
    display: grid;
    place-items: center;
    padding: 24px;
    overflow: auto;
  }

  .panel {
    width: min(440px, 100%);
    padding: 28px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .head {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 4px;
  }

  .logo {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    background: linear-gradient(135deg, #1e40af, #0e7490);
  }

  .small {
    font-size: 12px;
  }

  .path {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>

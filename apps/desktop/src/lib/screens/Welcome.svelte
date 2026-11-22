<script lang="ts">
  import { api, errorMessage, isCommandError, MIN_MASTER_PASSWORD_CHARS, type Status } from "../api";
  import Join from "../components/Join.svelte";

  let {
    vaultPath,
    oncreated,
    onjoined,
  }: {
    vaultPath: string;
    oncreated: (status: Status) => void;
    onjoined: () => void;
  } = $props();

  let joining = $state(false);

  let password = $state("");
  let again = $state("");
  let busy = $state(false);
  let error = $state("");
  /** Windows Hello could not be used: the user may set it up, or go on without. */
  let noHello = $state(false);

  let tooShort = $derived(
    password.length > 0 && [...password].length < MIN_MASTER_PASSWORD_CHARS,
  );
  let mismatch = $derived(again.length > 0 && password !== again);
  let ready = $derived(
    [...password].length >= MIN_MASTER_PASSWORD_CHARS && password === again && !busy,
  );

  async function create(event: SubmitEvent) {
    event.preventDefault();
    await make(false);
  }

  async function make(withoutHardware: boolean) {
    if (!ready) return;
    busy = true;
    error = "";
    noHello = false;
    try {
      const status = await api.createVault(password, withoutHardware);
      password = "";
      again = "";
      oncreated(status);
    } catch (caught) {
      if (isCommandError(caught) && caught.code === "HardwareUnavailable") {
        noHello = true;
      } else {
        error = errorMessage(caught);
      }
    } finally {
      busy = false;
    }
  }
</script>

<main class="center">
  {#if joining}
  <div class="card panel">
    <Join {onjoined} oncancel={() => (joining = false)} />
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
    {#if noHello}
      <div class="notice warn no-hello" role="alert">
        <p>
          Windows Hello is not set up on this PC. Your one-time codes and
          passkeys are protected by it, apart from the master password.
        </p>
        <p>
          Set up a PIN in Settings &gt; Accounts &gt; Sign-in options, then choose
          Create vault again. Or create the vault without them for now: you can
          add them on this PC once Windows Hello is set up.
        </p>
        <div>
          <button class="button small" type="button" onclick={() => void make(true)} disabled={!ready}>
            Create without Windows Hello
          </button>
        </div>
      </div>
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
    <button class="button ghost" type="button" onclick={() => (joining = true)} disabled={busy}>
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

  .no-hello {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .no-hello p {
    margin: 0;
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

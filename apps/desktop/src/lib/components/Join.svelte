<script lang="ts">
  import { onMount } from "svelte";

  import { devices, errorMessage, isCommandError, MIN_MASTER_PASSWORD_CHARS } from "../api";

  let { onjoined, oncancel }: { onjoined: () => void; oncancel: () => void } = $props();

  let code = $state("");
  let name = $state("");
  let password = $state("");
  let again = $state("");
  let busy = $state(false);
  let error = $state("");
  let result = $state("");
  /** Windows Hello could not be used: the user may set it up, or go on without. */
  let noHello = $state(false);

  let ready = $derived(
    code.trim().length > 0 &&
      [...password].length >= MIN_MASTER_PASSWORD_CHARS &&
      password === again &&
      !busy,
  );

  onMount(() => {
    devices
      .defaultName()
      .then((found) => {
        if (name === "") name = found;
      })
      .catch(() => {});
  });

  async function join(event: SubmitEvent) {
    event.preventDefault();
    await connect(false);
  }

  async function connect(withoutHardware: boolean) {
    if (!ready) return;
    busy = true;
    error = "";
    noHello = false;
    try {
      const joined = await devices.join(code, name, password, withoutHardware);
      password = "";
      again = "";
      code = "";
      result = joined.first_sync_error
        ? `Joined. The first sync did not complete (${joined.first_sync_error}); the next one catches up.`
        : `Joined. First sync: received ${joined.received} change(s).`;
      onjoined();
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

<form class="join" onsubmit={join}>
  <h1>Join a vault</h1>
  <p class="muted">
    On a device that has the vault, open ZeroPass, go to <strong>Devices</strong>
    and choose <strong>Add a device</strong>. Enter the code it shows here.
    Both devices must be on the same network.
  </p>
  <label class="field">
    <span>Pairing code</span>
    <input class="input mono" bind:value={code} autocomplete="off" spellcheck="false" disabled={busy} />
  </label>
  <label class="field">
    <span>This device's name (shown on the other device)</span>
    <input class="input" bind:value={name} disabled={busy} />
  </label>
  <label class="field">
    <span>Master password for this device (at least {MIN_MASTER_PASSWORD_CHARS} characters)</span>
    <input class="input" type="password" autocomplete="new-password" bind:value={password} disabled={busy} />
  </label>
  <label class="field">
    <span>Repeat the master password</span>
    <input class="input" type="password" autocomplete="new-password" bind:value={again} disabled={busy} />
  </label>
  <p class="muted small">
    Each device has its own master password. The one-time codes and passkeys
    are bound to this device's Windows Hello.
  </p>
  {#if again.length > 0 && password !== again}
    <p class="notice warn">The two passwords differ.</p>
  {/if}
  {#if busy}
    <p class="notice info">Connecting… Confirm on the other device that this one may join. Windows Hello may ask here too.</p>
  {/if}
  {#if error}
    <p class="notice error" role="alert">{error}</p>
  {/if}
  {#if noHello}
    <div class="notice warn no-hello" role="alert">
      <p>
        Windows Hello is not set up on this PC, so it cannot keep your one-time
        codes and passkeys.
      </p>
      <p>
        Set up a PIN in Settings &gt; Accounts &gt; Sign-in options, then join
        again (ask the other device for a new code if this one has expired). Or
        join without them for now: once Windows Hello is set up, this PC can get
        them from a device that has them.
      </p>
      <div>
        <button class="button small" type="button" onclick={() => void connect(true)} disabled={!ready}>
          Join without Windows Hello
        </button>
      </div>
    </div>
  {/if}
  {#if result}
    <p class="notice ok">{result}</p>
  {/if}
  <div class="actions">
    <button class="button primary" type="submit" disabled={!ready}>{busy ? "Joining…" : "Join"}</button>
    <button class="button ghost" type="button" onclick={oncancel} disabled={busy}>Back</button>
  </div>
</form>

<style>
  .join {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .small {
    font-size: 12px;
  }

  .no-hello {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .no-hello p {
    margin: 0;
  }

  .actions {
    display: flex;
    gap: 8px;
  }
</style>

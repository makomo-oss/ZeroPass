<script lang="ts">
  // Gets the one-time code and passkey keys from another device of the vault
  // (ADR-0011): that device shows a pairing code, this one enters it.
  import { devices, errorMessage, isCommandError, type DomainName } from "../api";

  let {
    onreceived,
  }: {
    /** Keys were taken in: the state of the vault changed. */
    onreceived: () => void;
  } = $props();

  let code = $state("");
  let busy = $state(false);
  let error = $state("");
  let result = $state("");

  const NAMES: Record<DomainName, string> = {
    password: "passwords",
    totp: "one-time codes",
    passkey: "passkeys",
  };

  async function receive(event: SubmitEvent) {
    event.preventDefault();
    if (code.trim() === "") return;
    busy = true;
    error = "";
    result = "";
    try {
      const received = await devices.receiveKeys(code);
      code = "";
      result =
        received.domains.length === 0
          ? "This PC already had every key the other device has."
          : `Received the keys of your ${received.domains.map((domain) => NAMES[domain]).join(" and ")}.`;
      if (received.first_sync_error) {
        result += ` The sync that follows did not complete (${received.first_sync_error}); the next one catches up.`;
      }
      onreceived();
    } catch (caught) {
      if (isCommandError(caught) && caught.code === "HardwareUnavailable") {
        error =
          "Windows Hello is not set up on this PC yet. Set up a PIN in Settings > Accounts > Sign-in options, then try again.";
      } else if (isCommandError(caught) && caught.code === "UserCancelled") {
        error =
          "Windows Hello was cancelled here, or the other device refused (or has no one-time code or passkey keys to give).";
      } else {
        error = errorMessage(caught);
      }
    } finally {
      busy = false;
    }
  }
</script>

<form class="receive" onsubmit={receive}>
  <p class="muted small">
    On a device that has them, open ZeroPass, go to <strong>Devices</strong>
    and choose <strong>Add a device</strong>. Enter the code it shows here, and
    confirm there. Both devices must be on the same network.
  </p>
  <div class="row">
    <input
      class="input mono"
      bind:value={code}
      placeholder="Pairing code"
      aria-label="Pairing code from the other device"
      autocomplete="off"
      spellcheck="false"
      disabled={busy}
    />
    <button class="button primary" type="submit" disabled={busy || code.trim() === ""}>
      {busy ? "Waiting…" : "Get the keys"}
    </button>
  </div>
  {#if busy}
    <p class="notice info small">Confirm on the other device. Windows Hello may ask here too.</p>
  {/if}
  {#if error}
    <p class="notice error" role="alert">{error}</p>
  {/if}
  {#if result}
    <p class="notice ok">{result}</p>
  {/if}
</form>

<style>
  .receive {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .receive p {
    margin: 0;
  }

  .row {
    display: flex;
    gap: 8px;
  }

  .row input {
    flex: 1;
    min-width: 0;
  }

  .small {
    font-size: 12px;
  }
</style>

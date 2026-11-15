<script lang="ts">
  import { onDestroy, onMount } from "svelte";

  import { devices, errorMessage, type PairProgress } from "../api";
  import { transportNames } from "../search";

  let { onclose, onadded }: { onclose: () => void; onadded: () => void } = $props();

  let progress: PairProgress = $state({ stage: "idle" });
  let error = $state("");
  let left = $state(0);
  let poller: ReturnType<typeof setInterval> | undefined;
  let countdown: ReturnType<typeof setInterval> | undefined;

  function stop() {
    clearInterval(poller);
    clearInterval(countdown);
  }

  async function poll() {
    try {
      const next = await devices.pairProgress();
      if (next.stage === "waiting" && progress.stage !== "waiting") {
        left = next.lifetime_secs;
        clearInterval(countdown);
        countdown = setInterval(() => (left = Math.max(0, left - 1)), 1000);
      }
      progress = next;
      if (next.stage === "done") {
        stop();
        onadded();
      } else if (next.stage === "failed" || next.stage === "cancelled") {
        stop();
      }
    } catch (caught) {
      error = errorMessage(caught);
      stop();
    }
  }

  async function start() {
    error = "";
    try {
      await devices.pairStart();
      progress = { stage: "starting" };
      clearInterval(poller);
      poller = setInterval(() => void poll(), 300);
    } catch (caught) {
      error = errorMessage(caught);
    }
  }

  async function answer(approved: boolean) {
    await devices.pairAnswer(approved);
  }

  async function cancel() {
    await devices.pairCancel();
    stop();
    onclose();
  }

  onDestroy(() => {
    stop();
    if (progress.stage === "starting" || progress.stage === "waiting" || progress.stage === "confirm") {
      void devices.pairCancel();
    }
  });

  onMount(() => void start());
</script>

<section class="card pairing">
  {#if progress.stage === "idle" || progress.stage === "starting"}
    <h3>Add a device</h3>
    <p class="muted">
      Preparing a pairing code. Windows Hello may ask: adding a device hands
      it every part of the vault.
    </p>
  {:else if progress.stage === "waiting"}
    <h3>Add a device</h3>
    <div class="offer">
      <img class="qr" src={progress.qr} alt="Pairing code as a QR code" width="220" height="220" />
      <div class="how">
        <p>
          On a phone, scan the picture with the ZeroPass app. On a computer,
          choose <strong>Join a vault from another device</strong> and enter
          the code:
        </p>
        <p class="code mono" aria-label="pairing code">{progress.code}</p>
        <p class="muted small">
          Valid for {left} more seconds, once. Waiting on {transportNames(progress.transports)}.
        </p>
        {#each progress.problems as problem (problem)}
          <p class="muted small">Not available: {problem}</p>
        {/each}
        <p class="notice warn small">
          Anyone who sees the code while it is valid can ask to join. You will
          see the device's name and decide.
        </p>
      </div>
    </div>
    <div><button class="button" onclick={() => void cancel()}>Cancel</button></div>
  {:else if progress.stage === "confirm"}
    <h3>Add this device to the vault?</h3>
    <p class="device"><strong>{progress.name}</strong> <span class="mono muted">{progress.device_id}</span></p>
    <p class="muted">
      Add it only if it is the device you are setting up. It gets every
      password, one-time code and passkey of this vault.
    </p>
    <div class="actions">
      <button class="button primary" onclick={() => void answer(true)}>Add the device</button>
      <button class="button" onclick={() => void answer(false)}>Refuse</button>
    </div>
  {:else if progress.stage === "done"}
    <h3>Device added</h3>
    <p><strong>{progress.name}</strong> is now a device of this vault.</p>
    {#if progress.first_sync_error}
      <p class="notice warn">The first sync did not complete ({progress.first_sync_error}); the next sync catches up.</p>
    {:else}
      <p class="notice ok">First sync: sent {progress.sent} change(s), received {progress.received}.</p>
    {/if}
    <div><button class="button primary" onclick={onclose}>Close</button></div>
  {:else if progress.stage === "failed"}
    <h3>The device was not added</h3>
    <p class="notice error">{progress.message}</p>
    <div class="actions">
      <button class="button primary" onclick={() => void start()}>Try again</button>
      <button class="button" onclick={onclose}>Close</button>
    </div>
  {:else if progress.stage === "cancelled"}
    <h3>Pairing cancelled</h3>
    <div><button class="button" onclick={onclose}>Close</button></div>
  {/if}
  {#if error}
    <p class="notice error" role="alert">{error}</p>
    <div><button class="button" onclick={onclose}>Close</button></div>
  {/if}
</section>

<style>
  .pairing {
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    box-shadow: none;
  }

  .offer {
    display: flex;
    gap: 20px;
    align-items: flex-start;
    flex-wrap: wrap;
  }

  .qr {
    background: #fff;
    border-radius: var(--radius);
    padding: 6px;
  }

  .how {
    flex: 1;
    min-width: 240px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .code {
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-2);
    word-break: break-all;
    user-select: all;
  }

  .small {
    font-size: 12px;
  }

  .device {
    display: flex;
    gap: 10px;
    align-items: baseline;
    flex-wrap: wrap;
  }

  .actions {
    display: flex;
    gap: 8px;
  }
</style>

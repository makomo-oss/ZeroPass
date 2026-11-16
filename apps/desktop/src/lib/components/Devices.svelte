<script lang="ts">
  import { onMount } from "svelte";

  import {
    devices,
    errorMessage,
    isCommandError,
    type Device,
    type SyncReport,
    type SyncStatus,
  } from "../api";
  import { transportNames } from "../search";
  import ConfirmButton from "./ConfirmButton.svelte";
  import Pairing from "./Pairing.svelte";

  let { onchanged }: { onchanged: () => void } = $props();

  let list: Device[] = $state([]);
  let sync: SyncStatus | null = $state(null);
  let report: SyncReport | null = $state(null);
  let pairing = $state(false);
  let syncing = $state(false);
  let revoking: string | null = $state(null);
  let error = $state("");
  let notice = $state("");

  async function loadDevices() {
    try {
      list = await devices.list();
    } catch (caught) {
      error = errorMessage(caught);
    }
  }

  async function loadSync(start = false) {
    try {
      sync = await devices.syncStatus(start);
    } catch (caught) {
      error = errorMessage(caught);
    }
  }

  async function syncNow() {
    syncing = true;
    error = "";
    report = null;
    try {
      report = await devices.syncNow(15);
      await loadDevices();
      await loadSync();
      onchanged();
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      syncing = false;
    }
  }

  async function revoke(device: Device) {
    revoking = device.id;
    error = "";
    notice = "";
    try {
      await devices.revoke(device.id);
      notice = `"${device.name}" was revoked and the vault keys were replaced. The other devices get the new keys with their next sync. Change the passwords that device could see if it was stolen.`;
      await loadDevices();
    } catch (caught) {
      error =
        isCommandError(caught) && caught.code === "UserCancelled"
          ? "Windows Hello was cancelled. Every part of the vault must be open to revoke a device."
          : errorMessage(caught);
    } finally {
      revoking = null;
    }
  }

  onMount(() => {
    void loadDevices();
    void loadSync();
    const timer = setInterval(() => void loadSync(), 5000);
    return () => clearInterval(timer);
  });

  function stateLabel(device: Device): string {
    switch (device.state) {
      case "this":
        return "This device";
      case "revoked":
        return "Revoked";
      default:
        return "Active";
    }
  }
</script>

<div class="devices">
  <header>
    <h2>Devices</h2>
    {#if !pairing}
      <button class="button primary" onclick={() => (pairing = true)}>Add a device</button>
    {/if}
  </header>

  {#if pairing}
    <Pairing
      onclose={() => {
        pairing = false;
        void loadDevices();
      }}
      onadded={() => void loadDevices()}
    />
  {/if}

  <section class="card block">
    <div class="sync-head">
      <h3>Sync</h3>
      <button class="button small" onclick={() => void syncNow()} disabled={syncing || !sync?.running}>
        {syncing ? "Syncing…" : "Sync now"}
      </button>
    </div>
    {#if sync === null}
      <p class="muted">…</p>
    {:else if !sync.running}
      <p class="notice warn">The sync daemon is not running, so changes do not reach your other devices.</p>
      <div><button class="button small" onclick={() => void loadSync(true)}>Start it</button></div>
    {:else if sync.syncing}
      <p class="notice ok">
        Syncing with nearby devices over {transportNames(sync.transports)}. Nothing leaves your local
        network.
      </p>
    {:else}
      <p class="notice warn">Not syncing: {sync.not_syncing_because}</p>
    {/if}
    {#if sync && sync.problems.length > 0}
      <ul class="problems">
        {#each sync.problems as problem (problem)}
          <li class="muted">Not available: {problem}</li>
        {/each}
      </ul>
    {/if}
    {#if report}
      {#if report.other_devices === 0}
        <p class="muted">This vault has no other devices yet.</p>
      {:else if report.results.length === 0}
        <p class="muted">No other device of this vault was found nearby.</p>
      {:else}
        <ul class="results">
          {#each report.results as result, index (index)}
            <li>
              {#if result.error}
                <span class="bad">A sync attempt failed: {result.error}</span>
              {:else}
                Synced with <strong>{result.name}</strong>: sent {result.sent}, received {result.received}
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  </section>

  {#if notice}
    <p class="notice ok">{notice}</p>
  {/if}
  {#if error}
    <p class="notice error" role="alert">{error}</p>
  {/if}

  <table class="card list">
    <thead>
      <tr><th>Name</th><th>State</th><th>Changes held</th><th></th></tr>
    </thead>
    <tbody>
      {#each list as device (device.id)}
        <tr class:revoked={device.state === "revoked"}>
          <td>
            <div class="name">{device.name}</div>
            <div class="mono muted id">{device.id}</div>
          </td>
          <td>{stateLabel(device)}</td>
          <td>{device.changes_held}</td>
          <td class="tools">
            {#if device.state === "active"}
              <ConfirmButton
                label={revoking === device.id ? "Revoking…" : "Revoke"}
                question="Revoke it for good?"
                disabled={revoking !== null}
                onconfirm={() => void revoke(device)}
              />
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
  <p class="muted small">
    Revoke a lost or retired device. The vault keys are replaced so that it
    cannot read what changes from then on; what it already holds stays
    readable to it. Every part of the vault must be open: Windows Hello asks up
    to twice, once for your one-time codes and once for your passkeys.
  </p>
</div>

<style>
  .devices {
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 820px;
  }

  header,
  .sync-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .block {
    padding: 18px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    box-shadow: none;
  }

  .problems,
  .results {
    margin: 0;
    padding-left: 18px;
    font-size: 13px;
  }

  .bad {
    color: var(--danger);
  }

  .list {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    box-shadow: none;
    overflow: hidden;
  }

  th,
  td {
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }

  th {
    font-size: 12px;
    color: var(--text-3);
    font-weight: 600;
    background: var(--surface-2);
  }

  tbody tr:last-child td {
    border-bottom: 0;
  }

  .revoked td {
    color: var(--text-3);
  }

  .id {
    font-size: 11px;
  }

  .tools {
    text-align: right;
  }

  .small {
    font-size: 12px;
  }
</style>

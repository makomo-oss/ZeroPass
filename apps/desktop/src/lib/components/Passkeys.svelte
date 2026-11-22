<script lang="ts">
  import { api, errorMessage, isCommandError, items, type DomainState, type Summary } from "../api";
  import { byTitle } from "../search";
  import ConfirmButton from "./ConfirmButton.svelte";
  import MissingDomain from "./MissingDomain.svelte";

  let {
    domain,
    onchanged,
  }: {
    /** The state of the passkey domain. */
    domain: DomainState | undefined;
    /** The state of the vault may have changed. */
    onchanged: () => void;
  } = $props();

  let passkeys: Summary[] = $state([]);
  /** Passkeys made with keys that have not reached this device (ADR-0011). */
  let unreadable = $state(0);
  let busy = $state(false);
  let error = $state("");

  let unlocked = $derived(domain?.available === true && domain.unlocked);

  async function unlock() {
    busy = true;
    error = "";
    try {
      await api.unlock("passkey");
      onchanged();
    } catch (caught) {
      error =
        isCommandError(caught) && caught.code === "UserCancelled"
          ? "Windows Hello was cancelled."
          : errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function hide() {
    try {
      await api.lock("passkey");
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      passkeys = [];
      onchanged();
    }
  }

  async function load() {
    try {
      const listing = await items.listing("passkey");
      unreadable = listing.unreadable;
      passkeys = listing.items.sort(byTitle);
    } catch (caught) {
      passkeys = [];
      if (isCommandError(caught) && caught.code === "Locked") {
        onchanged();
      } else {
        error = errorMessage(caught);
      }
    }
  }

  async function remove(passkey: Summary) {
    try {
      await items.delete(passkey.id);
      await load();
    } catch (caught) {
      error = errorMessage(caught);
    }
  }

  $effect(() => {
    if (unlocked) {
      void load();
    } else {
      passkeys = [];
    }
  });
</script>

<section class="passkeys">
  <header>
    <h2>Passkeys</h2>
    {#if unlocked}
      <button class="button small" onclick={() => void hide()} title="Lock the passkeys now">Hide passkeys</button>
    {/if}
  </header>

  <p class="muted">
    Websites create and use passkeys through the ZeroPass browser extension.
    Windows Hello confirms every use. Passkeys reach your other devices with
    the next sync.
  </p>

  {#if domain && !domain.available}
    <MissingDomain {domain} what="passkeys" {onchanged} />
  {:else if !unlocked}
    <div class="locked card">
      <p>
        Passkeys are protected by Windows Hello, separately from your master
        password. They lock again after a while of not being used.
      </p>
      <button class="button primary" onclick={() => void unlock()} disabled={busy}>
        {busy ? "Waiting for Windows Hello…" : "Show passkeys"}
      </button>
    </div>
  {:else}
    {#if unreadable > 0}
      <p class="notice warn">
        {unreadable === 1 ? "1 passkey was" : `${unreadable} passkeys were`} made on another
        device with keys this PC does not have yet. Get the keys from that device.
      </p>
    {/if}
    {#if passkeys.length === 0 && unreadable === 0}
      <p class="muted">No passkeys yet.</p>
    {/if}
    <ul class="list">
      {#each passkeys as passkey (passkey.id)}
        <li class="card entry">
          <div class="who">
            <strong>{passkey.title}</strong>
            <span class="muted">{passkey.username || "(no account name)"}</span>
          </div>
          <ConfirmButton
            label="Delete"
            question="Delete this passkey? The site is not told: remove it there too."
            onconfirm={() => void remove(passkey)}
          />
        </li>
      {/each}
    </ul>
  {/if}

  {#if error}
    <p class="notice error" role="alert">{error}</p>
  {/if}
</section>

<style>
  .passkeys {
    display: flex;
    flex-direction: column;
    gap: 14px;
    max-width: 720px;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .locked {
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    align-items: flex-start;
    box-shadow: none;
  }

  .small {
    font-size: 12px;
  }

  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .entry {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 14px;
    box-shadow: none;
  }

  .who {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
</style>

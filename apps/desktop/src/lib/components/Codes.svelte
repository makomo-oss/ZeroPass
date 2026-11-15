<script lang="ts">
  import { onDestroy } from "svelte";

  import {
    api,
    errorMessage,
    isCommandError,
    items,
    type DomainState,
    type Summary,
  } from "../api";
  import { byTitle } from "../search";
  import ConfirmButton from "./ConfirmButton.svelte";
  import CopyButton from "./CopyButton.svelte";

  let {
    domain,
    logins,
    onchanged,
  }: {
    /** The state of the TOTP domain. */
    domain: DomainState | undefined;
    /** For tying a new entry to a login. */
    logins: Summary[];
    /** The state of the vault may have changed. */
    onchanged: () => void;
  } = $props();

  interface Entry {
    summary: Summary;
    code: string;
    remaining: number;
  }

  let entries: Entry[] = $state([]);
  let busy = $state(false);
  let error = $state("");
  let adding = $state(false);
  let uri = $state("");
  let loginId = $state("");
  let ticker: ReturnType<typeof setInterval> | undefined;

  let unlocked = $derived(domain?.available === true && domain.unlocked);

  async function unlock() {
    busy = true;
    error = "";
    try {
      await api.unlock("totp");
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
      await api.lock("totp");
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      entries = [];
      onchanged();
    }
  }

  async function load() {
    try {
      const list = (await items.list("totp")).sort(byTitle);
      entries = await Promise.all(
        list.map(async (summary) => {
          const code = await items.totpCode(summary.id);
          return { summary, code: code.code, remaining: code.seconds_remaining };
        }),
      );
    } catch (caught) {
      entries = [];
      if (isCommandError(caught) && caught.code === "Locked") {
        onchanged();
      } else {
        error = errorMessage(caught);
      }
    }
  }

  async function refresh(entry: Entry) {
    try {
      const code = await items.totpCode(entry.summary.id);
      entry.code = code.code;
      entry.remaining = code.seconds_remaining;
    } catch (caught) {
      if (isCommandError(caught) && caught.code === "Locked") {
        entries = [];
        onchanged();
      }
    }
  }

  function tick() {
    for (const entry of entries) {
      entry.remaining -= 1;
      if (entry.remaining <= 0) {
        entry.remaining = 0;
        void refresh(entry);
      }
    }
  }

  $effect(() => {
    if (unlocked) {
      void load();
      ticker = setInterval(tick, 1000);
    } else {
      entries = [];
    }
    return () => clearInterval(ticker);
  });

  onDestroy(() => {
    entries = [];
  });

  async function add(event: SubmitEvent) {
    event.preventDefault();
    if (uri.trim() === "") return;
    busy = true;
    error = "";
    try {
      await items.addTotp(uri, loginId === "" ? null : loginId);
      uri = "";
      loginId = "";
      adding = false;
      await load();
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }

  async function remove(entry: Entry) {
    try {
      await items.delete(entry.summary.id);
      await load();
    } catch (caught) {
      error = errorMessage(caught);
    }
  }

  function grouped(code: string): string {
    return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
  }
</script>

<section class="codes">
  <header>
    <h2>One-time codes</h2>
    {#if unlocked}
      <div class="head-tools">
        <button class="button small" onclick={() => void hide()} title="Lock the one-time codes now">Hide codes</button>
        <button class="button small" onclick={() => (adding = !adding)}>
          {adding ? "Close" : "Add"}
        </button>
      </div>
    {/if}
  </header>

  {#if !domain?.available}
    <p class="notice info">
      This vault keeps no one-time codes: it was created on a device without
      Windows Hello. One-time codes are protected by Windows Hello, separately
      from your master password.
    </p>
  {:else if !unlocked}
    <div class="locked card">
      <p>
        One-time codes are protected by Windows Hello, separately from your
        master password. They lock again after a minute of not being used.
      </p>
      <button class="button primary" onclick={() => void unlock()} disabled={busy}>
        {busy ? "Waiting for Windows Hello…" : "Show one-time codes"}
      </button>
    </div>
  {:else}
    {#if adding}
      <form class="card add" onsubmit={add}>
        <label class="field">
          <span>Setup key as an otpauth:// address</span>
          <input class="input mono" type="password" bind:value={uri} autocomplete="off"
            placeholder="otpauth://totp/Service:you@example.com?secret=…" />
        </label>
        <label class="field">
          <span>Belongs to the login (optional)</span>
          <select class="input" bind:value={loginId}>
            <option value="">—</option>
            {#each [...logins].sort(byTitle) as login (login.id)}
              <option value={login.id}>{login.title}{login.username ? ` (${login.username})` : ""}</option>
            {/each}
          </select>
        </label>
        <p class="muted small">
          The setup key is stored and never shown again; only the codes are.
        </p>
        <div>
          <button class="button primary" type="submit" disabled={busy || uri.trim() === ""}>Add</button>
        </div>
      </form>
    {/if}

    {#if entries.length === 0}
      <p class="muted">No one-time codes yet.</p>
    {/if}
    <ul class="list">
      {#each entries as entry (entry.summary.id)}
        <li class="card entry">
          <div class="who">
            <strong>{entry.summary.title || "(no issuer)"}</strong>
            <span class="muted">{entry.summary.username}</span>
          </div>
          <span class="code mono" aria-label="current code">{grouped(entry.code)}</span>
          <span class="remaining muted" title="seconds until the next code">{entry.remaining}s</span>
          <CopyButton id={entry.summary.id} field="code" onerror={(message) => (error = message)} />
          <ConfirmButton label="Delete" question="Delete these codes?" onconfirm={() => void remove(entry)} />
        </li>
      {/each}
    </ul>
  {/if}

  {#if error}
    <p class="notice error" role="alert">{error}</p>
  {/if}
</section>

<style>
  .codes {
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

  .head-tools {
    display: flex;
    gap: 6px;
  }

  .locked {
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    align-items: flex-start;
    box-shadow: none;
  }

  .add {
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
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

  .who strong,
  .who span {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .code {
    font-size: 22px;
    letter-spacing: 0.04em;
    color: var(--accent);
  }

  .remaining {
    width: 32px;
    text-align: right;
    font-size: 12px;
  }
</style>

<script lang="ts">
  import { onMount } from "svelte";

  import {
    api,
    domainState,
    errorMessage,
    isCommandError,
    items,
    type AppInfo,
    type Details,
    type Status,
    type Summary,
  } from "../api";
  import Codes from "../components/Codes.svelte";
  import Devices from "../components/Devices.svelte";
  import Generator from "../components/Generator.svelte";
  import LoginForm from "../components/LoginForm.svelte";
  import LoginView from "../components/LoginView.svelte";
  import NoteEditor from "../components/NoteEditor.svelte";
  import NoteView from "../components/NoteView.svelte";
  import Settings from "../components/Settings.svelte";
  import { userActive } from "../activity";
  import { byTitle, filterItems, hostOf } from "../search";

  let {
    status,
    info,
    onlock,
    onchanged,
  }: {
    status: Status;
    info: AppInfo | null;
    onlock: () => void;
    /** The state of the vault may have changed: ask again. */
    onchanged: () => void;
  } = $props();

  type Section = "logins" | "notes" | "codes" | "generator" | "devices" | "settings";
  let section = $state<Section>("logins");
  let all: Summary[] = $state([]);
  let query = $state("");
  let selected: string | null = $state(null);
  let details: Details | null = $state(null);
  let mode = $state<"view" | "new" | "edit">("view");
  let error = $state("");
  let search: HTMLInputElement | undefined = $state();

  let kindOf = $derived(section === "notes" ? "note" : "login");
  let shown = $derived(
    filterItems(
      all.filter((item) => item.kind === kindOf),
      query,
    ).sort(byTitle),
  );
  let logins = $derived(all.filter((item) => item.kind === "login"));
  let listed = $derived(section === "logins" || section === "notes");

  function handle(caught: unknown) {
    if (isCommandError(caught) && caught.code === "Locked" && caught.domain === "password") {
      // The vault locked itself: back to the unlock screen.
      onchanged();
      return;
    }
    error = errorMessage(caught);
  }

  async function load() {
    try {
      all = await items.list("password");
      error = "";
    } catch (caught) {
      handle(caught);
    }
  }

  async function open(id: string) {
    selected = id;
    mode = "view";
    details = null;
    try {
      details = await items.get(id);
    } catch (caught) {
      handle(caught);
    }
  }

  function choose(next: Section) {
    section = next;
    selected = null;
    details = null;
    mode = "view";
    query = "";
    // What other devices changed shows when the user looks.
    if (next === "logins" || next === "notes") void load();
  }

  async function saved(id: string) {
    await load();
    await open(id);
  }

  async function remove() {
    if (!selected) return;
    try {
      await items.delete(selected);
      selected = null;
      details = null;
      await load();
    } catch (caught) {
      handle(caught);
    }
  }

  /** How often the list is read again: other devices change the vault too. */
  const RELOAD_MS = 10_000;
  /** How recently the user must have been active for a background reload. */
  const ACTIVE_MS = 60_000;

  onMount(() => {
    void load();
    const keys = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f" && listed) {
        event.preventDefault();
        search?.focus();
      }
    };
    const onFocus = () => void load();
    const timer = setInterval(() => {
      // Not while a form is open: nothing the user types is disturbed, but
      // there is no need either.
      // Only while the user is here: reading the vault counts as using it,
      // and an idle window must let the vault lock itself.
      if (mode === "view" && userActive(ACTIVE_MS, Date.now(), document.visibilityState === "visible")) void load();
    }, RELOAD_MS);
    window.addEventListener("keydown", keys);
    window.addEventListener("focus", onFocus);
    return () => {
      clearInterval(timer);
      window.removeEventListener("keydown", keys);
      window.removeEventListener("focus", onFocus);
    };
  });

  const sections: { id: Section; label: string }[] = [
    { id: "logins", label: "Logins" },
    { id: "notes", label: "Secure notes" },
    { id: "codes", label: "One-time codes" },
    { id: "generator", label: "Password generator" },
    { id: "devices", label: "Devices" },
    { id: "settings", label: "Settings" },
  ];

  function subtitle(item: Summary): string {
    if (item.username) return item.username;
    const host = item.urls.length > 0 ? hostOf(item.urls[0] ?? "") : "";
    return host;
  }
</script>

<div class="layout" class:listed>
  <nav class="sidebar">
    <div class="brand">
      <div class="logo" aria-hidden="true"></div>
      <span>ZeroPass</span>
    </div>
    <ul>
      {#each sections as entry (entry.id)}
        <li>
          <button
            class="nav"
            class:active={section === entry.id}
            onclick={() => choose(entry.id)}
            aria-current={section === entry.id ? "page" : undefined}
          >
            {entry.label}
            {#if entry.id === "logins"}<span class="count">{logins.length}</span>{/if}
            {#if entry.id === "notes"}<span class="count">{all.length - logins.length}</span>{/if}
            {#if entry.id === "settings" && !status.has_recovery_kit}<span class="dot" title="No recovery kit yet"></span>{/if}
          </button>
        </li>
      {/each}
    </ul>
    <div class="foot">
      <button class="button" onclick={onlock}>Lock</button>
    </div>
  </nav>

  {#if listed}
    <section class="list">
      <div class="list-head">
        <input
          bind:this={search}
          class="input"
          type="search"
          placeholder="Search (Ctrl+F)"
          bind:value={query}
          aria-label="Search"
        />
        <button
          class="button primary"
          onclick={() => {
            selected = null;
            details = null;
            mode = "new";
          }}
          title={section === "notes" ? "New secure note" : "New login"}>+</button
        >
      </div>
      <ul class="items">
        {#each shown as item (item.id)}
          <li>
            <button class="item" class:active={selected === item.id} onclick={() => void open(item.id)}>
              <span class="item-title">{item.title || "(no title)"}</span>
              <span class="item-sub muted">{subtitle(item)}</span>
            </button>
          </li>
        {:else}
          <li class="empty muted">
            {#if query}
              Nothing matches “{query}”.
            {:else if section === "notes"}
              No secure notes yet.
            {:else}
              No logins yet. Add one with +.
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  <main class="content">
    {#if !status.has_recovery_kit && section !== "settings"}
      <p class="notice warn banner">
        This vault has no recovery kit yet.
        <button class="link" onclick={() => choose("settings")}>Make one in Settings</button>
      </p>
    {/if}
    {#if error}
      <p class="notice error" role="alert">{error}</p>
    {/if}

    {#if section === "codes"}
      <Codes domain={domainState(status, "totp")} {logins} {onchanged} />
    {:else if section === "generator"}
      <div class="generator">
        <h2>Password generator</h2>
        <Generator />
      </div>
    {:else if section === "devices"}
      <Devices {onchanged} />
    {:else if section === "settings"}
      <Settings {status} {info} {onchanged} />
    {:else if mode === "new"}
      {#if section === "notes"}
        {#key "new-note"}
          <NoteEditor onsaved={(id) => void saved(id)} oncancel={() => (mode = "view")} />
        {/key}
      {:else}
        {#key "new-login"}
          <LoginForm onsaved={(id) => void saved(id)} oncancel={() => (mode = "view")} />
        {/key}
      {/if}
    {:else if details?.kind === "login"}
      {#if mode === "edit"}
        {#key details.id}
          <LoginForm existing={details} onsaved={(id) => void saved(id)} oncancel={() => (mode = "view")} />
        {/key}
      {:else}
        <LoginView login={details} onedit={() => (mode = "edit")} ondelete={() => void remove()} />
      {/if}
    {:else if details?.kind === "note"}
      {#if mode === "edit"}
        {#key details.id}
          <NoteEditor existing={details} onsaved={(id) => void saved(id)} oncancel={() => (mode = "view")} />
        {/key}
      {:else}
        <NoteView note={details} onedit={() => (mode = "edit")} ondelete={() => void remove()} />
      {/if}
    {:else}
      <div class="placeholder muted">
        {section === "notes" ? "Choose a note, or add one with +." : "Choose a login, or add one with +."}
      </div>
    {/if}
  </main>
</div>

<style>
  .layout {
    height: 100%;
    display: grid;
    grid-template-columns: 200px 1fr;
  }

  .layout.listed {
    grid-template-columns: 200px 300px 1fr;
  }

  .sidebar {
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border);
    background: var(--surface);
    min-height: 0;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 16px;
    font-weight: 700;
  }

  .logo {
    width: 26px;
    height: 26px;
    border-radius: 7px;
    background: linear-gradient(135deg, #1e40af, #0e7490);
  }

  .sidebar ul {
    list-style: none;
    margin: 0;
    padding: 0 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    flex: 1;
  }

  .nav {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border: 0;
    border-radius: var(--radius);
    background: transparent;
    text-align: left;
    cursor: pointer;
  }

  .nav:hover {
    background: var(--surface-2);
  }

  .nav.active {
    background: var(--accent-soft);
    font-weight: 600;
  }

  .count {
    margin-left: auto;
    font-size: 12px;
    color: var(--text-3);
  }

  .dot {
    margin-left: auto;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--warn);
  }

  .foot {
    padding: 12px;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
  }

  .list {
    display: flex;
    flex-direction: column;
    border-right: 1px solid var(--border);
    min-height: 0;
  }

  .list-head {
    display: flex;
    gap: 8px;
    padding: 12px;
    border-bottom: 1px solid var(--border);
  }

  .items {
    list-style: none;
    margin: 0;
    padding: 6px;
    overflow: auto;
    flex: 1;
  }

  .item {
    width: 100%;
    display: flex;
    flex-direction: column;
    padding: 8px 10px;
    border: 0;
    border-radius: var(--radius);
    background: transparent;
    text-align: left;
    cursor: pointer;
  }

  .item:hover {
    background: var(--surface-2);
  }

  .item.active {
    background: var(--accent-soft);
  }

  .item-title,
  .item-sub {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .item-sub {
    font-size: 12px;
  }

  .empty {
    padding: 16px 10px;
    font-size: 13px;
  }

  .content {
    padding: 24px 28px;
    overflow: auto;
    min-height: 0;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .banner {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .link {
    border: 0;
    background: none;
    padding: 0;
    color: inherit;
    font-weight: 600;
    text-decoration: underline;
    cursor: pointer;
  }

  .placeholder {
    margin: auto;
  }

  .generator {
    display: flex;
    flex-direction: column;
    gap: 16px;
    max-width: 560px;
  }
</style>

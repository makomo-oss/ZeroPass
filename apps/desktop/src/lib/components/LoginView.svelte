<script lang="ts">
  import { errorMessage, items, type Details } from "../api";
  import ConfirmButton from "./ConfirmButton.svelte";
  import CopyButton from "./CopyButton.svelte";

  type Login = Extract<Details, { kind: "login" }>;
  let {
    login,
    onedit,
    ondelete,
  }: { login: Login; onedit: () => void; ondelete: () => void } = $props();

  let password: string | null = $state(null);
  let error = $state("");
  let hideTimer: ReturnType<typeof setTimeout> | undefined;

  // Another item: forget what was shown of the previous one.
  $effect(() => {
    void login.id;
    password = null;
    error = "";
    return () => clearTimeout(hideTimer);
  });

  async function toggle() {
    if (password !== null) {
      password = null;
      return;
    }
    try {
      password = await items.revealPassword(login.id);
      // Shown for a while only.
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => (password = null), 30_000);
    } catch (caught) {
      error = errorMessage(caught);
    }
  }
</script>

<article class="detail">
  <header>
    <div class="avatar" aria-hidden="true">{login.title.slice(0, 1).toUpperCase() || "?"}</div>
    <div class="titles">
      <h2>{login.title || "(no title)"}</h2>
      <p class="muted">Login</p>
    </div>
    <div class="tools">
      <button class="button small" onclick={onedit}>Edit</button>
      <ConfirmButton label="Delete" question="Delete it for good?" onconfirm={ondelete} />
    </div>
  </header>

  <dl>
    <dt>User name</dt>
    <dd>
      <span class="value">{login.username || "—"}</span>
      {#if login.username}
        <CopyButton id={login.id} field="username" onerror={(message) => (error = message)} />
      {/if}
    </dd>

    <dt>Password</dt>
    <dd>
      {#if login.has_password}
        <span class="value mono">{password ?? "••••••••••••"}</span>
        <button class="button small" onclick={() => void toggle()}>
          {password === null ? "Show" : "Hide"}
        </button>
        <CopyButton id={login.id} field="password" onerror={(message) => (error = message)} />
      {:else}
        <span class="value muted">No password</span>
      {/if}
    </dd>

    {#if login.urls.length > 0}
      <dt>Websites</dt>
      <dd class="urls">
        {#each login.urls as url (url)}
          <span class="value mono">{url}</span>
        {/each}
      </dd>
    {/if}

    {#if login.notes}
      <dt>Notes</dt>
      <dd><p class="value notes">{login.notes}</p></dd>
    {/if}
  </dl>

  {#if error}
    <p class="notice error">{error}</p>
  {/if}
</article>

<style>
  .detail {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  header {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .titles {
    flex: 1;
    min-width: 0;
  }

  .titles h2 {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .tools {
    display: flex;
    gap: 6px;
  }

  .avatar {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 700;
    font-size: 18px;
  }

  dl {
    margin: 0;
    display: grid;
    grid-template-columns: 110px 1fr;
    gap: 14px 16px;
    align-items: start;
  }

  dt {
    color: var(--text-3);
    font-size: 12px;
    font-weight: 600;
    padding-top: 6px;
  }

  dd {
    margin: 0;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
    min-width: 0;
  }

  .value {
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .urls {
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
  }

  .notes {
    white-space: pre-wrap;
  }
</style>

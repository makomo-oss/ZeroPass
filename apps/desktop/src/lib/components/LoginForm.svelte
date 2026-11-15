<script lang="ts">
  import { untrack } from "svelte";

  import { errorMessage, items, type Details, type LoginInput } from "../api";
  import Generator from "./Generator.svelte";

  type Login = Extract<Details, { kind: "login" }>;
  let {
    existing = null,
    onsaved,
    oncancel,
  }: {
    existing?: Login | null;
    onsaved: (id: string) => void;
    oncancel: () => void;
  } = $props();

  // The form starts from the item being edited, once.
  const initial = untrack(() => existing);
  let title = $state(initial?.title ?? "");
  let username = $state(initial?.username ?? "");
  let urls = $state(initial?.urls.join("\n") ?? "");
  let notes = $state(initial?.notes ?? "");
  /** Only set when the user types or generates a new password. */
  let password = $state("");
  let changePassword = $state(initial === null);
  let showPassword = $state(false);
  let showGenerator = $state(false);
  let busy = $state(false);
  let error = $state("");

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (busy || title.trim() === "") return;
    busy = true;
    error = "";
    const input: LoginInput = {
      title: title.trim(),
      username: username.trim(),
      password: changePassword ? password : null,
      urls: urls.split(/\r?\n/),
      notes,
    };
    try {
      if (initial) {
        await items.updateLogin(initial.id, input);
        onsaved(initial.id);
      } else {
        onsaved(await items.addLogin(input));
      }
      password = "";
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }
</script>

<form class="form" onsubmit={save}>
  <h2>{initial ? "Edit login" : "New login"}</h2>

  <label class="field">
    <span>Title</span>
    <input class="input" bind:value={title} placeholder="Example Bank" required />
  </label>
  <label class="field">
    <span>User name or e-mail</span>
    <input class="input" bind:value={username} autocomplete="off" spellcheck="false" />
  </label>

  <div class="field">
    <span>Password</span>
    {#if changePassword}
      <div class="row">
        <input
          class="input mono"
          type={showPassword ? "text" : "password"}
          bind:value={password}
          autocomplete="new-password"
          spellcheck="false"
        />
        <button class="button" type="button" onclick={() => (showPassword = !showPassword)}>
          {showPassword ? "Hide" : "Show"}
        </button>
        <button class="button" type="button" onclick={() => (showGenerator = !showGenerator)}>
          Generate…
        </button>
      </div>
      {#if showGenerator}
        <div class="card generator">
          <Generator
            compact
            onuse={(generated) => {
              password = generated;
              showGenerator = false;
            }}
          />
        </div>
      {/if}
    {:else}
      <div class="row">
        <span class="muted unchanged">Unchanged</span>
        <button class="button" type="button" onclick={() => (changePassword = true)}>
          Change password
        </button>
      </div>
    {/if}
  </div>

  <label class="field">
    <span>Websites (one per line)</span>
    <textarea class="input mono" bind:value={urls} rows="3" spellcheck="false"
      placeholder="https://example.com"></textarea>
  </label>
  <label class="field">
    <span>Notes</span>
    <textarea class="input" bind:value={notes} rows="4"></textarea>
  </label>

  {#if error}
    <p class="notice error" role="alert">{error}</p>
  {/if}

  <div class="actions">
    <button class="button primary" type="submit" disabled={busy || title.trim() === ""}>
      {busy ? "Saving…" : "Save"}
    </button>
    <button class="button ghost" type="button" onclick={oncancel} disabled={busy}>Cancel</button>
  </div>
</form>

<style>
  .form {
    display: flex;
    flex-direction: column;
    gap: 14px;
    max-width: 640px;
  }

  .row {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .unchanged {
    flex: 1;
  }

  .generator {
    margin-top: 8px;
    padding: 16px;
    box-shadow: none;
  }

  .actions {
    display: flex;
    gap: 8px;
  }
</style>

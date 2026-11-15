<script lang="ts">
  import { untrack } from "svelte";

  import { errorMessage, items, type Details } from "../api";

  type Note = Extract<Details, { kind: "note" }>;
  let {
    existing = null,
    onsaved,
    oncancel,
  }: {
    existing?: Note | null;
    onsaved: (id: string) => void;
    oncancel: () => void;
  } = $props();

  const initial = untrack(() => existing);
  let title = $state(initial?.title ?? "");
  let body = $state(initial?.body ?? "");
  let busy = $state(false);
  let error = $state("");

  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (busy || title.trim() === "") return;
    busy = true;
    error = "";
    try {
      const note = { title: title.trim(), body };
      if (initial) {
        await items.updateNote(initial.id, note);
        onsaved(initial.id);
      } else {
        onsaved(await items.addNote(note));
      }
    } catch (caught) {
      error = errorMessage(caught);
    } finally {
      busy = false;
    }
  }
</script>

<form class="form" onsubmit={save}>
  <h2>{initial ? "Edit secure note" : "New secure note"}</h2>
  <label class="field">
    <span>Title</span>
    <input class="input" bind:value={title} required />
  </label>
  <label class="field">
    <span>Text</span>
    <textarea class="input" bind:value={body} rows="12"></textarea>
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

  .actions {
    display: flex;
    gap: 8px;
  }
</style>

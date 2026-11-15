<script lang="ts">
  import type { Details } from "../api";
  import ConfirmButton from "./ConfirmButton.svelte";
  import CopyButton from "./CopyButton.svelte";

  type Note = Extract<Details, { kind: "note" }>;
  let {
    note,
    onedit,
    ondelete,
  }: { note: Note; onedit: () => void; ondelete: () => void } = $props();

  let error = $state("");
</script>

<article class="detail">
  <header>
    <div class="titles">
      <h2>{note.title || "(no title)"}</h2>
      <p class="muted">Secure note</p>
    </div>
    <div class="tools">
      <CopyButton id={note.id} field="note" label="Copy text" onerror={(message) => (error = message)} />
      <button class="button small" onclick={onedit}>Edit</button>
      <ConfirmButton label="Delete" question="Delete it for good?" onconfirm={ondelete} />
    </div>
  </header>
  <pre class="body">{note.body}</pre>
  {#if error}
    <p class="notice error">{error}</p>
  {/if}
</article>

<style>
  .detail {
    display: flex;
    flex-direction: column;
    gap: 16px;
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

  .tools {
    display: flex;
    gap: 6px;
  }

  .body {
    margin: 0;
    padding: 14px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-2);
    font-family: inherit;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
</style>

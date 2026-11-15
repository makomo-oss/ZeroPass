<script lang="ts">
  // A button that asks once more, in place, before it acts: for what cannot
  // be undone. (The webview's own confirm() dialog is not available on every
  // platform.)
  let {
    label,
    question,
    confirmLabel = label,
    onconfirm,
    small = true,
    danger = true,
    disabled = false,
  }: {
    label: string;
    question: string;
    confirmLabel?: string;
    onconfirm: () => void;
    small?: boolean;
    danger?: boolean;
    disabled?: boolean;
  } = $props();

  let asking = $state(false);
</script>

{#if asking}
  <span class="ask" role="alertdialog" aria-label={question}>
    <span class="question">{question}</span>
    <button
      class="button"
      class:small
      class:danger
      type="button"
      onclick={() => {
        asking = false;
        onconfirm();
      }}>{confirmLabel}</button
    >
    <button class="button ghost" class:small type="button" onclick={() => (asking = false)}>Cancel</button>
  </span>
{:else}
  <button class="button" class:small class:danger type="button" {disabled} onclick={() => (asking = true)}>
    {label}
  </button>
{/if}

<style>
  .ask {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .question {
    font-size: 13px;
    color: var(--danger);
  }
</style>

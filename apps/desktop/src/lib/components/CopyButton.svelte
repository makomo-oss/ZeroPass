<script lang="ts">
  import { errorMessage, items, type CopyField } from "../api";

  let {
    id,
    field,
    label = "Copy",
    onerror,
  }: { id: string; field: CopyField; label?: string; onerror?: (message: string) => void } =
    $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    try {
      await items.copy(id, field);
      copied = true;
      clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 2500);
    } catch (caught) {
      onerror?.(errorMessage(caught));
    }
  }
</script>

<button
  class="button small"
  type="button"
  onclick={() => void copy()}
  title="Copies to the clipboard, kept out of its history; cleared after 30 seconds"
>
  {copied ? "Copied" : label}
</button>

<script lang="ts">
  import type { Status } from "../api";

  let { status, onlock }: { status: Status; onlock: () => void } = $props();
</script>

<div class="layout">
  <header class="top">
    <h2>ZeroPass</h2>
    <button class="button" onclick={onlock}>Lock</button>
  </header>
  <main class="body">
    {#if !status.has_recovery_kit}
      <p class="notice warn">
        This vault has no recovery kit yet. Without it, a forgotten master
        password or a lost device means the vault is lost.
      </p>
    {/if}
    <p class="muted">The vault is unlocked.</p>
  </main>
</div>

<style>
  .layout {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }

  .body {
    flex: 1;
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    overflow: auto;
  }
</style>

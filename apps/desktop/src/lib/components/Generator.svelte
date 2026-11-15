<script lang="ts">
  import { errorMessage, items, type GeneratorOptions } from "../api";

  let {
    onuse,
    compact = false,
  }: { onuse?: (password: string) => void; compact?: boolean } = $props();

  let options: GeneratorOptions = $state({
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    avoid_ambiguous: false,
  });
  let password = $state("");
  let bits = $state(0);
  let error = $state("");
  let copied = $state(false);

  let strength = $derived(
    bits >= 128 ? "Very strong" : bits >= 80 ? "Strong" : bits >= 60 ? "Fair" : "Weak",
  );

  async function regenerate() {
    error = "";
    copied = false;
    try {
      const generated = await items.generate({ ...options });
      password = generated.password;
      bits = generated.bits;
    } catch (caught) {
      password = "";
      bits = 0;
      error = errorMessage(caught);
    }
  }

  async function copy() {
    try {
      await items.copyText(password);
      copied = true;
    } catch (caught) {
      error = errorMessage(caught);
    }
  }

  // A new password whenever the options change.
  $effect(() => {
    void [
      options.length,
      options.lowercase,
      options.uppercase,
      options.digits,
      options.symbols,
      options.avoid_ambiguous,
    ];
    void regenerate();
  });
</script>

<div class="generator" class:compact>
  <div class="output">
    <output class="mono password" aria-live="polite">{password}</output>
    <button class="button small" type="button" onclick={() => void regenerate()} title="Generate another">
      New
    </button>
  </div>
  <div class="meter" data-strength={strength}>
    <span class="bar"><span class="fill" style:width={`${Math.min(100, (bits / 128) * 100)}%`}></span></span>
    <span class="muted">{strength} · about {Math.round(bits)} bits</span>
  </div>

  <label class="length">
    <span>Length <strong>{options.length}</strong></span>
    <input type="range" min="8" max="64" bind:value={options.length} />
  </label>
  <div class="classes">
    <label><input type="checkbox" bind:checked={options.lowercase} /> a–z</label>
    <label><input type="checkbox" bind:checked={options.uppercase} /> A–Z</label>
    <label><input type="checkbox" bind:checked={options.digits} /> 0–9</label>
    <label><input type="checkbox" bind:checked={options.symbols} /> !#$%</label>
    <label><input type="checkbox" bind:checked={options.avoid_ambiguous} /> No look-alikes (l, 1, O, 0…)</label>
  </div>

  {#if error}
    <p class="notice error">{error}</p>
  {/if}

  <div class="actions">
    {#if onuse}
      <button class="button primary" type="button" disabled={!password} onclick={() => onuse?.(password)}>
        Use this password
      </button>
    {:else}
      <button class="button primary" type="button" disabled={!password} onclick={() => void copy()}>
        {copied ? "Copied — cleared in 30 s" : "Copy"}
      </button>
    {/if}
  </div>
</div>

<style>
  .generator {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .output {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .password {
    flex: 1;
    min-height: 44px;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface-2);
    font-size: 16px;
    word-break: break-all;
  }

  .compact .password {
    font-size: 14px;
    min-height: 36px;
    padding: 6px 10px;
  }

  .meter {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
  }

  .bar {
    flex: 0 0 120px;
    height: 6px;
    border-radius: 3px;
    background: var(--surface-2);
    overflow: hidden;
  }

  .fill {
    display: block;
    height: 100%;
    background: var(--danger);
  }

  .meter[data-strength="Fair"] .fill {
    background: var(--warn);
  }

  .meter[data-strength="Strong"] .fill,
  .meter[data-strength="Very strong"] .fill {
    background: var(--ok);
  }

  .length {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 13px;
  }

  .classes {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 16px;
    font-size: 13px;
  }

  .classes label {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .actions {
    display: flex;
    gap: 8px;
  }
</style>

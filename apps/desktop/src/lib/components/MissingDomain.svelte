<script lang="ts">
  // For a domain this PC does not have (ADR-0011): explains why, and makes it
  // here when no other device seems to have it.
  import { api, errorMessage, isCommandError, type DomainState } from "../api";

  let {
    domain,
    what,
    onchanged,
  }: {
    /** The state of the one-time code or passkey domain. */
    domain: DomainState;
    /** What the domain keeps, in the plural: "one-time codes", "passkeys". */
    what: string;
    /** The state of the vault may have changed. */
    onchanged: () => void;
  } = $props();

  let busy = $state(false);
  let error = $state("");
  /** The daemon found that other devices have the domain after all. */
  let foundElsewhere = $state(false);

  let elsewhere = $derived(domain.elsewhere || foundElsewhere);

  async function setUp() {
    busy = true;
    error = "";
    try {
      await api.setUpDomain(domain.name);
      onchanged();
    } catch (caught) {
      if (isCommandError(caught) && caught.code === "DomainElsewhere") {
        foundElsewhere = true;
      } else if (isCommandError(caught) && caught.code === "HardwareUnavailable") {
        error =
          "Windows Hello is not set up on this PC yet. Set up a PIN in Settings > Accounts > Sign-in options, then try again.";
      } else if (isCommandError(caught) && caught.code === "UserCancelled") {
        error = "Windows Hello was cancelled.";
      } else {
        error = errorMessage(caught);
      }
    } finally {
      busy = false;
    }
  }
</script>

<div class="missing card">
  {#if elsewhere}
    <p>
      This PC does not have the keys of your {what} yet: it joined the vault
      without Windows Hello. Your other devices have them.
    </p>
    <p class="muted">
      Set up Windows Hello on this PC (a PIN in Settings &gt; Accounts &gt;
      Sign-in options), then get the keys from a device that has them.
    </p>
  {:else}
    <p>
      This vault has no {what} yet: it was created without Windows Hello, which
      protects them apart from your master password.
    </p>
    <p class="muted">
      Set up Windows Hello on this PC (a PIN in Settings &gt; Accounts &gt;
      Sign-in options), then set up {what} here. Your other devices get them
      from this PC.
    </p>
    <div>
      <button class="button primary" onclick={() => void setUp()} disabled={busy}>
        {busy ? "Waiting for Windows Hello…" : `Set up ${what} on this PC`}
      </button>
    </div>
  {/if}
  {#if error}
    <p class="notice error" role="alert">{error}</p>
  {/if}
</div>

<style>
  .missing {
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    box-shadow: none;
  }

  .missing p {
    margin: 0;
  }
</style>

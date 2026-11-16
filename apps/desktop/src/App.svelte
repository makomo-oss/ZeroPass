<script lang="ts">
  import { onMount } from "svelte";

  import { watchActivity } from "./lib/activity";
  import { api, domainState, errorMessage, type AppInfo, type Status } from "./lib/api";
  import Splash from "./lib/screens/Splash.svelte";
  import Unlock from "./lib/screens/Unlock.svelte";
  import Vault from "./lib/screens/Vault.svelte";
  import Welcome from "./lib/screens/Welcome.svelte";

  /** How often the state of the vault is asked for: it locks itself. */
  const POLL_MS = 5000;

  let status: Status | null = $state(null);
  let info: AppInfo | null = $state(null);
  let failure = $state("");
  let reportedReady = false;
  let polling = false;

  type Screen = "loading" | "failure" | "welcome" | "unlock" | "vault";
  let screen: Screen = $derived.by(() => {
    if (failure) return "failure";
    if (status === null) return "loading";
    if (!status.exists) return "welcome";
    return domainState(status, "password")?.unlocked ? "vault" : "unlock";
  });

  async function refresh() {
    if (polling) return;
    polling = true;
    try {
      status = await api.status();
      failure = "";
    } catch (caught) {
      failure = errorMessage(caught);
    } finally {
      polling = false;
    }
  }

  async function lockAll() {
    try {
      await api.lock();
    } finally {
      await refresh();
    }
  }

  onMount(() => {
    api
      .appInfo()
      .then((found) => (info = found))
      .catch(() => {});
    void refresh();
    // The state of the vault is asked for without using its keys (Status),
    // so this polling never holds off the auto-lock; what reads items does
    // so only while the user is active (lib/activity.ts).
    const stopWatching = watchActivity();
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, POLL_MS);
    const onFocus = () => void refresh();
    window.addEventListener("focus", onFocus);
    return () => {
      clearInterval(timer);
      window.removeEventListener("focus", onFocus);
      stopWatching();
    };
  });

  // The first real screen is drawn: report it once (start-up time).
  $effect(() => {
    if (screen !== "loading" && !reportedReady) {
      reportedReady = true;
      requestAnimationFrame(() => {
        void api.uiReady();
      });
    }
  });
</script>

{#if screen === "loading"}
  <Splash />
{:else if screen === "failure"}
  <main class="failure">
    <div class="card panel">
      <h2>ZeroPass cannot reach its vault</h2>
      <p class="notice error">{failure}</p>
      <button class="button primary" onclick={() => void refresh()}>Try again</button>
    </div>
  </main>
{:else if screen === "welcome"}
  <Welcome
    vaultPath={info?.vault_path ?? ""}
    oncreated={(created) => (status = created)}
    onjoined={() => void refresh()}
  />
{:else if screen === "unlock"}
  <Unlock onunlocked={() => void refresh()} />
{:else if screen === "vault" && status}
  <Vault {status} {info} onlock={() => void lockAll()} onchanged={() => void refresh()} />
{/if}

<style>
  .failure {
    height: 100%;
    display: grid;
    place-items: center;
    padding: 24px;
  }

  .panel {
    width: min(460px, 100%);
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
</style>

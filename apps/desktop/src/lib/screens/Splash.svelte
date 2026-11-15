<script lang="ts">
  let { message = "" }: { message?: string } = $props();
</script>

<div class="splash">
  <div class="logo" aria-hidden="true"></div>
  <p class="muted">{message}</p>
</div>

<style>
  .splash {
    height: 100%;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
  }

  .logo {
    width: 56px;
    height: 56px;
    border-radius: 14px;
    background: linear-gradient(135deg, #1e40af, #0e7490);
  }
</style>

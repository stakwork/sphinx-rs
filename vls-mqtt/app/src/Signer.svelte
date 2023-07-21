<script>
  import * as signer from "./signer";
  import { onMount, onDestroy } from "svelte";

  onMount(() => {
    signer.initialize();
  });

  onDestroy(() => {
    signer.say_bye();
  });
</script>

<main>Ready to sign...</main>

<style>
  main {
    padding: 2rem;
    display: flex;
    flex-direction: column;
  }
</style>

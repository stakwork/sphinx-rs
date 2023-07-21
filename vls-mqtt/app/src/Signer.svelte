<script>
  import * as signer from "./signer";
  import { onMount } from "svelte";

  onMount(() => {
    signer.initialize();
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

<script>
  import * as signer from "./signer";
  import { onDestroy } from "svelte";
  import { Button } from "carbon-components-svelte";
  import PlayFilled from "carbon-icons-svelte/lib/PlayFilled.svelte";

  let started = false;
  function start() {
    started = true;
    signer.initialize();
  }

  onDestroy(() => {
    signer.say_bye();
  });
</script>

<main>
  <Button icon={PlayFilled} disabled={started} on:click={start}>Start</Button>
</main>

<style>
  main {
    padding: 2rem;
    display: flex;
    flex-direction: column;
  }
</style>

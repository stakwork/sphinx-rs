<script>
  import * as signer from "./signer";
  import { onDestroy } from "svelte";
  import { keys, pubkey } from "./store";
  import { Button } from "carbon-components-svelte";
  import PlayFilled from "carbon-icons-svelte/lib/PlayFilled.svelte";
  import SubtractAlt from "carbon-icons-svelte/lib/SubtractAlt.svelte";

  let started = false;
  function start() {
    started = true;
    signer.initialize($keys);
  }

  function clear() {
    console.log("CLEAR!");
    signer.clear();
  }

  onDestroy(() => {
    signer.say_bye();
  });

  const cantPlay = started || !$pubkey;
</script>

<main>
  <div class="buttons">
    <Button icon={PlayFilled} disabled={cantPlay} on:click={start}>
      Start
    </Button>
    <div class="gap" />
    <Button
      kind="tertiary"
      icon={SubtractAlt}
      on:click={clear}
      iconDescription="Clear State"
    />
  </div>
</main>

<style>
  main {
    padding: 2rem;
    display: flex;
    flex-direction: column;
  }
  .buttons {
    display: flex;
  }
  .gap {
    width: 1rem;
  }
</style>

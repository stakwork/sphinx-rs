<script>
  import * as signer from "./signer";
  import { onDestroy } from "svelte";
  import { keys, pubkey, cmds } from "./store";
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
  <div class="cmd-wrap">
    {#each $cmds as cmd}
      <div class="cmd">{`=> ${cmd}`}</div>
    {/each}
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
  .cmd-wrap {
    margin-top: 2rem;
    display: flex;
    flex-direction: column-reverse;
    max-height: calc(100vh - 205px);
    overflow: auto;
  }
  .cmd {
    margin: 0.2rem 0;
  }
</style>

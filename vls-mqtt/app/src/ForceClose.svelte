<script lang="ts">
  import {
    DataTable,
    Button,
    TextInput,
    Loading,
  } from "carbon-components-svelte";
  import Exit from "carbon-icons-svelte/lib/Exit.svelte";

  let addy = "";

  async function forceClose() {
    console.log("FORCE CLOSE");
  }
</script>

<main>
  <TextInput placeholder="Recovery Address" bind:value={addy} />
  <br /><br />
  <Button icon={Exit} disabled={!addy} on:click={forceClose}
    >Force Close Channels</Button
  >
</main>

<style>
  main {
    padding: 2rem;
  }
</style>

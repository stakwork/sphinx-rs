<script lang="ts">
  import {
    DataTable,
    Button,
    TextInput,
    Loading,
  } from "carbon-components-svelte";
  import Add from "carbon-icons-svelte/lib/Add.svelte";
  import Save from "carbon-icons-svelte/lib/Save.svelte";
  import { allowlist } from "./store";
  import { onMount } from "svelte";
  import * as api from "./api";

  let list = $allowlist.slice();

  async function initPolicy() {
    const p = await api.getAllowlist();
    console.log(p);
    list = p;
  }
  onMount(() => {
    initPolicy();
  });

  let adding;
  let newAddress = "";
  let txtInput;
  let loading;

  function triggerAdding() {
    adding = true;
    setTimeout(() => {
      if (txtInput) txtInput.focus();
    }, 2);
  }
  function enter(e) {
    if (e.key === "Enter") {
      add();
    }
  }
  function add() {
    list = [...list, newAddress];
    adding = false;
    newAddress = "";
  }
  async function save() {
    // allowlist.set(list);
    loading = true;
    // setTimeout(() => (loading = false), 1000);
    const p = await api.setAllowlist(list);
    loading = false;
    console.log(p);
  }

  function equals(a, b) {
    return a.length === b.length && a.every((v, i) => v === b[i]);
  }
  $: dirty = !equals(list, $allowlist);
</script>

<main>
  <DataTable
    headers={[{ key: "address", value: "Withdrawal Addresses" }]}
    rows={list.map((address, id) => ({
      address,
      id,
    }))}
  />
  <br /><br />
  {#if adding}
    <TextInput
      placeholder="New Address"
      bind:value={newAddress}
      on:keydown={enter}
      bind:ref={txtInput}
    />

    <!-- <Button icon={Save} disabled={!dirty}>Save</Button> -->
    <br />
  {/if}
  <div class="btns">
    <Button icon={Add} disabled={adding} on:click={triggerAdding}>Add</Button>
    <Button icon={Save} disabled={!dirty} on:click={save}>Save</Button>
    <div style="width:1rem">
      {#if loading}
        <Loading withOverlay={false} small />
      {/if}
    </div>
  </div>
</main>

<style>
  main {
    padding: 2rem;
  }
  .btns {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 16.3rem;
  }
</style>

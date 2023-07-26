<script lang="ts">
  import * as sphinx from "../../../sphinx-wasm/pkg";
  import { onMount } from "svelte";
  import Sidebar from "./Sidebar.svelte";
  import { pages, menu, pubkey, formatPubkey, loaded } from "./store";
  import Account from "./Account.svelte";
  import Allowlist from "./Allowlist.svelte";
  import Policy from "./Policy.svelte";
  import ForceClose from "./ForceClose.svelte";
  import Signer from "./Signer.svelte";

  async function loadWasm() {
    try {
      await sphinx.default("/sphinx_wasm_bg.wasm");
      loaded.set(true);
    } catch (e) {
      console.log(e);
    }
  }

  onMount(loadWasm);

  $: page = pages.find((p) => p.page === $menu);
  const components = {
    signer: Signer,
    account: Account,
    policy: Policy,
    allowlist: Allowlist,
    forceclose: ForceClose,
  };

  $: component = components[page.page];

  let scale = 1;
  function copyPubkey() {
    scale = 1.2;
    navigator.clipboard.writeText($pubkey);
    setTimeout(() => {
      scale = 1;
    }, 140);
  }
</script>

<main>
  <header>
    <div class="lefty logo-wrap">
      <img src="/logo.svg" alt="logo" />
    </div>
    <div class="page-right">
      <div class="page-title">
        {page.label}
      </div>
      {#if $pubkey}
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <div
          class="pubkey"
          on:click={copyPubkey}
          style={`transform:scale(${scale},${scale})`}
        >
          {formatPubkey($pubkey)}
        </div>
      {/if}
    </div>
  </header>
  <div class="body">
    <div class="lefty"><Sidebar /></div>
    {#if $loaded}
      <svelte:component this={component} />
    {/if}
  </div>
</main>

<style>
  main {
    height: 100vh;
    width: 100vw;
    display: flex;
    background: #161616;
    flex-direction: column;
  }
  header {
    height: 4.2rem;
    display: flex;
    align-items: center;
    border-bottom: 1px dashed #bfbfbf;
  }
  .logo-wrap {
    display: flex;
    align-items: center;
  }
  header img {
    height: 3rem;
    margin: 0 1rem;
  }
  .body {
    display: flex;
    height: 100%;
  }
  .lefty {
    width: 15rem;
    max-width: 15rem;
    height: 100%;
    border-right: 1px dashed #bfbfbf;
  }
  .page-right {
    display: flex;
    justify-content: space-between;
    width: 100%;
  }
  .page-title {
    font-size: 1.2rem;
    padding-left: 2rem;
  }
  .pubkey {
    margin-right: 2rem;
    display: flex;
    align-items: center;
    font-weight: bold;
    font-size: 0.7rem;
    color: #aaa;
    cursor: pointer;
  }
  .pubkey:hover {
    color: white;
  }
</style>

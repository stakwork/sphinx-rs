<script lang="ts">
  import * as sphinx from "../../../sphinx-wasm/pkg";
  import { onMount } from "svelte";
  import Sidebar from "./Sidebar.svelte";
  import { pages, menu } from "./store";
  import Account from "./Account.svelte";
  import Allowlist from "./Allowlist.svelte";
  import Policy from "./Policy.svelte";

  let loaded = false;

  async function loadWasm() {
    try {
      await sphinx.default("/sphinx_wasm_bg.wasm");
      loaded = true;
    } catch (e) {
      console.log(e);
    }
  }

  onMount(loadWasm);

  $: page = pages.find((p) => p.page === $menu);
  const components = {
    account: Account,
    policy: Policy,
    allowlist: Allowlist,
  };
  $: component = components[page.page];
</script>

<main>
  <header>
    <div class="lefty logo-wrap">
      <img src="/logo.svg" alt="logo" />
    </div>
    <div class="page-title">
      {page.label}
    </div>
  </header>
  <div class="body">
    <div class="lefty"><Sidebar /></div>
    {#if loaded}
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
  .page-title {
    font-size: 1.2rem;
    padding-left: 2rem;
  }
</style>

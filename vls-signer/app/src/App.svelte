<script lang="ts">
  import * as sphinx from "../../../sphinx-wasm/pkg";
  import { onMount } from "svelte";
  import Sidebar from "./Sidebar.svelte";
  import { pages, menu } from "./store";
  import Account from "./Account.svelte";
  import Allowlist from "./Allowlist.svelte";
  import Policy from "./Policy.svelte";

  function test() {
    // let sk = "86c8977989592a97beb409bc27fde76e981ce3543499fd61743755b832e92a3e";
    // let pk = sphinx.pubkey_from_secret_key(sk);
    // console.log(pk);

    // let msg = { type: "Nonce" };
    // let req = sphinx.build_control_request(JSON.stringify(msg), sk, BigInt(0));
    // console.log(req);

    let mnemonic =
      "man dwarf taxi bargain naive envelope width license rotate divide keep tag limb immune express nasty word arm assist problem lobster innocent pottery sweet";

    let seed = sphinx.entropy_from_mnemonic(mnemonic);
    console.log("seed", seed);

    // let asdf = sphinx.mnemonic_from_entropy(seed);
    // console.log(asdf);

    let hi = sphinx.node_keys("regtest", seed);
    console.log("secret", hi.secret);
  }
  async function loadWasm() {
    try {
      await sphinx.default("/sphinx_wasm_bg.wasm");
      test();
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
    <svelte:component this={component} />
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
    height: 4rem;
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

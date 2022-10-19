<script lang="ts">
  import * as sphinx from "../../pkg";
  import { onMount } from "svelte";

  async function loadWasm() {
    await sphinx.default("/sphinx_wasm_bg.wasm");
    let sk = "86c8977989592a97beb409bc27fde76e981ce3543499fd61743755b832e92a3e";
    let pk = sphinx.pubkey_from_secret_key(sk);
    console.log(pk);

    let msg = { type: "Nonce" };
    let req = sphinx.build_control_request(JSON.stringify(msg), sk, BigInt(0));
    console.log(req);
  }
  onMount(loadWasm);
</script>

<main />

<style>
  main {
    height: 100vh;
    width: 100vw;
    display: flex;
    background: black;
  }
</style>

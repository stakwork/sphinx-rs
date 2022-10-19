<script lang="ts">
  import * as sphinx from "../../../sphinx-wasm/pkg";
  import { onMount } from "svelte";

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
</script>

<header>
  <img src="/logo.svg" alt="logo" />
</header>
<main />

<style>
  main {
    height: 100vh;
    width: 100vw;
    display: flex;
    background: black;
  }
  header {
    height: 3rem;
  }
  header img {
    height: 1rem;
  }
</style>

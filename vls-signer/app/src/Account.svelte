<script lang="ts">
  import { Toggle, SkeletonText } from "carbon-components-svelte";
  import { seed } from "./store";
  import { sphinx } from "./wasm";
  import { getNonce } from "./api";

  getNonce();

  function split(s: string) {
    let a = s.split(" ");
    if (a.length !== 24) {
      throw "Wrong mnemonic length";
    }
    return [
      `${a[0]} ${a[1]} ${a[2]} ${a[3]} ${a[4]} ${a[5]}`,
      `${a[6]} ${a[7]} ${a[8]} ${a[9]} ${a[10]} ${a[11]}`,
      `${a[12]} ${a[13]} ${a[14]} ${a[15]} ${a[16]} ${a[17]}`,
      `${a[18]} ${a[19]} ${a[20]} ${a[21]} ${a[22]} ${a[23]}`,
    ];
  }

  let lines;
  let show = false;
  let timeout;
  $: {
    if (show) {
      timeout = setTimeout(() => {
        const words = sphinx.mnemonic_from_entropy($seed);
        lines = split(words);
      }, 850);
    } else {
      lines = null;
      if (timeout) clearTimeout(timeout);
    }
  }
</script>

<main>
  <div class="wrap">
    <div class="upper">
      <div class="label">Mnemonic</div>
      <div class="toggle">
        <Toggle
          size="sm"
          labelText="View Mnemonic"
          bind:toggled={show}
          hideLabel={true}
          labelA="View"
          labelB="Hide"
        />
      </div>
    </div>
    <div class="mnemonic">
      {#if show}
        {#if lines}
          {#each lines as line}
            <div>{line}</div>
          {/each}
        {:else}
          <SkeletonText paragraph width="50%" lines={4} />
        {/if}
      {/if}
    </div>
  </div>
</main>

<style>
  main {
    padding: 2rem;
    display: flex;
    flex-direction: column;
  }
  .wrap {
    width: 30rem;
    max-width: 100%;
  }
  .mnemonic {
    height: 9.5rem;
    background: #262626;
    color: #a2a2a2;
    border-radius: 1rem;
    padding: 2rem;
    width: 100%;
    font-size: 1.08rem;
    line-height: 1.33rem;
  }
  .upper {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.3rem;
    width: 100%;
  }
  .label {
    font-weight: bold;
    font-size: 1rem;
    display: inline-block;
    margin-right: 0.8rem;
    color: #a7a7a7;
  }
  .toggle {
    width: 4.7rem;
  }
</style>

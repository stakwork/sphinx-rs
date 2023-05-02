<script lang="ts">
  import { Button } from "carbon-components-svelte";
  import { menu, pages, Page } from "./store";
  import VirtualColumnKey from "carbon-icons-svelte/lib/VirtualColumnKey.svelte";
  import Policy from "carbon-icons-svelte/lib/Policy.svelte";
  import ListChecked from "carbon-icons-svelte/lib/ListChecked.svelte";
  import Exit from "carbon-icons-svelte/lib/Exit.svelte";

  function navigate(page: string) {
    menu.set(page as Page);
  }
  const icons = {
    account: VirtualColumnKey,
    policy: Policy,
    allowlist: ListChecked,
    forceclose: Exit,
  };
</script>

<div class="topper" />
{#each pages as page}
  <div
    class="btn-wrap"
    on:click={() => navigate(page.page)}
    on:keypress={() => {}}
  >
    <Button
      isSelected={$menu === page.page}
      kind="ghost"
      iconDescription={page.label}
      tooltipAlignment="center"
      tooltipPosition="right"
      icon={icons[page.page]}
      on:click={() => navigate(page.page)}
    />
    <span>{page.label}</span>
  </div>
{/each}

<style>
  .topper {
    height: 1rem;
  }
  .btn-wrap {
    height: 3rem;
    display: flex;
    align-items: center;
    margin: 1rem;
  }
  .btn-wrap span {
    margin-left: 1rem;
  }
  .btn-wrap:hover {
    background: #353535;
    cursor: pointer;
  }
</style>

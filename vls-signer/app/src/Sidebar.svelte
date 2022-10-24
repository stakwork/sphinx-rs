<script lang="ts">
  import { Button } from "carbon-components-svelte";
  import { menu, pages } from "./store";
  import VirtualColumnKey from "carbon-icons-svelte/lib/VirtualColumnKey.svelte";
  import Policy from "carbon-icons-svelte/lib/Policy.svelte";
  import ListChecked from "carbon-icons-svelte/lib/ListChecked.svelte";

  function navigate(page: string) {
    menu.set(page);
  }
  const icons = {
    account: VirtualColumnKey,
    policy: Policy,
    allowlist: ListChecked,
  };
</script>

<div class="topper" />
{#each pages as page}
  <div class="btn-wrap">
    <Button
      isSelected={$menu === page.page}
      kind="ghost"
      iconDescription={page.label}
      tooltipAlignment="center"
      tooltipPosition="right"
      icon={icons[page.page]}
      on:click={() => navigate(page.page)}
    />
    <span on:click={() => navigate(page.page)}>{page.label}</span>
  </div>
{/each}

<style>
  .topper {
    height: 1rem;
  }
  .btn-wrap {
    height: 4rem;
    display: flex;
    align-items: center;
    margin-left: 0.9rem;
  }
  .btn-wrap span {
    margin-left: 1rem;
    cursor: pointer;
  }
</style>

<script lang="ts">
  import {
    NumberInput,
    Form,
    Dropdown,
    FormGroup,
    Button,
  } from "carbon-components-svelte";
  import Save from "carbon-icons-svelte/lib/Save.svelte";
  import { onMount } from "svelte";
  import * as api from "./api";
  import { policy } from "./store";

  let msat_per_interval = $policy.msat_per_interval;
  let interval = $policy.interval;
  let htlc_limit_msat = $policy.htlc_limit_msat;

  async function initPolicy() {
    const p = await api.getPolicy();
    console.log(p);
    msat_per_interval = p.msat_per_interval;
    interval = p.interval;
    htlc_limit_msat = p.htlc_limit_msat;
  }
  onMount(() => {
    initPolicy();
  });

  // dirty = ready to be saved
  $: dirty =
    htlc_limit_msat !== $policy.htlc_limit_msat ||
    interval !== $policy.interval ||
    msat_per_interval !== $policy.msat_per_interval;

  async function submit(e) {
    e.preventDefault();
    await api.setPolicy({
      msat_per_interval,
      htlc_limit_msat,
      interval,
    });
  }
</script>

<main>
  <Form on:submit={submit}
    ><FormGroup>
      <NumberInput
        label="Satoshi Limit Per Interval"
        bind:value={msat_per_interval}
      />
      <br />
      <Dropdown
        titleText="Interval"
        bind:selectedId={interval}
        items={[
          { id: "daily", text: "Day" },
          { id: "hourly", text: "Hour" },
        ]}
      />
    </FormGroup>
    <br />
    <NumberInput label="HTLC Limit" bind:value={htlc_limit_msat} />
    <br /><br /><br />
    <Button type="submit" icon={Save} disabled={!dirty}>Save</Button>
  </Form>
</main>

<style>
  main {
    padding: 2rem;
    display: flex;
    flex-direction: column;
  }
</style>

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

  let sat_limit = $policy.sat_limit;
  let interval = $policy.interval;
  let htlc_limit = $policy.htlc_limit;

  async function initPolicy() {
    const p = await api.getPolicy();
    sat_limit = p.sat_limit;
    interval = p.interval;
    htlc_limit = p.htlc_limit;
  }
  onMount(() => {
    initPolicy();
  });

  // dirty = ready to be saved
  $: dirty =
    htlc_limit !== $policy.htlc_limit ||
    interval !== $policy.interval ||
    sat_limit !== $policy.sat_limit;

  async function submit(e) {
    e.preventDefault();
    await api.setPolicy({
      sat_limit,
      htlc_limit,
      interval,
    });
  }
</script>

<main>
  <Form on:submit={submit}
    ><FormGroup>
      <NumberInput label="Satoshi Limit Per Interval" bind:value={sat_limit} />
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
    <NumberInput label="HTLC Limit" bind:value={htlc_limit} />
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

<script lang="ts">
  import {
    NumberInput,
    Form,
    Dropdown,
    FormGroup,
    Button,
  } from "carbon-components-svelte";
  import Save from "carbon-icons-svelte/lib/Save.svelte";

  import { policy } from "./store";

  let sat_limit = $policy.sat_limit;
  let interval = $policy.interval;
  let htlc_limit = $policy.htlc_limit;
  // dirty = ready to be saved
  $: dirty =
    htlc_limit !== $policy.htlc_limit ||
    interval !== $policy.interval ||
    sat_limit !== $policy.sat_limit;
</script>

<main>
  <Form
    on:submit={(e) => {
      e.preventDefault();
      policy.set({
        sat_limit,
        htlc_limit,
        interval,
      });
    }}
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

import * as localforage from "localforage";
import * as msgpack from "@msgpack/msgpack";
import { type Policy, seed, lss_nonce, policy, allowlist } from "./store";
import { get } from "svelte/store";

// store state mutations in IndexedDB
const forage = localforage.createInstance({
  name: "vls",
});

export type State = { [k: string]: Bytes };

export type Bytes = Uint8Array;

export interface Args {
  seed: Uint8Array;
  network: string;
  policy: Policy;
  allowlist: string[];
  timestamp: number; // unix ts in seconds
  lss_nonce: Uint8Array;
}

interface ArgsAndState {
  args: string;
  state: Uint8Array;
}
export async function argsAndState(): Promise<ArgsAndState> {
  const args = stringifyArgs(makeArgs());
  const sta: State = await load_muts();
  const state = msgpack.encode(sta);
  return { args, state };
}

export async function storeMutations(inc: Uint8Array): Promise<number[]> {
  try {
    const muts: State = msgpack.decode(inc) as State;
    await persist_muts(muts);
    if (muts["VELOCITY"]) {
      return parseVelocity(muts["VELOCITY"]);
    }
  } catch (e) {
    console.error(e);
  }
}

function parseVelocity(veldata: Uint8Array | undefined): number[] {
  if (!veldata) return;
  try {
    const vel = msgpack.decode(veldata);
    if (Array.isArray(vel)) {
      if (vel.length > 1) {
        const pmts = vel[1];
        if (Array.isArray(pmts)) {
          return pmts;
        }
      }
    }
  } catch (e) {
    console.error("invalid velocity");
  }
}

function makeArgs(): Args {
  return {
    seed: fromHexString(get(seed)),
    network: "regtest",
    policy: get(policy),
    allowlist: get(allowlist),
    timestamp: now(),
    lss_nonce: fromHexString(get(lss_nonce)),
  };
}

function stringifyArgs(a: Args): string {
  return JSON.stringify(a, (k, v) => {
    if (v instanceof Uint8Array) {
      return Array.from(v);
    } else {
      return v;
    }
  });
}

export function now() {
  return Math.round(new Date().getTime() / 1000);
}

function fromHexString(hexString: string): Uint8Array {
  return Uint8Array.from(
    hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
  );
}

export async function clearAll() {
  await forage.clear();
}

async function persist_muts(muts: State) {
  for (let k in muts) {
    const val = muts[k];
    await forage.setItem<Uint8Array>(k, val);
  }
}

async function load_muts(): Promise<State> {
  const keys = await forage.keys();
  const ret: State = {};
  for (let k of keys) {
    const item = await forage.getItem<Uint8Array>(k);
    ret[k] = item;
  }
  return ret;
}

import * as localforage from "localforage";
import { Buffer } from "buffer/";
import * as msgpack from "@msgpack/msgpack";
import { type Policy, seed, lss_nonce, policy, allowlist } from "./store";
import { get } from "svelte/store";

const forage = localforage.createInstance({
  name: "vls",
});

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

export async function storeMutations(inc: Uint8Array) {
  try {
    const ms: LssResponse = msgpack.decode(inc) as LssResponse;
    if (!ms.VlsMuts) return;
    if (!ms.VlsMuts.muts) return;
    const muts = ms.VlsMuts.muts;
    await persist_muts(muts);
  } catch (e) {
    console.error(e);
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

export type State = { [k: string]: VersionBytes };

export interface LssResponse {
  VlsMuts: VlsMuts;
}

export interface VlsMuts {
  client_hmac: Bytes;
  muts: Mutations;
}

export type Mutations = VlsBytes[];

export type VlsBytes = (string | VersionBytes)[];

export type VersionBytes = (number | Bytes)[];

export type Bytes = Uint8Array;

export type Velocity = (number | Bytes)[];

// ["name", [1, [bytes]]]
export interface Args {
  seed: Uint8Array;
  network: string;
  policy: Policy;
  velocity?: Velocity;
  allowlist: string[];
  timestamp: number; // unix ts in seconds
  lss_nonce: Uint8Array;
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

async function persist_muts(muts: Mutations) {
  interface Ret {
    key: string;
    value: string;
  }
  let ret: Ret[] = [];
  for (let m of muts) {
    let name = m[0];
    let val = m[1];
    let ver = val[0];
    const ver_bytes = getInt64Bytes(BigInt(ver as number));
    let mut = Buffer.from(val[1] as Uint8Array);
    const bytes = Buffer.concat([ver_bytes, mut]);
    ret.push({ key: name as string, value: bytes.toString("base64") });
  }
  for (let r of ret) {
    await forage.setItem(r.key, r.value);
  }
}

async function load_muts(): Promise<State> {
  const keys = await forage.keys();
  const ret: State = {};
  for (let k of keys) {
    const item = await forage.getItem(k);
    const b = Buffer.from(item as string, "base64");
    const ver_bytes = b.slice(0, 8);
    const ver = intFromBytes(ver_bytes);
    const bytes = b.slice(8);
    ret[k] = [Number(ver), bytes];
  }
  return ret;
}

function getInt64Bytes(x) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64LE(x, 0);
  return bytes;
}

function intFromBytes(x) {
  return x.readBigInt64LE();
}

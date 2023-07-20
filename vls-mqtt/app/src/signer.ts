import { type Policy, keys } from "./store";
import { get } from "svelte/store";
import { sphinx } from "./wasm";
import mqtt from "mqtt";

export enum topics {
  VLS = "vls",
  VLS_RES = "vls-res",
  CONTROL = "control",
  CONTROL_RES = "control-res",
  PROXY = "proxy",
  PROXY_RES = "proxy-res",
  ERROR = "error",
  INIT_1_MSG = "init-1-msg",
  INIT_1_RES = "init-1-res",
  INIT_2_MSG = "init-2-msg",
  INIT_2_RES = "init-2-res",
  LSS_MSG = "lss-msg",
  LSS_RES = "lss-res",
  HELLO = "hello",
  BYE = "bye",
}

export function initialize() {
  const ks = get(keys);
  const secret = ks.secret;

  const auth_token = sphinx.make_auth_token(now(), ks.secret);
  console.log(auth_token);
  // start and sub mqtt
  // send HELLO
  const url = "ws://localhost:8083";
  const cl = mqtt.connect(url, {
    username: ks.pubkey,
    password: auth_token,
  });
  cl.on("connect", async function () {
    cl.on("close", function (e) {
      console.log("MQTT CLOSED", e);
    });
    cl.on("error", function (e) {
      console.log("MQTT ERROR", e);
    });
    cl.on("message", function (topic, message) {
      console.log("=====>>>>> GOT A MSG", topic, message);
    });
  });
}

export type State = { [k: string]: VersionBytes };

export function run_init_1(a: Args, s: State) {}

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

function _test() {
  const ones = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1,
  ];
  const a: Args = {
    seed: Uint8Array.from(ones),
    network: "regtest",
    policy: {
      msat_per_interval: 21000000000,
      interval: "daily",
      htlc_limit_msat: 1000000000,
    },
    allowlist: [],
    timestamp: 1111111111,
    lss_nonce: Uint8Array.from(ones),
  };
  const s = stringifyArgs(a);
  console.log(s);
}

function now() {
  return Math.round(new Date().getTime() / 1000);
}

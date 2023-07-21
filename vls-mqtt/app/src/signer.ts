import { type Policy, keys } from "./store";
import { get } from "svelte/store";
import { sphinx } from "./wasm";

export enum Topics {
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

function publish(cl: any, topic: Topics, payload: any) {
  if (!cl) return console.log("NO MQTT CLIENT");
  const t = `${cl.options.clientId}/${topic}`;
  cl.publish(t, payload);
}

function sub(cl: any, topic: Topics) {
  const t = `${cl.options.clientId}/${topic}`;
  console.log("subsribe, ", t);
  cl.subscribe(t);
}

function suball(cl) {
  const ts = [Topics.VLS, Topics.INIT_1_MSG, Topics.INIT_2_MSG, Topics.LSS_MSG];
  for (let t of ts) {
    sub(cl, t);
  }
}

declare global {
  interface Window {
    mqtt: any;
  }
}

export function initialize() {
  const ks = get(keys);

  const auth_token = sphinx.make_auth_token(now(), ks.secret);
  console.log("auth_token", auth_token);
  // start and sub mqtt
  // send HELLO
  const url = "ws://localhost:8083";
  const cl = window.mqtt.connect(url, {
    username: ks.pubkey,
    password: auth_token,
  });
  cl.on("error", function (e) {
    console.log("MQTT ERROR", e);
  });
  cl.on("close", function (e) {
    console.log("MQTT CLOSED", e);
  });
  cl.on("connect", async function () {
    console.log("MQTT connected!");
    cl.on("message", processMessage);
    suball(cl);
    publish(cl, Topics.HELLO, "");
  });
}

function processMessage(topic: string, payload: Uint8Array) {
  console.log("=====>>>>> GOT A MSG", topic, payload);
  const ts = topic.split("/");
  const last = ts[ts.length - 1];
  switch (last) {
    case Topics.INIT_1_MSG:
      run_init_1(payload);
      break;
    case Topics.INIT_2_MSG:
      run_init_2(payload);
      break;
    case Topics.VLS:
      run_vls(payload);
      break;
    case Topics.LSS_MSG:
      run_lss(payload);
      break;
    default:
      console.log("bad topic", last);
  }
}

export type State = { [k: string]: VersionBytes };

export function run_init_1(p: Uint8Array) {}

export function run_init_2(p: Uint8Array) {}

export function run_vls(p: Uint8Array) {}

export function run_lss(p: Uint8Array) {}

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

import { type Policy, keys, seed, lss_nonce, policy, allowlist } from "./store";
import { get } from "svelte/store";
import { sphinx } from "./wasm";
import * as msgpack from "@msgpack/msgpack";

let MQTT;

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

function publish(topic: Topics, payload: any) {
  if (!MQTT) return console.log("NO MQTT CLIENT");
  const t = `${MQTT.options.clientId}/${topic}`;
  MQTT.publish(t, payload);
}

function sub(topic: Topics) {
  if (!MQTT) return console.log("NO MQTT CLIENT");
  const t = `${MQTT.options.clientId}/${topic}`;
  console.log("subsribe, ", t);
  MQTT.subscribe(t);
}

export function say_bye() {
  console.log("say bye!");
  publish(Topics.BYE, "");
}

function suball() {
  const ts = [Topics.VLS, Topics.INIT_1_MSG, Topics.INIT_2_MSG, Topics.LSS_MSG];
  for (let t of ts) {
    sub(t);
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
  MQTT = cl;
  cl.on("error", function (e) {
    console.log("MQTT ERROR", e);
  });
  cl.on("close", function (e) {
    console.log("MQTT CLOSED", e);
  });
  cl.on("connect", async function () {
    console.log("MQTT connected!");
    cl.on("message", processMessage);
    suball();
    publish(Topics.HELLO, "");
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

let lss_msg1: Uint8Array = Uint8Array.from([]);
let lss_msg2: Uint8Array = Uint8Array.from([]);
let prev_vls: Uint8Array = Uint8Array.from([]);
let prev_lss: Uint8Array = Uint8Array.from([]);

function processVlsResult(ret: sphinx.VlsResponse) {
  switch (ret.topic) {
    case Topics.INIT_1_RES:
      publish(Topics.INIT_1_RES, ret.lss_bytes);
      break;
    case Topics.INIT_2_RES:
      publish(Topics.INIT_2_RES, ret.lss_bytes);
      break;
    case Topics.VLS_RES:
      publish(Topics.VLS_RES, ret.vls_bytes);
      break;
    case Topics.LSS_RES:
      publish(Topics.LSS_RES, ret.lss_bytes);
      break;
    default:
      console.log("unexpected return topic", ret.topic);
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

interface ArgsAndState {
  args: string;
  state: Uint8Array;
}
function argsAndState(): ArgsAndState {
  const args = stringifyArgs(makeArgs());
  const sta: State = {};
  const state = msgpack.encode(sta);
  return { args, state };
}

export function run_init_1(p: Uint8Array) {
  try {
    const a = argsAndState();
    const ret = sphinx.run_init_1(a.args, a.state, p);
    lss_msg1 = ret.lss_bytes;
    processVlsResult(ret);
  } catch (e) {
    console.log("run_init_1 failed:", e);
  }
}

export function run_init_2(p: Uint8Array) {
  try {
    const a = argsAndState();
    console.log("run_init_2", a, lss_msg1, p);
    const ret = sphinx.run_init_2(a.args, a.state, lss_msg1, p);
    lss_msg2 = ret.lss_bytes;
    processVlsResult(ret);
  } catch (e) {
    console.log("run_init_2 failed:", e);
  }
}

export function run_vls(p: Uint8Array) {
  try {
    const a = argsAndState();
    const ret = sphinx.run_vls(a.args, a.state, lss_msg1, lss_msg2, p);
    if (ret.topic === Topics.LSS_RES) {
      prev_vls = ret.vls_bytes;
      prev_lss = ret.lss_bytes;
    }
    processVlsResult(ret);
  } catch (e) {
    console.log("run_vls failed:", e);
  }
}

export function run_lss(p: Uint8Array) {
  try {
    const a = argsAndState();
    const ret = sphinx.run_lss(
      a.args,
      a.state,
      lss_msg1,
      lss_msg2,
      prev_vls,
      prev_lss,
      p
    );
    processVlsResult(ret);
  } catch (e) {
    console.log("run_lss failed:", e);
  }
}

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

function fromHexString(hexString: string): Uint8Array {
  return Uint8Array.from(
    hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
  );
}

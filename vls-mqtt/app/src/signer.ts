import { keys } from "./store";
import { get } from "svelte/store";
import { sphinx } from "./wasm";
import { now, argsAndState, storeMutations } from "./signerUtils";

// broker: sequence 0 != expected 1

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
  try {
    const ks = get(keys);

    sphinx.init_logs();

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
  } catch (e) {
    console.error(e);
  }
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

export async function run_init_1(p: Uint8Array) {
  try {
    // save Init Msg
    lss_msg1 = p;
    const a = await argsAndState();
    const ret = sphinx.run_init_1(a.args, a.state, p);
    processVlsResult(ret);
  } catch (e) {
    console.log("run_init_1 failed:", e);
  }
}

export async function run_init_2(p: Uint8Array) {
  try {
    // save Created Msg
    lss_msg2 = p;
    const a = await argsAndState();
    const ret = sphinx.run_init_2(a.args, a.state, lss_msg1, p);
    processVlsResult(ret);
  } catch (e) {
    console.log("run_init_2 failed:", e);
  }
}

export async function run_vls(p: Uint8Array) {
  try {
    const a = await argsAndState();
    const ret = sphinx.run_vls(a.args, a.state, lss_msg1, lss_msg2, p);
    if (ret.topic === Topics.LSS_RES) {
      prev_vls = ret.vls_bytes;
      prev_lss = ret.lss_bytes;
      storeMutations(ret.lss_bytes);
    }
    processVlsResult(ret);
  } catch (e) {
    console.log("run_vls failed:", e);
  }
}

export async function run_lss(p: Uint8Array) {
  try {
    const a = await argsAndState();
    const ret = sphinx.run_lss(
      a.args,
      a.state,
      lss_msg1,
      lss_msg2,
      p,
      prev_vls,
      prev_lss
    );
    processVlsResult(ret);
  } catch (e) {
    console.log("run_lss failed:", e);
  }
}

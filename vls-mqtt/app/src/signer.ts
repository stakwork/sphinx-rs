import { sphinx } from "./wasm";
import { now, argsAndState, storeMutations, clearAll } from "./signerUtils";
import * as Paho from "paho-mqtt";
import { cmds } from "./store";

let MQTT;

let CLIENT_ID;

let sequence: number | undefined = undefined;

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

function suball() {
  const ts = [Topics.VLS, Topics.INIT_1_MSG, Topics.INIT_2_MSG, Topics.LSS_MSG];
  for (let t of ts) {
    sub(t);
  }
}

export async function clear() {
  await clearAll();
}

export async function initialize(secret: string, pubkey: string) {
  try {
    sphinx.init_logs();

    const userName = pubkey;
    const password = sphinx.make_auth_token(now(), secret);
    console.log("auth_token", password);

    const host = "localhost";
    const port = 8083;
    const useSSL = false;

    CLIENT_ID = `paho-${genId()}`;
    MQTT = new Paho.Client(host, port, "", CLIENT_ID) as any;

    async function onConnectionLost() {
      console.log("onConnectionLost");
      sequence = undefined;
      await sleep(1000);
      mqttConnect(userName, password, useSSL);
    }
    MQTT.onConnectionLost = onConnectionLost;

    mqttConnect(userName, password, useSSL);
  } catch (e) {
    console.error(e);
  }
}

function mqttConnect(userName: string, password: string, useSSL: boolean) {
  function onSuccess() {
    console.log("MQTT connected!");
    MQTT.onMessageArrived = function (m) {
      processMessage(m.topic, new Uint8Array(m.payloadBytes));
    };
    suball();
    publish(Topics.HELLO, "");
  }
  MQTT.connect({ onSuccess, useSSL, userName, password });
}

type VlsHandler = (
  args: string,
  state: Uint8Array,
  p: Uint8Array,
  sequence?: number
) => sphinx.VlsResponse;

const funcs: { [k: string]: VlsHandler } = {
  [Topics.INIT_1_MSG]: sphinx.run_init_1,
  [Topics.INIT_2_MSG]: sphinx.run_init_2,
  [Topics.VLS]: sphinx.run_vls,
  [Topics.LSS_MSG]: sphinx.run_lss,
};

async function processMessage(topic: string, payload: Uint8Array) {
  try {
    // console.log("=====>>>>> GOT A MSG", topic, payload);
    const ts = topic.split("/");
    const last = ts[ts.length - 1];
    if (!funcs[last]) {
      return console.log("bad topic", last);
    }
    const a = await argsAndState();
    const ret = funcs[last](a.args, a.state, payload, sequence);
    await processVlsResult(ret);
    if (last === Topics.VLS) {
      if (ret.cmd) {
        cmds.update((cs) => [...cs, ret.cmd]);
      }
      if (ret.sequence || ret.sequence === 0) {
        sequence = ret.sequence + 1;
      }
    }
  } catch (e) {
    console.error(e);
    if (e.toString().startsWith("Error: VLS Failed: invalid sequence")) {
      console.log("BAD SEQUENCE ERROR");
      await restart();
    }
  }
}

async function restart() {
  await clearAll();
  sequence = null;
  publish(Topics.HELLO, "");
}

async function processVlsResult(ret: sphinx.VlsResponse) {
  await storeMutations(ret.state);
  publish(ret.topic as Topics, ret.bytes);
}

function publish(topic: Topics, payload: any) {
  try {
    if (!MQTT) return console.log("NO MQTT CLIENT");
    const t = `${CLIENT_ID}/${topic}`;
    MQTT.publish(t, payload);
  } catch (e) {
    console.warn(e);
  }
}

function sub(topic: Topics) {
  try {
    if (!MQTT) return console.log("NO MQTT CLIENT");
    const t = `${CLIENT_ID}/${topic}`;
    console.log("subscribe, ", t);
    MQTT.subscribe(t);
  } catch (e) {
    console.warn(e);
  }
}

export function say_bye() {
  console.log("say bye!");
  publish(Topics.BYE, "");
}

export const genId = (): string => {
  return Array.from(
    window.crypto.getRandomValues(new Uint8Array(16)),
    (byte) => {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }
  ).join("");
};

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

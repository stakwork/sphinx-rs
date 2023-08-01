import { sphinx } from "./wasm";
import * as utils from "./signerUtils";
import { Topics } from "./signerUtils";
import * as Paho from "paho-mqtt";
import { cmds } from "./store";

let MQTT;

let CLIENT_ID;

let sequence: number | undefined = undefined;

export async function initialize(secret: string, pubkey: string) {
  try {
    sphinx.init_logs();

    const userName = pubkey;
    const password = sphinx.make_auth_token(utils.now(), secret);
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

function subscribeAll() {
  const ts = [Topics.VLS, Topics.INIT_1_MSG, Topics.INIT_2_MSG, Topics.LSS_MSG];
  for (let t of ts) {
    subscribe(t);
  }
}

function mqttConnect(userName: string, password: string, useSSL: boolean) {
  function onSuccess() {
    console.log("MQTT connected!");
    MQTT.onMessageArrived = function (m) {
      processMessage(m.topic, new Uint8Array(m.payloadBytes));
    };
    subscribeAll();
    publish(Topics.HELLO, "");
  }
  MQTT.connect({ onSuccess, useSSL, userName, password });
}

async function processMessage(topic: string, payload: Uint8Array) {
  try {
    const a = await utils.argsAndState();
    const ret = sphinx.run(topic, a.args, a.state, payload, sequence);
    await processVlsResult(ret);
    if (topic.endsWith(Topics.VLS)) {
      if (ret.cmd) {
        // store command history
        cmds.update((cs) => [...cs, ret.cmd]);
      }
      // update expected sequence
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

async function processVlsResult(ret: sphinx.VlsResponse) {
  const vel = await utils.storeMutations(ret.state);
  publish(ret.topic as Topics, ret.bytes);
}

export async function clear() {
  await utils.clearAll();
}

export function say_bye() {
  console.log("say bye!");
  publish(Topics.BYE, "");
}

async function restart() {
  await utils.clearAll();
  sequence = null;
  publish(Topics.HELLO, "");
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

function subscribe(topic: Topics) {
  try {
    if (!MQTT) return console.log("NO MQTT CLIENT");
    const t = `${CLIENT_ID}/${topic}`;
    console.log("subscribe, ", t);
    MQTT.subscribe(t);
  } catch (e) {
    console.warn(e);
  }
}

const genId = (): string => {
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

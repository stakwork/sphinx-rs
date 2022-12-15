import { sphinx } from "./wasm";
import { localStorageStore } from "./storage";
import { seed } from "./store";
import { derived, get } from "svelte/store";

const nonce = localStorageStore("nonce", 0);

console.log(get(nonce));

export const keys = derived([seed], ([$seed]) => {
  try {
    return sphinx.node_keys("regtest", $seed);
  } catch (e) {
    console.error(e);
  }
});

interface Control {
  type: Cmd;
  content?: any;
}
type Cmd =
  | "Nonce"
  | "ResetWifi"
  | "ResetKeys"
  | "ResetAll"
  | "QueryPolicy"
  | "UpdatePolicy"
  | "QueryAllowlist"
  | "UpdateAllowlist"
  | "Ota";

interface OtaParams {
  version: number;
  url: string;
}

interface WifiParams {
  ssid: string;
  password: string;
}

export function root() {
  let root = "/api/";
  if (window.location.host === "localhost:8080") {
    root = "http://localhost:8008/api/";
  }
  if (window.location.host === "localhost:3001") {
    root = "https://vls.sphinx.chat/api/";
  }
  return root;
}

async function sendCmd(type: Cmd, content?: any) {
  const j = JSON.stringify({ type, ...(content && { content }) });
  const ks: sphinx.Keys = get(keys);
  console.log("PUBKEY", ks.pubkey, j);
  let msg;
  try {
    msg = sphinx.build_control_request(j, ks.secret, BigInt(get(nonce)));
  } catch (e) {
    console.error(e);
    return null;
  }
  console.log("msg to ssend", `${root()}control?msg=${msg}`);
  const r = await fetch(`${root()}control?msg=${msg}`, {
    method: "POST",
  });
  const res = await r.text();
  return res;
}

export async function getNonce() {
  console.log("get nonce");
  try {
    console.log("-");
    const res = await sendCmd("Nonce");
    console.log("1", res);
    const msg = sphinx.parse_control_response(res);
    console.log("2");
    console.log(msg);
    return msg;
  } catch (e) {
    return null;
  }
}

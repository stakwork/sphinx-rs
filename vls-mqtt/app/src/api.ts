import { sphinx } from "./wasm";
import { localStorageStore } from "./storage";
import { seed } from "./store";
import { derived, get } from "svelte/store";

const nonce = localStorageStore("nonce", 0);

console.log(get(nonce));

export const keys = derived([seed], ([$seed]) => {
  try {
    return sphinx.node_keys("regtest", $seed);
  } catch (e) {}
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
  if (window.location.host === "localhost:3000") {
    root = "http://localhost:8000/api/";
  }
  if (window.location.host === "localhost:3001") {
    root = "https://vls.sphinx.chat/api/";
  }
  return root;
}

async function sendCmd(type: Cmd, content?: any) {
  const j = JSON.stringify({ type, ...(content && { content }) });
  const ks: sphinx.Keys = get(keys);
  let msg;
  try {
    msg = sphinx.build_control_request(j, ks.secret, BigInt(get(nonce)));
  } catch (e) {
    return null;
  }
  const r = await fetch(`${root()}control?msg=${msg}`, {
    method: "POST",
  });
  const res = await r.text();
  let ret;
  try {
    // return sphinx.
  } catch (e) {}
}

export function getNonce() {
  const req = sendCmd("Nonce");
}

import { sphinx } from "./wasm";
import { localStorageStore } from "./storage";
import { policy, allowlist, Policy, isSigner, keys } from "./store";
import { get } from "svelte/store";

const nonce = localStorageStore("nonce", 0);

function newNonce(update: boolean): bigint {
  let n = get(nonce);
  if (update) {
    nonce.update((n) => n + 1);
  }
  log("newNonce", n + 1);
  return BigInt(n + 1);
}

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
  if (get(isSigner)) {
    return console.log("=> skip sendCmd");
  }
  log("=> sendCmd", type, content);
  const j = JSON.stringify({ [type]: content || null });
  const ks: sphinx.Keys = get(keys);
  let msg;
  try {
    msg = sphinx.build_control_request(
      j,
      ks.secret,
      newNonce(type !== "Nonce")
    );
  } catch (e) {
    console.error(e);
    return null;
  }
  const r = await fetch(`${root()}control?msg=${msg}`, {
    method: "POST",
  });
  const res = await r.text();
  // update the nonce for next time
  return res;
}

export async function getNonce() {
  log("=> getNonce");
  try {
    const res = await sendCmd("Nonce");
    if (!res) return;
    const msg = sphinx.parse_control_response(res);
    console.log("nonce response:", msg, typeof msg);
    const j = JSON.parse(msg);
    if (j.Nonce) {
      nonce.set(j.Nonce);
      return j.Nonce;
    }
    return msg;
  } catch (e) {
    console.log("FAILED getNonce()");
    return null;
  }
}

export async function getPolicy(): Promise<Policy> {
  log("=> getPolicy");
  try {
    const res = await sendCmd("QueryPolicy");
    if (!res) return;
    const msg = sphinx.parse_control_response(res);
    const j = JSON.parse(msg);
    if (j.PolicyCurrent) {
      policy.set(j.PolicyCurrent);
      return j.PolicyCurrent;
    }
  } catch (e) {
    console.error(e);
  }
}

export async function setPolicy(p: Policy): Promise<Policy> {
  log("=> setPolicy");
  try {
    const res = await sendCmd("UpdatePolicy", p);
    if (!res) return;
    const msg = sphinx.parse_control_response(res);
    const j = JSON.parse(msg);
    if (j.PolicyUpdated) {
      console.log(j.PolicyUpdated);
      policy.set(j.PolicyUpdated);
      return j.PolicyUpdated;
    }
  } catch (e) {
    console.error(e);
  }
}

export async function getAllowlist(): Promise<string[]> {
  log("=> getAllowlist");
  try {
    const res = await sendCmd("QueryAllowlist");
    if (!res) return;
    const msg = sphinx.parse_control_response(res);
    const j = JSON.parse(msg);
    console.log(j);
    if (j.AllowlistCurrent) {
      allowlist.set(j.AllowlistCurrent);
      return j.AllowlistCurrent;
    }
    return [];
  } catch (e) {
    console.error(e);
  }
}

export async function setAllowlist(al: string[]): Promise<string[]> {
  log("=> setAllowlist");
  try {
    const res = await sendCmd("UpdateAllowlist", al);
    if (!res) return;
    const msg = sphinx.parse_control_response(res);
    const j = JSON.parse(msg);
    console.log(j);
    return [];
  } catch (e) {
    console.error(e);
  }
}

const log = true ? console.log : () => {};

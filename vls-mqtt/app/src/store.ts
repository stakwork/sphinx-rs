import { writable, derived } from "svelte/store";
import { localStorageStore } from "./storage";
import { sphinx } from "./wasm";

interface PageItem {
  page: Page;
  label: string;
}
const initialIsSigner = signerParam();

export const pages: PageItem[] = [
  { label: "Account", page: "account" },
  { label: "Policy", page: "policy" },
  { label: "Allow List", page: "allowlist" },
  { label: "Force Close", page: "forceclose" },
];
if (initialIsSigner) {
  pages.unshift({ label: "Signer", page: "signer" });
}

export type Page = "signer" | "account" | "allowlist" | "policy" | "forceclose";

export const menu = writable<Page>(initialIsSigner ? "signer" : "account");

export const loaded = writable<boolean>(false);

export type Interval = "hourly" | "daily";

export interface Policy {
  msat_per_interval: number;
  interval: Interval;
  htlc_limit_msat: number;
}

export const defaultPolicy: Policy = {
  msat_per_interval: 21000000000,
  interval: "daily",
  htlc_limit_msat: 1000000000,
};

export const policy = writable<Policy>(defaultPolicy);

export const allowlist = writable<string[]>([]);

export const cmds = writable<string[]>([]);

export const genSeed = (): string => {
  return Array.from(
    window.crypto.getRandomValues(new Uint8Array(32)),
    (byte) => {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }
  ).join("");
};

export const seed = localStorageStore<string>("seed", genSeed());

export const lss_nonce = writable<string>(genSeed());

export const keys = derived([loaded, seed], ([$loaded, $seed]) => {
  if (!$loaded) return null;
  try {
    return sphinx.node_keys("regtest", $seed);
  } catch (e) {
    console.error(e);
  }
});

export const pubkey = derived([keys], ([$keys]) => {
  if (!$keys) return "";
  return $keys.pubkey;
});

export const isSigner = writable<boolean>(initialIsSigner);

function signerParam(): boolean {
  const queryString = window.location.search;
  const urlParams = new URLSearchParams(queryString);
  const signer = urlParams.get("signer");
  if (signer) {
    console.log("=> signer mode");
    return true;
  } else {
    return false;
  }
}

export function formatPubkey(pk: string) {
  return `${pk.slice(0, 6)}...${pk.slice(60)}`;
}

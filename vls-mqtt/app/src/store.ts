import { writable } from "svelte/store";
import { localStorageStore } from "./storage";

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

export const genKey = (): string => {
  return Array.from(
    window.crypto.getRandomValues(new Uint8Array(32)),
    (byte) => {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }
  ).join("");
};

export const seed = localStorageStore<string>("seed", genKey());

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

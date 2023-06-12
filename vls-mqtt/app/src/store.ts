import { writable } from "svelte/store";
import { localStorageStore } from "./storage";

interface PageItem {
  page: Page;
  label: string;
}
export const pages: PageItem[] = [
  { label: "Account", page: "account" },
  { label: "Policy", page: "policy" },
  { label: "Allow List", page: "allowlist" },
  { label: "Force Close", page: "forceclose" },
];

export type Page = "account" | "allowlist" | "policy" | "forceclose";

export const menu = writable<Page>("account");

export type Interval = "hourly" | "daily";

export interface Policy {
  msat_per_interval: number;
  interval: Interval;
  htlc_limit_msat: number;
}

export const defaultPolicy: Policy = {
  msat_per_interval: 1100000,
  interval: "daily",
  htlc_limit_msat: 1000000,
};

export const policy = writable<Policy>(defaultPolicy);

const devAllowlist = [
  "lbtc134234gh234gh2g34hg2h3g4h2g34",
  "lbtc134234gh234gh2g34hg2h3g4h2g34",
  "lbtc134234gh234gh2g34hg2h3g4h2g34",
];

export const allowlist = writable<string[]>(devAllowlist);

export const genKey = (): string => {
  return Array.from(
    window.crypto.getRandomValues(new Uint8Array(32)),
    (byte) => {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }
  ).join("");
};

export const seed = localStorageStore<string>("seed", genKey());

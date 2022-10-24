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
];

type Page = "account" | "allowlist" | "policy";

export const menu = writable<Page>("account");

export const seed = localStorageStore<string>("seed", "");

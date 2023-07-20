import type { Policy } from "./store";

export interface LssResponse {
  VlsMuts: VlsMuts;
}

export interface VlsMuts {
  client_hmac: Bytes;
  muts: Mutations;
}

export type Mutations = VlsBytes[];

export type VlsBytes = (string | VersionBytes)[];

export type VersionBytes = (number | Bytes)[];

export type Bytes = Uint8Array;

export type Velocity = (number | Bytes)[];

// ["name", [1, [bytes]]]
export interface Args {
  seed: Uint8Array;
  network: string;
  policy: Policy;
  velocity?: Velocity;
  allowlist: string[];
  timestamp: number; // unix ts in seconds
  lss_nonce: Uint8Array;
}

function stringifyArgs(a: Args): string {
  return JSON.stringify(a, (k, v) => {
    if (v instanceof Uint8Array) {
      return Array.from(v);
    } else {
      return v;
    }
  });
}

function _test() {
  const ones = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1,
  ];
  const a: Args = {
    seed: Uint8Array.from(ones),
    network: "regtest",
    policy: {
      msat_per_interval: 21000000000,
      interval: "daily",
      htlc_limit_msat: 1000000000,
    },
    allowlist: [],
    timestamp: 1111111111,
    lss_nonce: Uint8Array.from(ones),
  };
  const s = stringifyArgs(a);
  console.log(s);
}

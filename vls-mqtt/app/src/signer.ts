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

// ["name", [1, [bytes]]]

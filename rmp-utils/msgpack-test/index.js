import { encode, decode } from "@msgpack/msgpack";

function go() {
  const bytes = Uint8Array.from([
    145, 146, 162, 104, 105, 146, 23, 147, 1, 2, 3,
  ]);

  const d = decode(bytes);

  console.log(d);

  const data = [["hi", [23, [1, 2, 3]]]];
  console.log(encode(data));
}

// go();

function vls_muts() {
  const b = [
    129, 167, 86, 108, 115, 77, 117, 116, 115, 130, 171, 99, 108, 105, 101, 110,
    116, 95, 104, 109, 97, 99, 196, 32, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 164, 109, 117, 116, 115, 147,
    146, 164, 97, 97, 97, 97, 146, 15, 196, 3, 255, 255, 255, 146, 164, 98, 98,
    98, 98, 146, 15, 196, 3, 255, 255, 255, 146, 164, 99, 99, 99, 99, 146, 15,
    196, 3, 255, 255, 255,
  ];
  const bytes = Uint8Array.from(b);
  const d = decode(bytes);
  // console.log(d);
  const to_persist = persist_muts(d["VlsMuts"].muts);
  const map = un_persist(to_persist);
  console.log(map);
}

function persist_muts(muts) {
  let ret = [];
  for (let m of muts) {
    let name = m[0];
    let val = m[1];
    let ver = val[0];
    const ver_bytes = getInt64Bytes(BigInt(ver));
    let mut = Buffer.from(val[1]);
    const bytes = Buffer.concat([ver_bytes, mut]);
    ret.push({ name, bytes: bytes.toString("base64") });
  }
  return ret;
}

function un_persist(aray) {
  const ret = {};
  for (let a of aray) {
    const b = Buffer.from(a.bytes, "base64");
    const ver_bytes = b.slice(0, 8);
    const ver = intFromBytes(ver_bytes);
    const bytes = b.slice(8);
    ret[a.name] = [Number(ver), bytes];
  }
  return ret;
}

vls_muts();

function getInt64Bytes(x) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64LE(x);
  return bytes;
}

function intFromBytes(x) {
  return x.readBigInt64LE();
}

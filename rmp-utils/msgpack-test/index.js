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

go();

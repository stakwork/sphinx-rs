import * as sphinx from "../../../sphinx-wasm/pkg";

export { sphinx };

async function load() {
  try {
    await sphinx.default("/sphinx_wasm_bg.wasm");
  } catch (e) {
    console.log(e);
  }
}

load();

import { greet, get_wasm_memory } from './pkg';

const memory = get_wasm_memory();
console.log("WebAssembly memory:", memory);
greet('World');

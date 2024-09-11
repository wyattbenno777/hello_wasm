use wasm_bindgen::prelude::*;
use zk_engine::{
    traits::zkvm::ZKVM,
    utils::{logging::init_logger, wasm::wat2wasm},
    wasm::{args::WASMArgsBuilder, ctx::WASMCtx},
    BatchedZKEngine,
};

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

// Define the memory configuration
#[wasm_bindgen]
pub fn get_wasm_memory() -> JsValue {
    wasm_bindgen::memory()
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    init_logger();

    let wasm = r#"(module
        (func $fib (export "fib") (param $N i64) (result i64)
            (local $n1 i64)
            (local $n2 i64)
            (local $tmp i64)
            (local $i i64)
            ;; return $N for N <= 1
            (if
                (i64.le_s (local.get $N) (i64.const 1))
                (then (return (local.get $N)))
            )
            (local.set $n1 (i64.const 1))
            (local.set $n2 (i64.const 1))
            (local.set $i (i64.const 2))
            ;;since we normally return n2, handle n=1 case specially
            (loop $continue
                (if
                    (i64.lt_s (local.get $i) (local.get $N))
                    (then
                        (local.set $tmp (i64.add (local.get $n1) (local.get $n2)))
                        (local.set $n1 (local.get $n2))
                        (local.set $n2 (local.get $tmp))
                        (local.set $i (i64.add (local.get $i) (i64.const 1)))
                        (br $continue)
                    )
                )
            )
            (local.get $n2)
        )
    )"#;
    
    let args = WASMArgsBuilder::default()
    .invoke(Some(String::from("fib")))
    .func_args(vec![String::from("1000")]) // This will generate 16,000 + opcodes
    .build();

    let wasm_bytes = match wat2wasm(wasm) {
        Ok(bytes) => bytes,
        Err(e) => {
            alert(&format!("Error in wat2wasm: {:?}", e));
            return;
        }
    };

    let mut ctx = match WASMCtx::new_from_bytecode(&wasm_bytes, &args) {
        Ok(ctx) => ctx,
        Err(e) => {
            alert(&format!("Error in WASMCtx::new_from_bytecode: {:?}", e));
            return;
        }
    };

    let pp = match BatchedZKEngine::setup(&mut ctx) {
        Ok(pp) => pp,
        Err(e) => {
            alert(&format!("Error in BatchedZKEngine::setup: {:?}", e));
            return;
        }
    };

    /*let (proof, public_values, _) =
    ZKEngine::prove_wasm(&mut WASMCtx::new_from_bytecode(&wasm_bytes, &args).unwrap(), &pp).unwrap();

    let (proof, public_values, _) =
    BatchedZKEngine::prove_wasm(&mut WASMCtx::new_from_bytecode(&wasm_bytes, &args).unwrap(), &pp).unwrap();*/

    alert(&format!("Hello, {}!", name));
}
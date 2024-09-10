use wasm_bindgen::prelude::*;
use zk_engine::{
    traits::zkvm::ZKVM,
    utils::{logging::init_logger, wasm::wat2wasm},
    wasm::{args::WASMArgsBuilder, ctx::WASMCtx},
    ZKEngine,
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
        (func (export "main") (param i32 i32) (result i32)
          local.get 0
          local.get 1
          i32.add))"#;
    
    let args = WASMArgsBuilder::default()
        .func_args(vec![String::from("1"), String::from("2")])
        .build();

    let wasm_bytes = wat2wasm(wasm).unwrap();

    // Run setup step for ZKVM
    //let pp = ZKEngine::setup(&mut WASMCtx::new_from_bytecode(&wasm_bytes, &args).unwrap()).unwrap();

    let pp = match ZKEngine::setup(&mut WASMCtx::new_from_bytecode(&wasm_bytes, &args).unwrap()) {
        Ok(pp) => pp,
        Err(e) => {
            alert(&format!("Error in ZKEngine::setup(): {:?}", e));
            return;
        }
    };

    alert(&format!("Hello, {}!", name));
}
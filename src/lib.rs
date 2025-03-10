use zk_engine::{
    nova::{
        provider::{ipa_pc, Bn256EngineIPA},
        spartan::{self, ppsnark::RelaxedR1CSSNARK},
        traits::{snark::RelaxedR1CSSNARKTrait, Dual},
    },
    utils::logging::init_logger,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK},
};

use wasm_bindgen::prelude::*;
use js_sys::Function;
use wat::parse_str;
use wasm_bindgen::prelude::*;
use js_sys::Date;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance)]
    fn now() -> f64;
}

// Ensure you use the correct cycle pairing
pub type E = Bn256EngineIPA;
pub type EE1 = ipa_pc::EvaluationEngine<E>;
pub type EE2 = ipa_pc::EvaluationEngine<Dual<E>>;
pub type S1 = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1>;
pub type S2 = RelaxedR1CSSNARK<Dual<E>, EE2>;

const FIB_WAT: &str = "(module
    (func $fib (export \"fib\") (param $N i64) (result i64)
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
)";

#[wasm_bindgen]
pub fn run_fib(func: &str, func_args: JsValue, step_size: u32, mem_step_size: u32, callback: js_sys::Function) -> Result<JsValue, JsValue> {
    init_logger();
    let this = JsValue::null();

    callback.call1(&this, &JsValue::from_str("Start"))?;
    
    //let step_size = StepSize::new(step_size as usize);
    let step_size = StepSize::new(10);
    callback.call1(&this, &JsValue::from_str("Start pp"))?;
    let start = now();
    let pp = WasmSNARK::<E, S1, S2>::setup(step_size);
    callback.call1(&this, &JsValue::from_str(&format!("End pp: {:?}", now() - start)))?;

    let args: Vec<String> = serde_wasm_bindgen::from_value(func_args)
        .map_err(|e| JsValue::from_str(&format!("Invalid function arguments: {}", e)))?;
    callback.call1(&this, &JsValue::from_str("loaded Args"))?;

    let wasm_bytes = parse_str(FIB_WAT).map_err(|e| JsValue::from_str(&format!("Error parsing WAT: {}", e)))?;
    
    let wasm_args = WASMArgsBuilder::default()
        .bytecode(wasm_bytes)
        .invoke("fib")
        .func_args(vec![String::from("16")])
        .build();

    callback.call1(&this, &JsValue::from_str("Start new"))?;
    
    let wasm_ctx = WASMCtx::new(wasm_args);
    callback.call1(&this, &JsValue::from_str("Start prove"))?;
    let start = now();
    let (snark, instance) = WasmSNARK::<E, S1, S2>::prove(&pp, &wasm_ctx, step_size)
        .map_err(|e| JsValue::from_str(&format!("Proving error: {}", e)))?;
    callback.call1(&this, &JsValue::from_str(&format!("Proving complete: {:?}", now() - start)))?;
    
    callback.call1(&this, &JsValue::from_str("Start verify"))?;
    let start = now();
    snark.verify(&pp, &instance)
        .map_err(|e| JsValue::from_str(&format!("Verification error: {}", e)))?;
    callback.call1(&this, &JsValue::from_str(&format!("Verify complete: {:?}", now() - start)))?;
    
    Ok(JsValue::from_str("Proof verified successfully"))
}
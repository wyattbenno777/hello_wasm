use delegated::ExclusionCircuit;
use halo2curves::bn256::Bn256;
use zk_engine::{
    nova::{
        provider::{Bn256EngineIPA, Bn256EngineKZG, GrumpkinEngine},
        spartan,
        traits::Dual,
    },
    utils::logging::init_logger,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK, ZKWASMInstance},
};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures;
use wat::parse_str;
mod delegated;

// Ensure you use the correct cycle pairing
type E = Bn256EngineKZG;
type E2 = GrumpkinEngine;
type EE1 = zk_engine::nova::provider::hyperkzg::EvaluationEngine<Bn256, E>;
type EE2 = zk_engine::nova::provider::ipa_pc::EvaluationEngine<E2>;
type S1 = zk_engine::nova::spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1>; 
type S2 = zk_engine::nova::spartan::snark::RelaxedR1CSSNARK<E2, EE2>; 


#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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

use web_sys::console;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance)]
    fn now() -> f64;
}

#[wasm_bindgen]
pub async fn run_fib(
    func: &str,
    func_args: JsValue,
    step_size: u32,
    mem_step_size: u32,
    callback: js_sys::Function,
) -> Result<JsValue, JsValue> {
    init_logger();
    let this = JsValue::null();

    callback.call1(&this, &JsValue::from_str("Start"))?;

    //let step_size = StepSize::new(step_size as usize);
    let step_size = StepSize::new(100);
    callback.call1(&this, &JsValue::from_str("Start pp"))?;
    let pp_start = now();
    let pp = WasmSNARK::<E, S1, S2>::setup(step_size);
    let pp_end = now();
    callback.call1(&this, &JsValue::from_str(&format!("End pp: {} ms", pp_end - pp_start)))?;

    let args: Vec<String> = serde_wasm_bindgen::from_value(func_args)
        .map_err(|e| JsValue::from_str(&format!("Invalid function arguments: {}", e)))?;
    callback.call1(&this, &JsValue::from_str("loaded Args"))?;

    let wasm_bytes =
        parse_str(FIB_WAT).map_err(|e| JsValue::from_str(&format!("Error parsing WAT: {}", e)))?;

    let wasm_args = WASMArgsBuilder::default()
        .bytecode(wasm_bytes)
        .invoke("fib")
        .func_args(vec![String::from("16")])
        .build();

    callback.call1(&this, &JsValue::from_str("Start new"))?;

    let wasm_ctx = WASMCtx::new(wasm_args);
    callback.call1(&this, &JsValue::from_str("Start prove"))?;

    let prove_start = now();
    let (snark, instance) = WasmSNARK::<E, S1, S2>::prove(&pp, &wasm_ctx, step_size)
        .await
        .map_err(|e| JsValue::from_str(&format!("Proving error: {}", e)))?;
    let prove_end = now();
    callback.call1(&this, &JsValue::from_str(&format!("Proving complete: {} ms", prove_end - prove_start)))?;

    let verify_start = now();
    snark
        .verify(&pp, &instance)
        .await
        .map_err(|e| JsValue::from_str(&format!("Verification error: {}", e)))?;
    let verify_end = now();
    callback.call1(&this, &JsValue::from_str(&format!("Verification complete: {} ms", verify_end - verify_start)))?;

    Ok(JsValue::from_str("Proof verified successfully"))
}

#[wasm_bindgen]
pub async fn verify_proof(
    str_snark: String,
    str_instance: String,
    callback: js_sys::Function,
) -> Result<JsValue, JsValue> {
    init_logger();
    let this = JsValue::null();

    // Parse the JSON strings
    callback.call1(&this, &JsValue::from_str("Loading files"))?;
    let snark: WasmSNARK<E, S1, S2> = serde_json::from_str(&str_snark)
        .map_err(|e| JsValue::from_str(&format!("Error parsing snark.json: {}", e)))?;

    let instance: ZKWASMInstance<E> = serde_json::from_str(&str_instance)
        .map_err(|e| JsValue::from_str(&format!("Error parsing instance.json: {}", e)))?;

    // Create a dummy setup to get public parameters
    // (assuming this is needed for verification)
    let step_size = StepSize::new(1);
    callback.call1(&this, &JsValue::from_str("Starting PP"))?;
    let pp = WasmSNARK::<E, S1, S2>::setup(step_size);

    callback.call1(&this, &JsValue::from_str("Verify start!"))?;

    // Verify the proof
    snark
        .verify(&pp, &instance)
        .await
        .map_err(|e| JsValue::from_str(&format!("Verification error: {}", e)))?;

    Ok(JsValue::from_str("Proof verified successfully"))
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn delegated_spartan(address: String, callback: js_sys::Function) -> Result<JsValue, JsValue> {
    use nova_snark::spartan::spark::TrivialCompComputationEngine;
    use nova_snark::traits::Engine;
    use nova_snark::{
        provider::{ipa_pc, Bn256EngineIPA},
        spartan::direct::DirectSNARK,
    };
    type E = Bn256EngineIPA;
    type F = <E as Engine>::Scalar;
    type EE = ipa_pc::EvaluationEngine<E>;
    type S = nova_snark::spartan::delegatedsnark::RelaxedR1CSSNARK<
        E,
        EE,
        TrivialCompComputationEngine<E, EE>,
    >;
    let this = JsValue::null();
    let address = address.as_bytes();
    let circuit = ExclusionCircuit::<E>::new(address.try_into().unwrap());
    callback.call1(&this, &JsValue::from_str("Setup..."))?;

    let (pk, vk) =
        DirectSNARK::<E, S, _>::setup(circuit.clone()).expect("pk, vk should be constructed");
    callback.call1(&this, &JsValue::from_str("Setup done!"))?;
    callback.call1(&this, &JsValue::from_str("Proving..."))?;
    let proof =
        DirectSNARK::<E, S, _>::prove(&pk, circuit, &[F::zero()]).expect("proof should be valid");
    callback.call1(&this, &JsValue::from_str("Proof generated!"))?;
    callback.call1(&this, &JsValue::from_str("Verifying..."))?;
    proof
        .verify(&vk, &[F::zero(), F::zero()])
        .expect("proof should be verified");
    Ok(JsValue::from_str("Proof verified successfully"))
}
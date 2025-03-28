use delegated::ExclusionCircuit;
use zk_engine::{
    nova::{
        provider::{ipa_pc, Bn256EngineIPA},
        spartan,
        traits::Dual,
    },
    utils::logging::init_logger,
    wasm_ctx::{WASMArgsBuilder, WASMCtx},
    wasm_snark::{StepSize, WasmSNARK, ZKWASMInstance},
};

use wasm_bindgen::prelude::*;
use wat::parse_str;
mod delegated;

// Ensure you use the correct cycle pairing
pub type E = Bn256EngineIPA;
pub type EE1 = ipa_pc::EvaluationEngine<E>;
pub type EE2 = ipa_pc::EvaluationEngine<Dual<E>>;
pub type S1 = spartan::batched::BatchedRelaxedR1CSSNARK<E, EE1>;
pub type S2 = spartan::snark::RelaxedR1CSSNARK<Dual<E>, EE2>;

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

#[wasm_bindgen]
pub fn run_fib(
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
    let step_size = StepSize::new(10);
    callback.call1(&this, &JsValue::from_str("Start pp"))?;
    let pp = WasmSNARK::<E, S1, S2>::setup(step_size);
    callback.call1(&this, &JsValue::from_str("End pp"))?;

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

    let (snark, instance) = WasmSNARK::<E, S1, S2>::prove(&pp, &wasm_ctx, step_size)
        .map_err(|e| JsValue::from_str(&format!("Proving error: {}", e)))?;
    callback.call1(&this, &JsValue::from_str("Proving complete"))?;

    snark
        .verify(&pp, &instance)
        .map_err(|e| JsValue::from_str(&format!("Verification error: {}", e)))?;

    callback.call1(&this, &JsValue::from_str("Proof verified successfully"))?;

    Ok(JsValue::from_str("Proof verified successfully"))
}

#[wasm_bindgen]
pub fn verify_proof(
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
    let step_size = StepSize::new(10);
    callback.call1(&this, &JsValue::from_str("Starting PP"))?;
    let pp = WasmSNARK::<E, S1, S2>::setup(step_size);

    callback.call1(&this, &JsValue::from_str("Verify start!"))?;

    // Verify the proof
    snark
        .verify(&pp, &instance)
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

self.importScripts("./pkg/zkvm_wasm_runner.js");

async function initWasm() {
    await wasm_bindgen("./pkg/zkvm_wasm_runner_bg.wasm");
}

initWasm().then(() => {
    self.onmessage = async (event) => {
        const data = event.data;

        function logOutput(message) {
            self.postMessage({ type: "log", message });
        }

        try {
            // Check the type of operation to perform
            if (!data.type || data.type === "run") {
                // Original functionality - run WAT file
                const { wat, func, args, stepSize, memStepSize } = data;

                console.log("Starting WASM execution...");
                const result = await wasm_bindgen.run_fib(func, args, stepSize, memStepSize, logOutput);
                console.log("WASM execution completed.");
                self.postMessage({ type: "result", result });
            }
            else if (data.type === "verify") {
                // New functionality - verify proof from JSON files
                const { snarkContent, instanceContent } = data;

                console.log("Starting proof verification...");
                logOutput("Verifying proof...");

                const result = await wasm_bindgen.verify_proof(snarkContent, instanceContent, logOutput);
                console.log("Proof verification completed.");
                self.postMessage({ type: "result", result });
            }
            else if (data.type === "delegated_spartan") {
                const { address } = data;
                console.log(address);
                const result = await wasm_bindgen.delegated_spartan(address);
                self.postMessage({ type: "result", result });
            }
        } catch (err) {
            console.error("Execution error:", err);
            self.postMessage({ type: "error", error: err.toString() });
        }
    };
});
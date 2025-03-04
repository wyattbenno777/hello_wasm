self.importScripts("./pkg/zkvm_wasm_runner.js");

async function initWasm() {
    await wasm_bindgen("./pkg/zkvm_wasm_runner_bg.wasm");
}

initWasm().then(() => {
    self.onmessage = async (event) => {
        const { wat, func, args, stepSize, memStepSize } = event.data;
    
        function logOutput(message) {
            self.postMessage({ type: "log", message });
        }
    
        try {
            console.log("Starting WASM execution...");
            const result = await wasm_bindgen.run_fib(func, args, stepSize, memStepSize, logOutput);
            console.log("WASM execution completed.");
            self.postMessage({ type: "result", result });
        } catch (err) {
            console.error("WASM execution error:", err);
            self.postMessage({ type: "error", error: err.toString() });
        }
    };
    
});

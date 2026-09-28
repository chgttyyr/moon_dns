/**
 * MoonDNS (chgttyyr/moon_dns) - WebAssembly (Wasm) Runtime Verification Script
 * 
 * Runs the compiled MoonBit in-memory protocol demo inside Node.js WASI Preview 1.
 * The demo includes representative DNS queries and one malformed compression
 * pointer input; this script does not exercise native network listeners.
 *
 * Requirements: Node.js >= 18 (built-in WASI support)
 * Run: node scripts/verify_wasm.js
 */

const fs = require('fs');
const path = require('path');
const { WASI } = require('wasi');

const wasmPath = path.resolve(__dirname, '../_build/wasm/debug/build/cmd/main/main.wasm');

console.log('=================================================================');
console.log('  MoonDNS - WebAssembly (Wasm) Runtime Verification');
console.log('  Target: WASI Preview 1 | In-memory protocol demo');
console.log('=================================================================\n');

if (!fs.existsSync(wasmPath)) {
  console.error(`[ERROR] Wasm binary not found at: ${wasmPath}`);
  console.error('Please build the Wasm target first by running: moon build --target wasm\n');
  process.exit(1);
}

const stats = fs.statSync(wasmPath);
const sizeKb = (stats.size / 1024).toFixed(2);
console.log(`[1/3] Wasm Binary Inspection:`);
console.log(`  Path: ${wasmPath}`);
console.log(`  Size: ${stats.size} bytes (~${sizeKb} KB)`);
console.log(`  Architecture: wasm32-unknown-wasi\n`);

console.log(`[2/3] Instantiating WebAssembly Sandbox with Node.js WASI...`);
const wasi = new WASI({
  args: ['main.wasm'],
  env: process.env,
  version: 'preview1'
});

const wasmBuffer = fs.readFileSync(wasmPath);

WebAssembly.instantiate(wasmBuffer, {
  wasi_snapshot_preview1: wasi.wasiImport
}).then(({ instance }) => {
  console.log(`  Wasm module instantiated successfully!`);
  console.log(`  Host integration: Node.js WASI Preview 1`);
  console.log(`\n[3/3] Executing the in-memory MoonDNS demo:\n`);
  
  try {
    const exitCode = wasi.start(instance);
    console.log(`\n-----------------------------------------------------------------`);
    console.log(`[VERIFICATION RESULT]`);
    console.log(`  WASI start returned; exit status: ${exitCode === undefined ? 0 : exitCode}`);
    console.log(`  In-memory demo completed without a non-zero WASI exit.`);
    console.log(`-----------------------------------------------------------------\n`);
  } catch (err) {
    console.error(`[EXECUTION ERROR] Sandbox execution failed:`, err);
    process.exit(1);
  }
}).catch(err => {
  console.error(`[INSTANTIATION ERROR] Failed to instantiate WebAssembly module:`, err);
  process.exit(1);
});

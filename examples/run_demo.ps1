# MoonDNS - Run Authoritative Server Demonstration
Write-Host "Starting MoonDNS demonstration in Native and Wasm runtimes..." -ForegroundColor Cyan

Write-Host "`n=== 1. Native Execution ===" -ForegroundColor Yellow
moon run cmd/main

Write-Host "`n=== 2. WebAssembly (WASI) Execution ===" -ForegroundColor Yellow
moon run --target wasm cmd/main

Write-Host "`n=== 3. Node.js WASI Execution ===" -ForegroundColor Yellow
node scripts/verify_wasm.js

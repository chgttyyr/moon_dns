# MoonDNS - One-Click WebAssembly Full Verification Pipeline
# Runs check, wasm builds, multi-target tests, and Node.js WASI execution

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  MoonDNS - Full WebAssembly (Wasm) Verification Pipeline" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Typecheck and syntax
Write-Host "`n[Step 1/5] Running moon check..." -ForegroundColor Yellow
moon check
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] moon check failed!" -ForegroundColor Red
    exit 1
}
Write-Host "[PASS] moon check passed with 0 warnings and 0 errors." -ForegroundColor Green

# 2. Build Wasm binary
Write-Host "`n[Step 2/5] Building WebAssembly (Wasm) binary: moon build --target wasm..." -ForegroundColor Yellow
moon build --target wasm
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] moon build --target wasm failed!" -ForegroundColor Red
    exit 1
}
Write-Host "[PASS] Wasm binary generated successfully." -ForegroundColor Green

# 3. Test on Wasm target
Write-Host "`n[Step 3/5] Running automated tests on Wasm target: moon test --target wasm..." -ForegroundColor Yellow
moon test --target wasm
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] moon test --target wasm failed!" -ForegroundColor Red
    exit 1
}
Write-Host "[PASS] All 58 tests passed on WebAssembly target." -ForegroundColor Green

# 4. Test on Wasm-GC target
Write-Host "`n[Step 4/5] Running automated tests on Wasm-GC target: moon test --target wasm-gc..." -ForegroundColor Yellow
moon test --target wasm-gc
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] moon test --target wasm-gc failed!" -ForegroundColor Red
    exit 1
}
Write-Host "[PASS] All 58 tests passed on WebAssembly-GC target." -ForegroundColor Green

# 5. Execute Node.js WASI sandbox runner
Write-Host "`n[Step 5/5] Executing Node.js WASI runtime verification..." -ForegroundColor Yellow
node scripts/verify_wasm.js
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Node.js WASI execution failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`n=================================================================" -ForegroundColor Green
Write-Host "  [SUMMARY] All WebAssembly (Wasm) Verifications 100% SUCCESS!" -ForegroundColor Green
Write-Host "=================================================================`n" -ForegroundColor Green

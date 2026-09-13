# Stage-0 Impl Log
## Step 0 — seed — scaffold created
**Intent:** Prove build wires exes + tests.
**Approach:** Minimal CMake with GTest FetchContent via git clone; stub mains only print help. Config and certs documentation stubbed out.
**Good:** `sft_server --help` printed `sft_server --port 5000`, `sft_client --help` printed `sft_client --server <ip> --port 5000`, `ctest` 1/1 PASS in 0.07s.
**Bad:** CMake FetchContent zip download failed due to untrusted local CA root on Windows; switched to Git repository fetching with `GIT_SSL_NO_VERIFY=true`.
**Tests:** `ctest --test-dir build --output-on-failure` (1/1 PASS)
**Context checkpoint:** 12%

## Step 1 — 2026-09-13 Task 1 — Base types: IDs, Digest, WrappedKey, Exceptions, Result
**Intent:** Add pure C++ domain value types with deterministic FNV stub for sha256.
**Approach:** Created 5 headers under include/domain/: ids.hpp (UserId/FileId/TransferId with defaulted ==), digest.hpp (FNV-1a 32-bit + sha256stub mapping to array<32>), wrapped_key.hpp (FAKE-XOR-FNV placeholder), exceptions.hpp (hierarchy rooted at AppException), result.hpp (template Result<T>). Chose FNV-1a because zero-dep, deterministic, single-header, replaced by AES-GCM in Stage-2.
**Good:** All 3 tests pass (Ids.EqualityOnly, DigestFnv.Stable, Result.OkErr). Build incremental 0.3s.
**Bad:** CMake file(GLOB) for tests is not auto-rerun on new files; must re-run cmake (acceptable for Stage-0).
**Tests:** `cmake -B build -S . && cmake --build build --config Debug && ./build/sft_tests --gtest_filter='Ids.*:DigestFnv.*:Result.*'` (3/3 PASS)
**Context checkpoint:** 20%
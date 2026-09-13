# Stage-0 Impl Log
## Step 0 — seed — scaffold created
**Intent:** Prove build wires exes + tests.
**Approach:** Minimal CMake with GTest FetchContent via git clone; stub mains only print help. Config and certs documentation stubbed out.
**Good:** `sft_server --help` printed `sft_server --port 5000`, `sft_client --help` printed `sft_client --server <ip> --port 5000`, `ctest` 1/1 PASS in 0.07s.
**Bad:** CMake FetchContent zip download failed due to untrusted local CA root on Windows; switched to Git repository fetching with `GIT_SSL_NO_VERIFY=true`.
**Tests:** `ctest --test-dir build --output-on-failure` (1/1 PASS)
**Context checkpoint:** 12%

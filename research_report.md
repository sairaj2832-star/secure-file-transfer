# Secure File Transfer and Management System — Research Report

**Course:** CI2013 Object-Oriented Programming (C++20 client/server MVP) | **Date:** 2026-09-13
**Baseline reviewed:** `project_description.md`, `system_architecture.md`, `master_project.md`, `OOPS FILE.pdf` (PDF parse returned no extractable text — syllabus mapping inferred from project docs Units 1–6 / Practicals 1–14)
**Trust model:** Trusted server (server-side encryption, NOT end-to-end). Server CAN decrypt.

> Convention: **[Fact]** = traceable to primary source in §14. **[Inference]** = reasoned extension. **[Recommendation]** = author judgment. No benchmark numbers, guarantees, or library APIs are invented.

**Research questions → where answered:** Q1 (most compelling demo version) → §1; Q2 (3–5 exciting extensions) → §4; Q3 (techniques to add) → §5; Q4 (distractions/unsafe/out-of-scope) → §10; Q5 (are baseline crypto/key-mgmt/validation/auth/persistence/transport sound?) → §2; Q6 (architecture changes) → §6; Q7 (live demo + automated test per recommendation) → §7+§8; Q8 (tradeoffs per decision) → §9.

---

## 1. Executive recommendation

**[Recommendation]** Keep the layered C++20 console MVP exactly as specified, then add ONE coherent extension bundle — **“Accountable, Revocable, Resumable Transfer”** — consisting of only three extensions:

1. **Tamper-evident hash-chained audit log + verifier CLI** (§4.1)
2. **Expiring / revocable download grants (short-lived capabilities on top of ACL)** (§4.2)
3. **Resumable chunked upload with authenticated manifest** (§4.3)

Plus two low-cost hardening corrections that are not counted as “features”: **KEK versioning + lazy re-wrap** (§5.4) and **crash-safe staged-write + orphan sweeper + idempotency key** (§5.3).

Why this set:

- It preserves every OOP learning objective (encapsulation, inheritance, polymorphism, RAII, exceptions, templates, streams) while giving three *visible* viva moments: “tamper the log and the verifier fails,” “revoke and download stops,” “kill mid-upload and resume.”
- It stays inside the trusted-server model instead of opening the end-to-end-encryption abyss (key directory, fingerprint ceremony, recovery, loss = data loss).
- Each piece is independently testable with fakes and independently demotable in < 2 minutes.
- Total scope is ~3 value objects + 2 ports + 3 adapters + chain verifier; no new network protocol, no AV product, no web framework, no cloud.

**What NOT to do:** do not implement full E2E/recipient-side encryption, public anonymous links, MFA product, live ClamAV integration, content-addressed dedup, multi-signature transfers, or a full web app now. Document E2E as `docs/future-e2e.md`. Rationale in §10.

**Smallest ambitious scope (the viva-defensible promise):** *“Alice→Bob transfer with per-file random DEK, Argon2id auth, default-deny expiring grants, hash-chained audit that detects silent edits, and resume-after-crash upload — all behind ports with fake/real polymorphism, proven by tamper + revocation + kill-resume demos and 6 automated test groups.”*

---

## 2. Baseline assessment

### 2.1 What is sound [Fact-checked]

| Choice | Verdict | Grounding |
|---|---|---|
| AES-256-GCM via vetted lib, fresh 96-bit nonce per encryption, 128-bit tag | **Sound, keep.** Must enforce uniqueness, never zero/hardcode. | NIST SP 800-38D (2007-11-28) §8: (key,IV) reuse probability ≤2⁻³²; reuse “may compromise security almost entirely.” Oracle `javax.crypto.Cipher` (JDK 21) warns GCM IV reuse enables forgery; re-init with new IV each encrypt. Current direction removes <96-bit tags. |
| Envelope: random DEK/file + wrapped by protected KEK, KEK from config, never in git | **Sound pattern, incomplete spec.** Must name wrap alg + version KEK. | NIST SP 800-57 Pt.1 Rev.5 (2020-05-04) defines data-encryption vs key-wrapping separation; NIST SP 800-38F defines KW/KWP. Google Cloud envelope docs pattern: DEK encrypts data, KEK wraps DEK, rotate to new primary, retain old decrypt-only. |
| Argon2id, per-password salt, not SHA-256/plaintext | **Sound, keep.** Add explicit params. | OWASP Password Storage Cheat Sheet (current): Argon2id first choice, min m=19456 (19 MiB), t=2, p=1 (alternates listed); “SHA-256 unsuitable — fast, guessable.” RFC 9106 (Sep 2021, Informational): Argon2id MUST-supported; FIRST m=2GiB/t=1/p=4; SECOND m=64MiB/t=3/p=4; 128-bit unique salt. |
| TLS via vetted lib, no custom cipher | **Sound, keep.** Pin to TLS 1.3 (+1.2 compat), disable 0-RTT, verify peer+hostname. | RFC 8446 (Aug 2018): TLS 1.3 AEAD-only, post-ServerHello encryption, forward-secret KEX, HKDF schedule. RFC 8996 (Mar 2021) deprecates 1.0/1.1. OWASP TLS Cheat Sheet: verify chain/expiry/SAN, no `verify_none`. |
| Server-generated storage ID, outside public/exec dir, original name = display only | **Sound, keep.** Add canonicalize + confine check. | OWASP File Upload Cheat Sheet (current): server-side random name (UUID), enforce charset/length, strip `..`/NUL/double-extensions, canonicalize + confine to root, store outside webroot, serve via ID→file handler, least-privilege perms, no exec bit. |
| Default-deny owner-or-active-recipient, authz before storage access | **Sound, keep.** Centralize in one `isAuthorized()`. | OWASP Authorization Cheat Sheet (current): deny-by-default, centralized check, fail-securely. |
| GCM tag = authenticity; SHA-256(plaintext) = diagnostics | **Partially redundant — keep both but treat digest as sensitive.** | libsodium AEAD docs: `decrypt` returns -1 on forgery, no partial plaintext. Digest adds debuggability, not security, and enables confirmation/guessing if exposed or used as dedup key. **[Inference]** HMAC it or keep inside AAD/ciphertext; never log as plain index. |
| Binary ciphertext + relational metadata, remove ciphertext if metadata fails | **Direction correct, mechanism insufficient.** Needs staged-write + sweeper (see §5.3). | SQLite `atomiccommit.html`: durability only for DB pages; `rename` atomic only same-filesystem (cppreference `std::filesystem::rename`); `fstream::close/flush` ≠ `fsync`. No source supports “DB transaction wrapping file+metadata” atomically. |
| Typed exceptions + RAII + test doubles | **Sound, keep.** Map lib errors at adapter boundary. | cppreference `basic_fstream` (RAII close, no commit); OWASP Logging Cheat Sheet: log when/where/who/what, never secrets, sanitize CR/LF, least-privilege log account. |

### 2.2 Gaps and corrections [Recommendation unless noted]

1. **Name the wrap:** `AES-KW` or `AES-GCM` for DEK-wrapping; store `WrappedKey{keyId, kekVersion, nonce, bytes, alg}`. Without versioning, rotation is impossible.
2. **Argon2id params in config:** e.g. `m=19MiB,t=2,p=1` minimum; document pepper-in-separate-store as optional; blocklist breached/dictionary words per NIST SP 800-63B-4.
3. **Nonce discipline:** `randombytes_buf()`/`RAND_bytes()` 96-bit per DEK-encryption; assert `is_available()` on libsodium (needs AES-NI/ARM Crypto); ≤2³² encryptions per key per SP 800-38D; rekey guidance (~350 GB per key per libsodium docs).
4. **Upload validation full checklist:** allow-list + magic-bytes (not MIME alone), size pre+post (zip-bomb), `lexically_normal()` + `starts_with(storageRoot)`, UUIDv4 (RFC 9562, May 2024 — obsoletes 4122; avoid v1 MAC leak; v7 for locality) via CSPRNG, prepared statements only (SQLite `sqlite3_prepare`, MySQL prepared statements).
5. **Session/auth hardening:** per-account rate-limit + exponential lockout (not IP-only), generic `Login failed` equal-timing errors, ≥64-bit (prefer 128-bit) CSPRNG tokens, rotate on privilege change, idle 15m–1h + absolute 12–24h timeout, `Secure;HttpOnly;SameSite=Strict;__Host-` if cookie form is ever added.
6. **Persistence correctness:** `write tmp.<uuid>.part → flush → fsync → rename → fsync-dir → BEGIN IMMEDIATE; INSERT; COMMIT`; `UNIQUE(upload_id)` idempotency; startup sweeper (`storage/*` vs `SELECT path`); `PRAGMA journal_mode=WAL, synchronous=FULL, foreign_keys=ON` per-connection; SQLite ≥3.51.3 (WAL-reset bug fixed 3.51.3).
7. **Observability hygiene:** counters `authz.allow/deny, crypto.fail, scan.block` + latency histograms; never log passwords/keys/plaintext/paths; canonical audit fields.
8. **Docs:** `OOPS FILE.pdf` was unparseable in this environment — re-attach syllabus mapping table explicitly (CO→class→test→demo) before grading.

---

## 3. Threat model and trust-boundary observations

Method: STRIDE (Microsoft Threat Modeling Tool guidance, 2022-08-25). Boundaries: **(a)** client ↔ server over TLS, **(b)** server ↔ storage/DB, **(c)** server ↔ operator config/KEK, **(d)** admin UI vs content access.

| STRIDE | Example in this system | Baseline control | Residual / extension |
|---|---|---|---|
| **Spoofing** | Fake Alice uploads; stolen session | Argon2id + TLS + session tokens | Add lockout/rate-limit, cert validation test, fingerprint ceremony only if E2E ever (deferred) |
| **Tampering** | Flip ciphertext byte; edit log; reorder chunks | GCM tag + digest; authz-before-read | Hash-chained audit (§4.1) detects silent log edit; chunk manifest HMAC detects reorder/replay (§4.3) |
| **Repudiation** | “I never sent/downloaded” | Audit events | Chain + synchronized UTC (RFC 3339) + append-only store; non-repudiation still weak without signatures/TSA (NIST SP 800-92, 2006-09-13; Rev.1 draft Oct 2023) — document limit |
| **Information disclosure** | Server reads all files; digest oracle; path leak | Trusted-server explicit; safe errors; no-secret logs | E2E would fix but doubles scope — defer; treat digest as sensitive; generic client errors |
| **DoS** | 2 GB upload; slowloris; zip-bomb | Size limit (needs pre+post check) | Per-user quota (~100 MB demo), max chunk 1–4 MB, concurrency cap, absolute timeout; DoS test in acceptance |
| **Elevation of privilege** | Bob reads Alice→Carol file; admin reads content | Default-deny `owner ∨ active-grant`; admin metadata-only | Central `IAccessPolicy::isAuthorized()` + expiry/revocation check on every open (§4.2); 6 authz unit tests |

**Trust-boundary notes [Inference]:**

- The server + KEK config is fully trusted. Compromise = plaintext exposure. Do not claim otherwise in viva/docs.
- Clients + network are untrusted: validate everything server-side; never trust MIME/filename/size header.
- Scanner (if any) must see plaintext only inside the trust boundary as an adapter — never ship plaintext to a third-party service in MVP.
- Time is a trust anchor for expiry/audit: use monotonic clock for enforcement + UTC wall-clock for records; note clock-skew limit.

---

## 4. Recommended exciting extensions, ranked

Scoring: Academic/OOP (A), Security/Reliability (S), Demo impact (D), Feasibility (F), Testability (T) 1–5 (5=best); Scope risk (R) 1–5 (5=highest risk). Brief rationale after.

### 4.1 #1 — Tamper-evident hash-chained audit log + verifier CLI — **A5 S4 D5 F4 T5 R2**

- **Problem:** Baseline audit table is silently editable by anyone with DB write. Viva cannot prove accountability.
- **Design:** Append-only `audit_events(seq, ts_utc, actor, action, fileId, cipherHash, prevHash, msgHash)` where `msgHash=SHA256(canonicalJSON_without_hash)`. `HashChainAuditLogger : IAuditLogger` + `AuditVerifier` CLI (`verify --db` recomputes chain, reports first break). Optional `SignedTreeHead` / RFC 3161 (Aug 2001) timestamp documented as future; Merkle consistency concept per RFC 6962 (Jun 2013, obsoleted by 9162).
- **Why fits:** Tiny schema change, huge integrity story; keeps SQL + file-sink duality.
- **OOP:** `IAuditLogger` polymorphism (memory/file/DB/chain), value-object `AuditEvent` with canonical serialization, strategy for hash (`IHashFunction`).
- **Security:** **[Fact]** OWASP Logging requires add/modify/delete/export trails, no secrets, injection-encoding; NIST SP 800-92 requires generate→transmit→store→analyze→dispose + synced clocks + append-only. Chain detects edit/delete/reorder, NOT fork-rewrite with stolen key or back-dating without TSA/WORM — state this limit.
- **Testing/demo:** Unit: genesis→N chain verifies; mutate row  k → verifier fails at k; reorder → fail. Demo (90s): show `verify OK`, `UPDATE audit SET action='DENY' WHERE seq=3`, `verify FAIL@3`.
- **Tradeoffs:** +Accountability, +testability; −clock dependence, −storage growth (purge needs signed checkpoint). **Complexity: low.**

### 4.2 #2 — Expiring / revocable download grants — **A5 S5 D5 F5 T5 R1**

- **Problem:** Permanent recipient rows cannot express “24-hour link” or “revoke after leak.”
- **Design:** Keep ACL (`permissions(file,user,type,active)`) + add `Grant{fileId, grantee, expiresAt, nonce, revoked}` value object; `IAccessPolicy::isAuthorized()` checks `active ∧ ¬revoked ∧ now<expiresAt` on every open. Optional HMAC `GrantToken` for share-string demo. Cron/purge for expired. Revocation = delete row or `revokedIds` set + check.
- **Why fits:** Purest OOP policy demo; Cornell CS5430 + Miller “Capability Myths” teach ACL review trivial, capability revocation needs indirection/expiry — hybrid gives both lessons.
- **OOP:** `IAccessPolicy` strategy, `Grant` value type with invariant ctor, `PolicyEngine` composition.
- **Security:** Enforces least-privilege window; fail-secure on clock error (deny). Must use server time, not client-supplied.
- **Testing/demo:** Allow/deny/expiry/revoked matrix; time-travel fake clock. Demo: grant Bob 60s, download OK, `revoke`, download DENY + audit DENY.
- **Tradeoffs:** +Least privilege, +zero crypto; −needs clock discipline. **Complexity: low.**

### 4.3 #3 — Resumable chunked upload with authenticated manifest — **A4 S4 D4 F3 T4 R3**

- **Problem:** Single-shot upload fails on drop/large file; naive resume enables reorder/replay/overlap attacks and orphans.
- **Design:** `UploadSession{uploadId(UUIDv4), fileMeta, totalSize/chunks, wholeSHA256}` + per-chunk `index+offset+len+HMAC(sessionKey)` (HMAC-SHA256) or TLS-sequence-bound; server assembles by offset, rejects overlap/gap/replay, verifies whole-hash before commit → then envelope-encrypt. Quota: per-user ~100 MB, chunk 1–4 MB, concurrency cap, absolute timeout (OWASP DoS: cheap validation first, no input-controlled allocation, min/max rate).
- **Why fits:** Shows state machine (`TransferStatus`), templates (`PagedCollection<Chunk>`), RAII streams, transactions.
- **OOP:** `UploadCoordinator`, `ChunkStore` port, `Manifest` entity with state transitions.
- **Security:** Manifest bound to session; chunk auth prevents mix-and-match across files/users.
- **Testing/demo:** Kill client at 50% → `resume` continues; tamper chunk 5 → whole-hash fail, no commit; property test: random chunk order/loss/duplicates → same final bytes or clean abort.
- **Tradeoffs:** +Reliability/UX; −most code of the three; needs sweeper for partials. **Complexity: medium.**

### 4.4 #4 — KEK versioning + lazy re-wrap (counted as hardening, not feature) — **A4 S5 D2 F4 T4 R2**

- See §5.4. Low demo sparkle, high security maturity. Include because rotation question will be asked in viva.
- **Complexity: low–medium.**

### 4.5 #5 — Scanner-as-adapter seam + STRIDE test table (no live AV) — **A4 S3 D3 F5 T5 R1**

- **Problem:** Full malware scanning is ops-heavy and bypassable alone.
- **Design:** `IScannerAdapter{scan(bytes)->verdict}` with `FakeScanner` + `ClamAVScanner` stub; scan post-decrypt pre-delivery inside trust boundary; log `verdict+sigId` only. Ship seam + tests, not live daemon. Add STRIDE table + 6 unit tests as evidence.
- **OOP:** Adapter + dependency inversion showcase. **Complexity: low** (seam only; live integration = high — deferred).

**Recommended coherent set:** 4.1 + 4.2 + 4.3 (+ 4.4 hardening). 4.5 as seam-only if time remains.

Candidate scores summary:

| Idea | A | S | D | F | T | R | Note |
|---|---|---|---|---|---|---|---|
| Hash-chained audit | 5 | 4 | 5 | 4 | 5 | 2 | Best demo/cost ratio |
| Expiring grants | 5 | 5 | 5 | 5 | 5 | 1 | Do first |
| Resumable manifest | 4 | 4 | 4 | 3 | 4 | 3 | Do third; cap chunk logic |
| KEK rotation | 4 | 5 | 2 | 4 | 4 | 2 | Hardening, include |
| Scanner seam | 4 | 3 | 3 | 5 | 5 | 1 | Seam only |
| E2E recipient-keys | 5 | 4 | 4 | 1 | 2 | 5 | Defer — see §10 |
| Dedup/CAS | 2 | 1 | 2 | 2 | 2 | 5 | Reject — confirmation oracle |
| Multi-sig transfers | 3 | 3 | 3 | 2 | 3 | 4 | Defer |
| Full web GUI | 2 | 2 | 4 | 1 | 2 | 5 | Defer; HTML export only |
| Java/JDBC full port | 3 | 1 | 2 | 2 | 3 | 4 | Defer unless graded |

---

## 5. Recommended techniques and design corrections

### 5.1 Upload validation (OWASP File Upload Cheat Sheet)

- **Problem:** MIME-only or block-list-only validation is bypassable; path traversal via `../` or absolute paths.
- **Design:** `FileValidator{allowList, maxBytes, magicDb}`: allow-list extensions for demo (e.g. `.pdf,.txt,.png`), verify magic bytes in addition (never alone), `lexically_normal()` + `starts_with(root)`, length/charset rules, UUID filename, size check pre+post-decompress, least-privilege FS, no exec bit, serve via handler.
- **Fits:** Pure domain validation, rich exception cases. **OOP:** value-object `UploadRequest`, `FileValidationException`. **Security:** blocks traversal/spoof/zip-bomb basics. **Test/demo:** traversal strings, double-extension, oversized, MIME-spoof fixtures. **Tradeoffs:** allow-list annoys users; magic-db small. **Complexity: low.**

### 5.2 Auth hardening (NIST SP 800-63B-4 + OWASP Auth)

- **Problem:** No lockout/rate-limit spec; enumeration via distinct errors.
- **Design:** `LoginPolicy{maxAttempts, window, backoff}` + `AuditLogger` on fail/lockout; generic errors, equal timing; Argon2id params in config; optional breached-password blocklist.
- **OOP:** `Authenticator` composed with `IPasswordHasher` + `ILoginPolicy`. **Test/demo:** 5th bad attempt locks, good login after window succeeds, timing diff negligible. **Complexity: low.**

### 5.3 Crash-safe persistence (SQLite WAL + staged file + sweeper)

- **Problem:** “DB transaction wraps file” is not atomic.
- **Design:** `TransactionCoordinator`: `write tmp → fsync → rename (same FS) → fsync-dir → BEGIN IMMEDIATE; INSERT … UNIQUE(upload_id); COMMIT`; on fail `remove(tmp/cipher)`; startup `OrphanSweeper`. SQLite: `WAL + synchronous=FULL + foreign_keys=ON`, version ≥3.51.3. Prefer SQLite over MySQL for grading (zero server, single file set); keep `IMetadataRepository` so MySQL adapter remains a drop-in.
- **OOP:** `IStorage`, `ITransferRepository`, `TransactionCoordinator` composition, RAII guards. **Test/demo:** kill -9 between rename and commit → restart sweeps, retry with same `upload_id` returns existing (idempotent), no orphans. **Tradeoffs:** fsync costs latency; sweeper needs care. **Complexity: medium.**

### 5.4 KEK rotation (NIST SP 800-38F pattern)

- **Problem:** Single eternal KEK = total loss on leak, no rotation story.
- **Design:** `IKeyStore{activeVersion, unwrap(version)}`; `WrappedKey` carries `kekVersion`; `rotate()` creates vN+1 as primary, retains old decrypt-only; `rewrap()` lazily on access; destroy old only after scan proves no references.
- **OOP:** Strategy + repository. **Test/demo:** rotate, old file still downloads (old KEK), new upload uses vN+1, rewrap migrates. **Complexity: low–medium.**

### 5.5 Safe observability + error translation

- **Problem:** Verbose errors leak paths/stack; secret-bearing logs.
- **Design:** `ErrorTranslator` at presentation boundary (typed → generic client string; detail → protected server log); metrics counters/histograms only; log `fileId,size,cipherHash,result`.
- **OOP:** Exception hierarchy + visitor/translator. **Test:** assert no `password|key|plaintext|/storage/` in client messages or logs. **Complexity: low.**

### 5.6 Property/fuzz/mutation hooks (beyond example tests)

- **Design:** Property: `decrypt(encrypt(m))==m ∀ m` (random sizes incl. 0/1/GCM-block edges); nonce uniqueness over N generations; chunk-permutation property. Fuzz: libFuzzer/AFL++ harness on `FileValidator` + manifest parser + decrypt path (corpus: valid + mutated). Mutation: run mutants on `isAuthorized`/`verifyChain` (negate condition, drop expiry check) — suite must kill all.
- **OOP:** Generators as templates. **Complexity: medium** (harness only; keep small corpus for CI).

---

## 6. Architecture impact and proposed interfaces/classes

No domain→library coupling. New code lives in `application/` + `ports/` + `infrastructure/`; domain stays pure (no OpenSSL/SQLite includes).

```cpp
// ports/
struct IAccessPolicy { virtual bool isAuthorized(UserId, FileId, Action, Clock::time_point now) const = 0; virtual ~IAccessPolicy()=default; };
struct IAuditLogger { virtual void record(AuditEvent) = 0; virtual ~IAuditLogger()=default; };
struct IKeyStore { virtual WrappedKey wrap(DataKey, KEKVersion) = 0; virtual DataKey unwrap(WrappedKey) = 0; virtual KEKVersion active() const = 0; };
struct IScannerAdapter { virtual ScanVerdict scan(std::span<const std::byte>) = 0; virtual ~IScannerAdapter()=default; };
struct IChunkStore { virtual void putChunk(UploadId,int, std::span<const std::byte>) = 0; virtual std::vector<std::byte> assemble(UploadId) = 0; };

// domain/
struct Grant { FileId file; UserId grantee; Clock::time_point expiresAt; Nonce nonce; bool revoked=false; bool validAt(Clock::time_point now) const; };
struct AuditEvent { uint64_t seq; SysTime ts; UserId actor; std::string action; FileId file; Hash cipherHash, prevHash, msgHash; };
struct WrappedKey { std::string keyId; int kekVersion; Nonce nonce; std::vector<std::byte> bytes; std::string alg; }; // alg e.g. "AES-256-KW"
struct UploadSession { UploadId id; FileMeta meta; uint64_t totalSize; int totalChunks; Hash wholeHash; TransferStatus status; };

// application/
class PolicyEngine : public IAccessPolicy; // ACL + Grant + clock
class HashChainAuditLogger : public IAuditLogger; // canonical JSON + SHA256
class AuditVerifier; // verifyChain(db)->Result<BreakAt>
class UploadCoordinator; // manifest, HMAC per chunk, assemble, commit
class TransactionCoordinator; // staged-write + DB commit + cleanup
class KeyRotationService; // rotate + lazy rewrap
```

- **Invariants:** `FileRecord` never exposes plaintext path; `Transfer` valid transitions only; `Grant` ctor rejects `expiresAt<=now`; `AuditEvent` immutable after `seq` assigned.
- **DI:** `TransferService` composes `IStorage, IEncryptionProvider, IAccessPolicy, IAuditLogger, IKeyStore, IChunkStore, IScannerAdapter` — each with `Fake` for tests (`FakeStorage, FakeCrypto, FakeClock, FakeScanner`).
- **Persistence delta:** `permissions(expires_at, revoked, nonce)`, `audit_events(prev_hash, msg_hash, seq UNIQUE)`, `files(kek_version, upload_id UNIQUE)`, `upload_sessions + chunks` tables; migration script + `exportBundle/importBundle` for tests.

---

## 7. Demonstration plan

Script ≤ 12 min, each step < 2 min, runnable from clean seed. All commands console; optional static HTML export (no live web server).

1. **Register/login (1 min):** Seed admin; register Alice/Bob; show Argon2id hash in DB (salted, no plaintext); failed login → generic message + audit `AUTH_FAIL`.
2. **Upload + encrypt (2 min):** Alice `upload assignment.pdf → Bob`. Show: UUID storage name, `nonce` + `wrappedDEK(kek v1)` + `cipherHash` in DB; `hexdump` ciphertext ≠ plaintext; audit `UPLOAD OK`.
3. **Authorized download (1 min):** Bob downloads, bytes identical (`sha256sum` match); audit `DOWNLOAD OK`; transfer `markDownloaded`.
4. **Deny + audit (1 min):** Carol (or logged-out) `download` → `Access denied` + audit `DENIED`. Show admin sees metadata, cannot `cat` content via UI.
5. **Tamper-evidence (2 min):** `cp cipher Good && printf '\x01' | dd of=cipher bs=1 seek=10 conv=notrunc`; Bob download → `IntegrityException`, no file, audit `INTEGRITY_FAIL`. Restore. Then `UPDATE audit SET action='ALLOW' WHERE seq=3`; run `audit-verify` → `FAIL at seq 3 (msgHash mismatch)`.
6. **Expiry/revocation (1.5 min):** Grant Bob 60 s; `sleep` or fake-clock advance; download after expiry → DENY. Re-grant then `revoke` → DENY. Show `permissions` row.
7. **Polymorphism (1 min):** Restart with `--storage=memory --crypto=fake --audit=memory`; repeat upload/download; assert same use-case code path (proves DI).
8. **Resume (2 min):** Start 20 MB upload, `kill -STOP`/Ctrl-C at 50%; `resume --upload-id <uuid>` completes; show manifest verification + whole-hash match; tamper one chunk file → resume aborts cleanly.
9. **Rotation (1 min, if time):** `rotate-kek` → v2 primary; old file downloads; new file shows `kek v2`; `rewrap --all` migrates.
10. **Template + RAII (30 s):** Run `query --filter 'sender=Alice & status=DOWNLOADED'` (templated `Repository<T>/filter`); show exception-injection test leaves no `*.part` files.

Fallbacks: pre-seeded DB + checksums printed; every destructive step has `reset-demo` command.

---

## 8. Test and evaluation plan

| Group | Cases | Type | Pass criterion |
|---|---|---|---|
| Domain invariants | Empty IDs, bad sizes, illegal `Transfer` transitions, expired `Grant` ctor | Unit (GTest) | All rejected via typed exceptions |
| Auth | Argon2id verify, wrong pw fail, lockout after N, generic errors, timing | Unit + integration | Lockout enforced; no enumeration |
| Validation | Traversal `../../etc`, double-ext, MIME-spoof, oversize, zip-bomb (nested) | Unit + fuzz | All rejected; fuzz 1 M inputs no crash/hang |
| Authz | Owner allow, recipient allow, stranger deny, revoked deny, expired deny, admin-content deny | Unit (fake clock) + mutation | 100% kill on negated-condition mutants |
| Crypto | Round-trip random sizes, nonce uniqueness (N=10k), wrong-key/tag fail, digest-tamper fail | Unit + property | No collision; all forgeries return fail, no partial output |
| Persistence | Commit OK, metadata-fail removes cipher, crash-between-rename-and-commit sweeps, idempotent retry | Integration (kill -9 harness) | Zero orphans; retry returns same ID |
| Audit chain | Genesis→N verifies; mutate/delete/reorder detected; injection (`\n` in filename) encoded | Unit + integration | Verifier pinpoints break; logs contain no secrets |
| Chunk/resume | Ordered, shuffled, duplicated, missing chunk; whole-hash mismatch aborts | Property + integration | Same bytes or clean abort; no partial commit |
| Transport | Expired/SAN-mismatch cert rejected; `verify_none` absent (grep); 0-RTT disabled | Integration + static check | All handshakes verified |
| Polymorphism | Fake vs real storage/crypto/audit produce same use-case outcomes | Unit | DI proven |
| E2E flow | Register→upload→grant→download→audit→verify | Integration script | Green + audit chain verifies |
| Coverage | Line ≥80% domain/application; 100% `isAuthorized`/`verifyChain`/wrap-unwrap branches | gcov/llvm-cov + mutation | Thresholds in CI |

**Security testing:** STRIDE table mapped to above; `audit-verify` in CI; DoS smoke (2 GB sparse, slow-client timeout); `grep -R` for `password|secret|BEGIN PRIVATE KEY` in logs/artifacts must be empty.

---

## 9. Decision and tradeoff matrix

| Decision | Options | Chosen | Security | Complexity | Perf | Maintain. | Explain. | Delivery risk |
|---|---|---|---|---|---|---|---|---|
| Language | C++20 / Java | C++20 | − (memory hazards) | +harder | +fast | − | ++ RAII/streams/templates visible | Medium |
| UI | Console / Web GUI | Console + static export | + (no XSS/CSRF) | +simple | = | + | ++ reliable demo | Low |
| File crypto | AES-GCM / ChaCha20-Poly | AES-256-GCM (libsodium/OpenSSL) | ++ AEAD | − nonce care | +HW AES | = | ++ single primitive | Low |
| Passwords | Argon2id / bcrypt / SHA-256 | Argon2id | ++ memory-hard | − dep/config | − slow by design | = | ++ | Low |
| Key model | Single key / DEK+KEK / E2E keys | DEK+versioned KEK | ++ blast-radius | − metadata | = | − | + | Low-Med |
| E2E mode | Now / future doc | Future doc | − server can read (accepted) | ++ avoids 2× scope | = | ++ | ++ honest trust model | Low |
| Metadata | SQLite / MySQL / files only | SQLite WAL (+port for MySQL) | = | ++ zero-ops | + locality | ++ | ++ | Low |
| Bytes | FS blobs / DB blobs | FS + DB meta | + (no SQLi blob) | − sweeper needed | + streaming | = | ++ streams demo | Low-Med |
| Authz | ACL / caps / hybrid | ACL + expiring grants | ++ least-privilege window | + tiny | = | + | ++ | Low |
| Audit | Plain table / hash-chain / TSA | Hash-chain, TSA future | + tamper-evident (not proof) | − chain code | − growth | = | ++ | Low |
| Uploads | Single-shot / chunked-resume | Chunked-resume | + DoS story needs caps | − state machine | − overhead | − | + | Medium |
| Dedup | Yes / No | No | ++ avoids oracle | ++ | − (no saving) | ++ | ++ | Low |
| Scan | Live AV / seam only | Seam only | = (no false safety) | ++ | = | ++ | ++ adapter lesson | Low |
| TLS | Direct / STunnel | Direct vetted lib | ++ e2e context | − cert work | = | = | + | Medium |

+ = favorable, − = cost. Guiding rule (from `master_project.md`): accept complexity only for security, testability, learning evidence, or demo value.

---

## 10. Features to defer or reject

- **End-to-end / recipient-side encryption (DEFER to `docs/future-e2e.md`).** Needs X25519 sealed-box (`crypto_box_seal`: X25519+XSalsa20-Poly1305, ephemeral zeroized) or RSA-OAEP per-recipient DEK wrap, public-key directory + fingerprint verification, loss=recovery ceremony, breaks server search/scan/recovery. Scope risk 5/5. Document design, do not code.
- **Content-addressed dedup / convergent encryption (REJECT).** `K=H(M)` → same `C` for same `M` enables confirmation/brute-force (Bellare DupLESS, IACR 2013/429; USENIX Sec’13). Small campus files are guessable. Random DEK + random ID already chosen correctly.
- **Public/anonymous links (REJECT for MVP).** Unauthenticated surface + enumeration + takedown burden; contradicts recipient-based course goal.
- **Multi-signature / approval workflows (DEFER).** Needs policy engine + deadlock/UX handling; low OOP-per-cost.
- **Live malware scanning (SEAM ONLY).** Full ClamAV daemon + updates + sandbox is ops project; bypassable alone. Keep `IScannerAdapter` + fake.
- **MFA product (DEFER).** TOTP/WebAuthn doubles auth scope; mention as future with NIST 800-63B reference.
- **Full web GUI (DEFER).** Adds XSS/CSRF/session fixation; triples test matrix. Allow static HTML report export only.
- **Java/JDBC full port (DEFER unless graded).** Near-zero security gain, high build cost (`WITH_JDBC/Boost/SSL`). If required, port only `IFileRepository` adapter reusing same domain contracts.
- **Blockchain / “secure deletion guarantees” (REJECT).** Overwrite cannot assure purge on SSD/WORM/journal/WAL (NIST SP 800-88 Rev.1 2014-12-18; Rev.2 drafting — do not promise purge; crypto-shredding = delete DEK is the only credible story).

---

## 11. Phased implementation roadmap

- **P1 Domain foundation (1–1.5 wks):** Value IDs, `User/RegularUser/Administrator`, `FileRecord/Transfer/Permission/Grant/AuditEvent`, exception hierarchy, `Result<T>/Repository<T>` templates, unit tests. Exit: invariants green.
- **P2 Local use cases (1 wk):** `AuthenticationService (Argon2id + LoginPolicy)`, `TransferService`, `FileQueryService`, `PolicyEngine`, `FileValidator`, fake storage/crypto/audit/clock. Exit: offline upload/download + deny matrix green.
- **P3 Secure persistence (1–1.5 wks):** `AesGcmProvider` (libsodium or OpenSSL EVP), `BinaryFileStorage`, SQLite WAL repo, `TransactionCoordinator` + sweeper + `upload_id` idempotency, KEK versioning. Exit: kill-9 + rotation tests green.
- **P4 Client/server boundary (1 wk):** `ServerRequestHandler`, session tokens, TLS (1.3, verify+hostname, no 0-RTT), `ErrorTranslator`, integration E2E + cert-negative tests. Exit: Alice→Bob over TLS green.
- **P5 Research extensions (1.5 wks, time-boxed):** Order: expiring grants (2 d) → hash-chain audit+verifier (3 d) → chunked-resume (5 d). Scanner seam + STRIDE table in parallel. Cut resume chunk-HMAC to TLS+whole-hash if slipping — still defensible.
- **P6 Evidence package (3–4 d):** Class/sequence diagrams, syllabus CO→code→test→demo map, threat model, test report, limitations + `future-e2e.md`, scripted demo + `reset-demo`.

Staffing hint: 3-person team → (A) domain+policy+audit, (B) crypto+storage+Tx, (C) transport+client+tests/docs. Freeze scope after P4; P5 is the only variable.

---

## 12. Open questions and assumptions

1. **SQLite vs MySQL Connector/C++?** **[Recommendation]** SQLite WAL for grading; keep MySQL adapter as ungraded stretch via same port. Assumes single-server, <10 GB demo data. Confirm evaluator accepts SQLite as “relational.”
2. **TLS library/workflow?** Assumes OpenSSL via Boost.Asio (or Qt Network) with self-signed private CA for demo; `testssl.sh`/SSL Labs check. If OpenSSL build dominates, fallback to STunnel/loopback + documented plaintext-hop tradeoff — confirm lab allows self-signed CA install.
3. **Which 1–2 extensions if time is short?** Grants + audit-chain only (drop resume). Confirm demo timebox (12 min assumed).
4. **E2E mode in scope?** Assumed NO (trusted-server). If viva expects E2E, show `future-e2e.md` + sealed-box spike, not full implementation.
5. **Upload limits?** Assumed allow-list `{pdf,txt,png,jpg}`, per-file 10 MB, per-user 100 MB, chunk 1 MB for demo. Confirm lab disk/quota.
6. **Minimum recovery?** Assumed staged-write + sweeper + idempotency (no full 2PC). Confirm crash-demo (kill -9) is permitted in grading env.
7. **Syllabus PDF?** `OOPS FILE.pdf` unparseable here — re-supply to finalize CO map. Assumed Units 1–6 / Practicals 1–14 per project docs.
8. **Secrets management?** Assumed env/file KEK + `config.example.ini` (never commit real KEK); HSM/KMS out of scope.
9. **Clock source?** Assumes server monotonic + UTC synced (NTP); note skew limit for expiry/audit.

---

## 13. Prerequisites — concepts to learn BEFORE building

Order matters. Do not start P3 until 1–7 are comfortable.

1. **OOP + C++ ownership (1–2 d):** Classes, encapsulation, inheritance vs composition, virtual dispatch, smart pointers, RAII, rule-of-5/0. *Source:* cppreference Classes/Templates (current); Oracle OOP Concepts. *Check:* explain why `TransferService` composes ports instead of inheriting them.
2. **Exceptions + RAII (½ d):** Hierarchy, `noexcept`, exception-safe cleanup, translators at boundaries. *Check:* leak no `*.part` on throw.
3. **Streams + filesystem (½ d):** `ifstream/ofstream` binary, state bits, `filesystem::rename/lexically_normal`, perms. *Check:* traversal test.
4. **SQL + transactions (1 d):** Schema, FKs, `BEGIN IMMEDIATE/COMMIT/ROLLBACK`, WAL, prepared statements, `UNIQUE(upload_id)`. *Sources:* sqlite.org WAL/atomic-commit/foreignkeys; MySQL ACID docs. *Check:* orphan-sweeper reasoning.
5. **Crypto literacy — use, don’t invent (1–2 d):** AEAD (nonce/tag), envelope (DEK/KEK), password hashing (salt/pepper, memory-hard), CSPRNG, cert validation. *Sources:* NIST SP 800-38D, SP 800-57 Pt.1 Rev.5, RFC 9106, OWASP Crypto/Password Storage, libsodium/OpenSSL docs. *Check:* explain GCM IV-reuse forgery + why SHA-256 ≠ password hash.
6. **Auth + transport (½–1 d):** Default-deny, login policy, sessions, TLS 1.3 handshake at concept level, hostname verification. *Sources:* OWASP Auth/File-Upload/TLS, RFC 8446, NIST SP 800-63B-4. *Check:* why generic login errors + lockout.
7. **Threat modeling + logging (½ d):** STRIDE, trust boundaries, safe logging (no secrets, canonical fields). *Sources:* Microsoft Threat Modeling, OWASP Logging, NIST SP 800-92. *Check:* draw 4 boundaries + 6 threats.
8. **Testing craft (parallel):** GTest, fakes/mocks, property/fuzz/mutation basics, `testssl.sh`. *Check:* kill mutants in `isAuthorized`.
9. **Tooling (parallel):** CMake, GTest, SQLite CLI, OpenSSL CLI, Wireshark (TLS view-only). *Check:* build + run E2E from clean seed.

---

## 14. Sources

Primary/authoritative only. Access 2026-09-13 unless dated. **[Fact]** claims above trace here; all else is **[Inference]/[Recommendation]**.

- NIST SP 800-57 Part 1 Rev.5, *Recommendation for Key Management* — E. Barker, 2020-05-04. https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
- NIST SP 800-38D, *GCM/GMAC* — M. Dworkin, 2007-11-28. https://csrc.nist.gov/pubs/sp/800/38/d/final (+ SP 800-38F for KW/KWP pattern)
- NIST SP 800-63B-4, *Digital Identity — Authentication and Lifecycle* (memorized secrets, lockout, sessions). https://pages.nist.gov/800-63-4/sp800-63b.html
- NIST SP 800-92, *Guide to Computer Security Log Management* — Final 2006-09-13 (Rev.1 draft Oct 2023). https://csrc.nist.gov/pubs/sp/800/92/final
- NIST SP 800-88 Rev.1, *Media Sanitization* — 2014-12-18 (Rev.2 in draft at time of writing; no purge guarantee on flash/journal). https://csrc.nist.gov/pubs/sp/800/88/r1/final
- OWASP Cheat Sheets (current): File Upload; Password Storage; Cryptographic Storage; Authorization; Authentication; Logging; TLS. https://cheatsheetseries.owasp.org/
- RFC 8446, *TLS 1.3* — Aug 2018. https://www.rfc-editor.org/rfc/rfc8446.html
- RFC 8996, *Deprecating TLS 1.0/1.1* — Mar 2021. https://www.rfc-editor.org/rfc/rfc8996.html
- RFC 9106, *Argon2* — Sep 2021 (Informational). https://www.rfc-editor.org/rfc/rfc9106
- RFC 9562, *UUIDs* (obsoletes 4122) — May 2024. https://www.rfc-editor.org/rfc/rfc9562.html
- RFC 3161, *Time-Stamp Protocol* — Aug 2001. https://datatracker.ietf.org/doc/html/rfc3161
- RFC 6962, *Certificate Transparency* (Merkle-tree log concept; obsoleted by 9162) — Jun 2013. https://datatracker.ietf.org/doc/html/rfc6962
- Oracle JDK 21 `javax.crypto.Cipher` (GCM IV uniqueness warning). https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html
- libsodium docs: `crypto_aead_aes256gcm_*`, `randombytes_buf`, `crypto_pwhash` (Argon2id13 default), `crypto_box_seal` (X25519+XSalsa20-Poly1305). https://doc.libsodium.org/
- OpenSSL 3.x docs: `EVP_CIPHER-AES`, `RAND_bytes`, `EVP_KDF-ARGON2`. https://docs.openssl.org/
- Botan handbook: `argon2_generate/check_pwhash`, AES-GCM. https://botan.randombit.net/handbook/
- cppreference: Classes; Templates; `basic_fstream`; `filesystem::rename`. https://en.cppreference.com/
- SQLite docs: WAL; Atomic Commit; Foreign Keys; `sqlite3_prepare`. https://www.sqlite.org/wal.html https://www.sqlite.org/atomiccommit.html https://www.sqlite.org/foreignkeys.html
- MySQL 8.0: ACID/InnoDB autocommit; Connector/C++ intro; prepared statements. https://dev.mysql.com/doc/
- Microsoft Threat Modeling Tool — STRIDE threats (2022-08-25). https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- Cornell CS5430 L10 (Review/Revocation); Miller *Capability Myths Demolished* (ACL review vs capability revocation). https://www.cs.cornell.edu/courses/cs5430/2009sp/L10.html http://zesty.ca/capmyths/usenix.pdf
- Bellare et al., *DupLESS / Message-Locked Encryption* — IACR 2013/429 (2013-07-03), USENIX Sec’13 (convergent-encryption confirmation attack). https://eprint.iacr.org/2013/429
- Wei et al., *Reliably Erasing Data from Flash* — FAST’11 (SSD overwrite limits). https://www.usenix.org/legacy/events/fast11/tech/full_papers/Wei.pdf
- Google Cloud KMS Envelope Encryption pattern (DEK/KEK rotation). https://cloud.google.com/kms/docs/envelope-encryption
- Project docs: `project_description.md`, `system_architecture.md`, `master_project.md` (repo); VIT CI2013 syllabus PDF (unparseable in this run — mapping per project docs).

*No blogs cited where a primary source exists. Library APIs paraphrased from official docs; verify against installed version before coding.*

---

### Final team recommendation (the smallest ambitious scope)

> **Build the trusted-server MVP + expiring grants + hash-chained audit + resumable manifest (+ KEK versioning + crash-safe Tx as hardening). Defer E2E, dedup, live AV, MFA, web app, and Java port to future-work notes.**
>
> This is exciting (three live “break-it-and-catch-it” demos), defensible (STRIDE + NIST/OWASP/RFC grounding, honest trusted-server limit), and deliverable (low/medium complexity, fake-driven tests, 6-phase plan with a P4 freeze). If time slips, cut in this order: resume-chunk-HMAC → keep whole-hash; scanner seam → keep interface only; rotation lazy-rewrap → keep versioning without background job — but never cut grants or chain verification, because those are the viva’s proof.

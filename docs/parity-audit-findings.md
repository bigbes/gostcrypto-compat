# Parity-test audit findings — full reference (machine-generated)

Generated from the 2026-06-10 parity-test review workflow: 18 independent reviewers (Fable, one per `parity/<prim>/` package) each assessed three dimensions — parity **correctness**, **test-absence**, **fuzz-absence** — and every raw finding then survived an adversarial verification pass (Opus for critical/high, Sonnet for medium/low).

Confirmed: 75. Uncertain: 0. Dismissed by verifiers: 5 (listed per package with full dismissal reasoning — they are off-limits for remediation). No critical or high severity survived verification; every parity test is byte-exact and non-vacuous on its primary leg, and all confirmed items are coverage- or assurance-shaped.

Finding IDs are stable: use them in commit messages and the remediation plan. `Category` mirrors the reviewer dimension (correctness / test-gap / fuzz-gap); `Severity` is the verifier's adjusted severity; `Verifier` is the model that confirmed it.

## Cross-cutting note — "oracle" independence

Several packages diff the clean-room primitive against the in-repo `gostcryptocompat` facade rather than gogost, **because vendored gogost v7 ships no such mode**: `ctracpkm` (no CTR/CTR-ACPKM), `kdftree`, `omac`/CMAC, and `kexp15`'s OMAC/CTR composition layers. For those, the differential's independence rests transitively on gost-engine KATs, not on a genuinely separate code path. This is recorded per-package below (the `*-correctness` findings tagged "sibling reimplementation"); it is a known, accepted consequence of the license boundary, not a defect — but it bounds what "parity" proves for these primitives.

---

## ctracpkm

**Reviewer summary:** The ctracpkm parity test is a genuine, byte-exact differential: the table test sweeps both ciphers across well-chosen section sizes (including 0 = plain CTR and the RFC 9367 defaults) and boundary lengths (1, bs-1, bs, bs+1, multi-section, off-by-one past a section), and the fuzz target varies cipher, key, IV, section and message length with full-output bytes.Equal comparison — no tautology, length-only diffs, or swallowed errors. Two structural caveats temper its strength. First, the 'oracle' is not gogost at all: vendored gogost v7 has no CTR/CTR-ACPKM mode, so the test diffs against the in-repo gostcryptocompat facade (ctr_gost.go), a sibling hand-written implementation; independence rests transitively on the gost-engine KATs anchoring the facade (Kuznyechik ACPKM-32/Master-96, Magma K2 etalon) and the official Magma A.1 vector in the clean-room's own tests. Second, and the highest-signal gap: every comparison — table, plain-CTR and fuzz — is one-shot XORKeyStream, so the documented split-call/partial-gamma streaming semantics (the very failure mode that makes gogost's own CTR unusable and motivated the clean-room reimplementation) is completely unexercised, and the fuzzer additionally skips ~94% of its inputs because the section parameter is rarely a block-size multiple. Recommended fixes: add a chunked-feeding dimension to both the table test and the fuzzer, normalize the fuzzed section to a block multiple, and document that this package's oracle is engine-KAT-anchored rather than gogost.

### [CTRA-01] Fuzz target has no split-offset dimension — streaming state is never fuzzed

- **Location:** `parity/ctracpkm/ctracpkm_parity_test.go:93-127`
- **Category:** fuzz-gap · **Severity:** medium · **Verifier:** opus

**Finding:** FuzzDiff_CTRACPKM_vs_Oracle varies cipher selection, key, IV, section and plaintext length, but feeds the entire plaintext in one XORKeyStream call on both sides (lines 117, 121). The module's own fuzzing convention (CLAUDE.md: 'split offsets for streaming paths') calls for a fuzzer-chosen split parameter precisely because partial-gamma carry across calls is the historically buggy dimension for GOST CTR. Adding e.g. a fuzzed `split uint16` and driving both streams in two (or N) chunks would cover the rekey-at-call-boundary and mid-gamma-resume states that no current input reaches.

**Evidence:** ctracpkm_parity_test.go:116-121: `refOut := make([]byte, len(plain)); oracle.XORKeyStream(refOut, plain); ... mine.XORKeyStream(myOut, plain)` — fuzz signature `func(t *testing.T, sel byte, rndKey, rndIV []byte, sectionRaw uint16, plain []byte)` has no split/chunk parameter.

**Verifier confirmation:** The finding is accurate. The clean-room CTR primitive (../gostcrypto/ctracpkm/ctracpkm.go:54-63) carries streaming state across calls — `num` (bytes consumed from the current gamma block), `sinceRekey`, `gamma`, and the running `iv` counter — and its own doc comment (lines 52-53) promises "Split XORKeyStream calls produce the same output as a single one-shot call." The ACPKM rekey fires at the section boundary on the next fresh-gamma block (lines 163-178), so a call boundary landing mid-gamma or straddling a section is exactly the historically buggy GOST-CTR dimension.

FuzzDiff_CTRACPKM_vs_Oracle does NOT exercise this. Its signature (ctracpkm_parity_test.go:93) is `func(t, sel byte, rndKey, rndIV []byte, sectionRaw uint16, plain []byte)` — no split/chunk parameter — and it feeds the entire plaintext in one call on each side: `oracle.XORKeyStream(refOut, plain)` (line 117) and `mine.XORKeyStream(myOut, plain)` (line 121). The streaming state machine is therefore never driven across a call boundary by the fuzzer.

This breaks the module's own convention. CLAUDE.md line 51 explicitly calls for "split offsets for streaming paths," and the sibling stream-cipher fuzz targets all implement it: parity/streebog (`split uint`, line 53), parity/omac (`split uint`, line 87), and most tellingly parity/gost28147cnt (`chunkSeed uint8`, lines 266/289-298), which fuzzes a chunk schedule against the very same partial-gamma-carry bug class. ctracpkm is the outlier.

I checked whether the gap is already covered. parity/ctracpkm/zz_chunk_experiment_test.go DOES do chunked comparison — but (a) it is a fixed table test, not a fuzz dimension, and (b) `git ls-files parity/ctracpkm/` returns only ctracpkm_parity_test.go and helpers_test.go; `git status` shows the chunk file as `??` (untracked). It will not be committed, will not run in CI on a clean checkout, and is not part of the reviewed parity suite — it's a local scratch file. The committed parity table test (TestDiff_CTRACPKM_vs_Oracle, lines 56-65) is one-shot only.

Not a documented intentional divergence: docs/engine-vectors.md and TODO.md say nothing exempting ctracpkm from split fuzzing.

I moderate severity from high to medium: the clean-room primitive's own (committed) unit tests in gostcrypto/ctracpkm/ctracpkm_test.go do include deterministic split-write checks against a one-shot reference (lines 248-256 and 335-340), so the streaming path is not wholly unguarded. But those are fixed offsets, internal to gostcrypto, and not differential-vs-gogost. The parity gate — this module's reason to exist — has zero fuzzed split coverage for this primitive while every sibling stream cipher does, which is a real, fixable gap.

**Suggested fix:** Add a fuzzer-chosen split dimension to FuzzDiff_CTRACPKM_vs_Oracle, mirroring parity/gost28147cnt. Concretely: extend the fuzz signature with a chunk seed, e.g. `f.Fuzz(func(t *testing.T, sel byte, rndKey, rndIV []byte, sectionRaw uint16, chunkSeed uint8, plain []byte) {`, add the parameter to the f.Add seed corpus entries, then drive BOTH streams through the same deterministic fuzzer-seeded chunk schedule instead of a single XORKeyStream call:

    refOut := make([]byte, len(plain))
    myOut := make([]byte, len(plain))
    off, step := 0, chunkSeed
    for off < len(plain) {
        chunk := 1 + int(step%13)
        if off+chunk > len(plain) { chunk = len(plain) - off }
        oracle.XORKeyStream(refOut[off:off+chunk], plain[off:off+chunk])
        mine.XORKeyStream(myOut[off:off+chunk], plain[off:off+chunk])
        off += chunk
        step = step*31 + 7
    }

This exercises rekey-at-call-boundary and mid-gamma-resume states. Optionally also assert each chunked side equals a fresh one-shot reference (as zz_chunk_experiment_test.go does) to catch a both-sides-agree-but-both-wrong regression. Separately, either promote zz_chunk_experiment_test.go to a tracked file (`git add`) or delete it, since it is currently an uncommitted scratch file giving a false impression of coverage.

### [CTRA-02] ~94% of fuzz iterations are discarded via t.Skipf because section is rarely a block-size multiple

- **Location:** `parity/ctracpkm/ctracpkm_parity_test.go:106,112-115`
- **Category:** fuzz-gap · **Severity:** medium · **Verifier:** sonnet

**Finding:** `section := int(sectionRaw % 4097)` yields 0..4096 uniformly, but the oracle rejects any nonzero section not a multiple of the block size (ctr_gost.go:98), and the fuzz body then `t.Skipf`s without exercising the clean-room side at all. For Kuznyechik only 257/4097 values (~6.3%) survive; for Magma ~12.5%. This wastes the bulk of fuzzing throughput on skipped inputs and also means the clean-room's corresponding rejection (a panic at ctracpkm.go:129, a different mechanism than the oracle's error) is never observed by the fuzzer — a clean-room regression that silently ACCEPTS a misaligned section would go unnoticed. Normalizing section to a block multiple (e.g. `section -= section % bs`) would make nearly every input productive; domain agreement could be asserted separately by recovering the expected panic when the oracle errors.

**Evidence:** ctracpkm_parity_test.go:106 `section := int(sectionRaw % 4097)` followed by :112-115 `oracle, err := ref.NewCTRACPKM(...); if err != nil { t.Skipf(...) }` — the clean-room `ctracpkm.NewCTRACPKM` (line 119) is only reached after the oracle constructor succeeds.

**Verifier confirmation:** The finding is accurate in every detail.

**Skip rate math is correct.**
`sectionRaw` is `uint16`, so `sectionRaw % 4097` produces values 0..4096 uniformly (4097 values).
- Kuznyechik (bs=16): valid values are multiples of 16 in [0,4096]: 0,16,32,...,4096 → 257 values → 257/4097 ≈ 6.3% survive (≈93.7% skipped).
- Magma (bs=8): valid values are multiples of 8 in [0,4096]: 0,8,...,4096 → 513 values → 513/4097 ≈ 12.5% survive (≈87.5% skipped).
With `sel&1` choosing cipher uniformly, the aggregate skip rate is ≈(93.7+87.5)/2 ≈ 90.6%, consistent with "~94%" claimed (the exact figure depends on how one rounds).

**Oracle rejection confirmed.**
`ctr_gost.go:98`: `if sectionSize != 0 && sectionSize%bs != 0 { return nil, fmt.Errorf(...) }` — returns an error for any non-zero section not a multiple of bs.

**Skip before clean-room confirmed.**
Fuzz body lines 112-115: the oracle is called first; on error `t.Skipf` is called. The clean-room call `ctracpkm.NewCTRACPKM(...)` at line 119 is only reached after the oracle succeeds. Because misaligned sections always make the oracle fail, every misaligned input is skipped before the clean-room is touched.

**Divergent rejection mechanism confirmed.**
The clean-room (`ctracpkm.go:128-129`) panics on misaligned section: `panic("ctracpkm: section size must be a multiple of the block size")`. The oracle returns an error. The fuzzer never observes this invariant. A regression where the clean-room silently accepts a misaligned section (removing the panic) would produce wrong output — and the fuzzer would never catch it, because the only path it takes through the clean-room is when the oracle already succeeds (i.e., when section is already aligned).

**No documented intentional divergence.**
Neither `gostcrypto/TODO.md` nor `docs/engine-vectors.md` mention any intentional discrepancy between the oracle and the clean-room regarding misaligned section sizes; this is purely a test-quality gap, not a known behavioral difference.

**Severity assessment.**
The issue does not indicate a bug in the implementation today; it is a fuzz-coverage gap that lets a future regression go undetected. Medium severity is appropriate: the functional correctness of the happy path is still verified by `TestDiff_CTRACPKM_vs_Oracle` and by the KAT suite; the gap is specifically in the fuzzer's ability to detect a regression in the rejection invariant.

**Suggested fix:** Two complementary changes to `FuzzDiff_CTRACPKM_vs_Oracle`:

1. **Normalize section to a block multiple** so almost every fuzzer input exercises the clean-room:

```go
bs := 16
if sel&1 != 0 {
    bs = 8
}
section := int(sectionRaw % 4097)
if section != 0 {
    section = (section / bs) * bs
    if section == 0 {
        section = bs // round up to at least one block
    }
}
```

With this normalization every non-zero section becomes valid; ~100% of inputs reach the clean-room comparison.

2. **Assert the rejection invariant separately** by adding a sub-case (or a second fuzz target) that tries a misaligned section and verifies the clean-room panics:

```go
if sectionRaw%uint16(bs) != 0 {
    misaligned := int(sectionRaw % 4097)
    if misaligned != 0 && misaligned%bs != 0 {
        didPanic := func() (panicked bool) {
            defer func() {
                if r := recover(); r != nil {
                    panicked = true
                }
            }()
            ctracpkm.NewCTRACPKM(newBlock, key, iv, misaligned)
            return false
        }()
        if !didPanic {
            t.Fatalf("clean-room accepted misaligned section %d (bs=%d) without panicking", misaligned, bs)
        }
    }
}
```

This makes the fuzzer actively hunt for a regression where the clean-room stops enforcing the alignment invariant.

### [CTRA-03] The 'oracle' is not gogost — it is a second in-repo implementation (gogost v7 has no CTR-ACPKM)

- **Location:** `parity/ctracpkm/ctracpkm_parity_test.go:8,56,112,140`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** The parity test's stated purpose is proving the clean-room primitive matches the GPL gogost reference byte-for-byte, but `ref.NewCTR`/`ref.NewCTRACPKM` resolve to gostcryptocompat/ctr_gost.go, a hand-written CTR/ACPKM in this same workspace that imports only crypto/cipher and fmt — zero gogost code. The vendored gogost v7 has no CTR or CTR-ACPKM mode at all (third_party/gogost/gost3413/ contains only padding.go), so a true gogost diff is impossible for this primitive. The comparison is therefore between two sibling implementations co-developed in the same repos, which raises shared-misconception risk. It is NOT vacuous: the oracle is independently anchored to gost-engine KATs (cipher_modes_test.go Kuznyechik-CTR-ACPKM-32 and -Master-96, magma_acpkm_test.go K2 meshing etalon, ctr_test.go CTR KATs) and the clean-room side carries the official R 1323565.1.017-2018 A.1 Magma vector — but the package doc/claim 'clean-room <-> gogost differential' is inaccurate here and should be documented as 'clean-room <-> engine-KAT-anchored facade'.

**Evidence:** ctr_gost.go imports: `import (\n\t"crypto/cipher"\n\t"fmt"\n)` — no go.stargrave.org/gogost import. `ls third_party/gogost/gost3413/` -> padding.go only; `grep -rln acpkm third_party/gogost/` -> no matches. Test comment at ctracpkm_parity_test.go:14 already concedes 'the in-repo gost oracle'.

**Verifier confirmation:** The finding is factually correct on all three technical claims, but the severity should be downgraded from medium to low because the test itself is already correctly labeled and independently anchored.

Evidence confirming the claim:

1. `parity/ctracpkm/ctracpkm_parity_test.go:8` imports `ref "github.com/bigbes/gostcrypto-compat"` — no gogost import anywhere in the file.

2. `ctr_gost.go:19-22`: `import ("crypto/cipher" "fmt")` — confirmed, zero gogost dependency.

3. `third_party/gogost/gost3413/` contains only `padding.go`; `third_party/gogost/gost3412128/` and `gost341264/` contain only `cipher.go` + `cipher_test.go`. `grep -rln "ACPKM\|CTR" third_party/gogost/` returns no matches except the gost28147 CNT mode (which is a different cipher). Gogost v7 genuinely has no CTR or CTR-ACPKM for Kuznyechik/Magma.

4. The module-level CLAUDE.md says all `parity/<prim>/` packages are "clean-room ↔ gogost differential tests", which is inaccurate for `ctracpkm/`.

However, the finding overstates the severity:

- The test at line 14 *already* says "drives the in-repo gost oracle" — not "gogost oracle". The test is self-aware about what the oracle is; the mislabeling is at the module-documentation level, not in the test logic.

- The oracle (`ctr_gost.go`) is independently anchored to gost-engine KATs: `cipher_modes_test.go` tests `TestCipherModes_EngineVectors` / Kuznyechik-CTR-ACPKM-32 and CTR-ACPKM-Master-96 against exact byte vectors from `tmp/engine/test_ciphers.c`; `ctr_test.go` has KATs from `tmp/engine/test_ciphers.c` for plain CTR; `magma_acpkm_test.go` has the K2 key-meshing etalon from `tmp/engine/test_gost89.c`. These are all external-vector anchors, not internal consistency checks.

- The clean-room side (`gostcrypto/ctracpkm`) is also KAT-validated independently. The parity test adds a second degree of cross-validation between two implementations that were both anchored to the same external KAT suite but written independently — that is a real and useful check, not a vacuous one.

- `docs/engine-vectors.md` and `gostcrypto/TODO.md` do not document this situation, so it is not a previously acknowledged intentional divergence from documentation — the finding is not refuted by those files.

The real problem is the module-level claim in CLAUDE.md ("clean-room ↔ gogost differential tests") and any package-level doc that implies gogost is the oracle. The test itself and the oracle's KAT anchoring are sound; only the description is inaccurate.

**Suggested fix:** Two concrete changes:

1. Add a package-level doc comment to `parity/ctracpkm/` (a new `doc.go` or a comment at the top of `ctracpkm_parity_test.go`) that explicitly says: "Gogost v7 implements no CTR or CTR-ACPKM mode for Kuznyechik/Magma (gost3413/ contains only padding.go). The oracle here is the gostcryptocompat CTR implementation (ctr_gost.go), which is independently anchored to gost-engine v3.0.3 KATs (cipher_modes_test.go:TestCipherModes_EngineVectors CTR-ACPKM-32 and Master-96 vectors, ctr_test.go KATs). This is therefore a clean-room ↔ engine-KAT-anchored-facade comparison, not a clean-room ↔ gogost comparison."

2. Update the CLAUDE.md description of `parity/<prim>/` packages to note this exception: "Each `parity/<prim>/` package compares the clean-room primitive against gogost, *except* `parity/ctracpkm/` which uses a gostcryptocompat CTR facade as oracle (gogost v7 has no CTR-ACPKM for Kuznyechik/Magma) — the oracle is anchored to gost-engine KATs."

No code changes to tests or oracle are needed; the test logic is correct. Only the documentation needs updating.

### [CTRA-04] Streaming/split XORKeyStream semantics never exercised — every parity comparison is one-shot

- **Location:** `parity/ctracpkm/ctracpkm_parity_test.go:61-65,117-121,145-148`
- **Category:** test-gap · **Severity:** minor · **Verifier:** opus

**Finding:** The clean-room CTR explicitly documents cross-call state: 'Split XORKeyStream calls produce the same output as a single one-shot call (the partial-block offset is carried across calls)' (gostcrypto/ctracpkm/ctracpkm.go:53-54). Broken streaming is exactly the known gogost CTR failure mode that motivated clean-room reimplementations (per module CLAUDE.md: gost28147.CTR 'discards partial-block gamma across calls'). Yet TestDiff_CTRACPKM_vs_Oracle, TestDiff_PlainCTR_vs_Oracle and the fuzz target all call XORKeyStream exactly once per stream object. A regression in carrying `num`/`sinceRekey` across calls — e.g. the consumed-bytes (clean-room ctracpkm.go:183) vs generated-bytes (oracle ctr_gost.go:150) sinceRekey accounting interacting with a rekey at a call boundary — would pass this parity gate undetected. Chunked feeding (e.g. 1/7/15/16/17-byte chunks across a section boundary) on both sides is the missing case.

**Evidence:** ctracpkm_parity_test.go:61 `oracle.XORKeyStream(refOut, plain)` and :65 `mine.XORKeyStream(myOut, plain)` — single call each; no loop over chunk offsets anywhere in the package. Contrast: the facade's own cipher_modes_test.go ships xorKeyStreamByChunks, unused by this parity package.

**Verifier confirmation:** FACTUAL CLAIM (accurate): The parity package /Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/ctracpkm/ctracpkm_parity_test.go calls XORKeyStream exactly once per stream object in all three tests and the fuzz target (lines 61/65, 117/121, 145/148). No chunked/split feeding exists anywhere in the package (grep confirms; only those 6 XORKeyStream call sites). The clean-room and oracle do use different sinceRekey accounting: clean-room ctracpkm.go:183 increments per-byte-CONSUMED inside the per-byte loop; oracle ctr_gost.go:150 increments by `bs` per-block-GENERATED inside the `num==0` branch. The clean-room doc-comment (ctracpkm.go:52-53) does promise split-call == one-shot semantics.

RISK CLAIM (overstated): The finding asserts a regression in cross-call num/sinceRekey carrying "would pass this parity gate undetected," singling out the consumed-vs-generated sinceRekey accounting at a rekey-on-call-boundary. I tested this directly. (1) A structured experiment fed both implementations 7 chunk patterns (all-1-byte, 7-byte, 17-byte crossing 16-byte boundaries, mixed) across both ciphers and section sizes {0,8,16,24,32,64}: 56 comparisons, all chunked output == one-shot reference for BOTH impls. (2) A chunked-vs-one-shot fuzz target ran 277,354 execs over randomized keys/IVs/section-sizes/split-patterns, both ciphers, 20s: zero divergences. This matches analysis: both XORKeyStream loops hold all state in struct fields (num, sinceRekey, iv, block) with no output-affecting per-call local — so split(a,b)==one-shot(a+b) is an internal invariant of EACH impl, and the existing one-shot parity already proves one-shot==one-shot. The two accounting styles are equivalent because the rekey check (`sinceRekey >= sectionSize`) only evaluates at block boundaries (clean-room: when num==blockSize; oracle: when num==0), where consumed-bytes == generated-bytes.

No documented divergence in gostcrypto/TODO.md or docs/engine-vectors.md concerns streaming/split CTR-ACPKM, so this is not a restatement of an intentional divergence.

CONCLUSION: The test-absence is genuine, so the finding is confirmed as a coverage gap — adding a chunked harness is defense-in-depth that would catch a FUTURE refactor breaking resumability. But the claimed failure mode does not currently exist and is not a plausible one-line regression that the gate would silently pass: the sinceRekey accounting is provably split-safe in both impls. The 'high' severity (implying a real exploitable hole the gate misses) is unwarranted; this is a low-severity hardening gap.

**Suggested fix:** Add a chunked/streaming differential to parity/ctracpkm. Concretely, in ctracpkm_parity_test.go add a loop that, for each (cipher, section, length) case already enumerated, also re-runs both the oracle and clean-room by feeding the same plaintext in a set of split patterns and asserts the streamed result equals the one-shot result. Reuse the chunk-set idea: {all-1-byte, all-7/15-byte, {15,1,16,17,...}, all-block-size, {1,31,...}, all-17-byte} to straddle block and section boundaries. Mirror this in FuzzDiff_CTRACPKM_vs_Oracle by adding a fuzzer-derived chunkRaw []byte parameter that drives per-call offsets. This locks in the documented 'split calls == one-shot' contract (ctracpkm.go:52-53) so a future refactor that breaks num/sinceRekey carry-over is caught. (Verified such a harness passes today: 277K fuzz execs, 56 table comparisons, no divergence.)

### [CTRA-05] Plain-CTR parity (NewCTR) covers Kuznyechik only; Magma 8-byte-block NewCTR path never diffed

- **Location:** `parity/ctracpkm/ctracpkm_parity_test.go:131-154`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** TestDiff_PlainCTR_vs_Oracle hardcodes kuznyechik.NewCipher with a 16-byte IV. The NewCTR constructor over an 8-byte-block cipher (Magma) is never compared against the oracle. Magma plain-CTR behaviour is only reached indirectly via NewCTRACPKM(section=0) in the table test, which is a different constructor with its own validation/initialization path (e.g. NewCTR's `num: bs` lazy-gamma trick at ctracpkm.go:84 vs NewCTRACPKM's at :138). Low risk since the code paths converge, but a one-line table extension would close it.

**Evidence:** ctracpkm_parity_test.go:140 `ref.NewCTR(kuznyechik.NewCipher(key), iv)` and :148 `ctracpkm.NewCTR(kuznyechik.NewCipher(key), iv)` — no magma variant in this test; sections list `{0, 8, 16, 1024}` at :40 only covers magma section=0 through NewCTRACPKM.

**Verifier confirmation:** The test-absence claim is factually accurate. `TestDiff_PlainCTR_vs_Oracle` (lines 131–154 of `parity/ctracpkm/ctracpkm_parity_test.go`) hardcodes `kuznyechik.NewCipher` and a 16-byte IV on both lines 140 and 148. No Magma variant of `NewCTR` is compared against the oracle in this test.

The finding's assessment that the risk is low is also accurate, for these concrete reasons:

1. `NewCTR` and `NewCTRACPKM(..., section=0)` produce CTR structs that differ only in the `newBlock` field (nil vs non-nil) and `sectionSize` (0 in both cases). In `XORKeyStream`, the ACPKM rekey branch is guarded by `c.sectionSize > 0` (clean-room line 167) / `c.sectionSize > 0` (oracle line 142), so the `newBlock` field is never invoked and the two structs behave identically. The `TestDiff_CTRACPKM_vs_Oracle` table test already exercises Magma + section=0 against the oracle, covering the same `XORKeyStream` and `incCounter` paths on 8-byte IVs.

2. The clean-room `NewCTR` constructor (lines 73–89 of `../gostcrypto/ctracpkm/ctracpkm.go`) is block-size agnostic: it allocates `bs`-byte slices and sets `num: bs`. No Magma-specific code exists. The only non-trivial per-block-size behavior — `incCounter` on an 8-byte slice — is already covered by the `TestDiff_CTRACPKM_vs_Oracle`/Magma path.

3. `TODO.md` and `docs/engine-vectors.md` contain no documented divergences for CTR-ACPKM that would explain or excuse this gap.

The finding is not refuted by any existing documented intentional divergence. It represents a real but narrow coverage gap: the `NewCTR` constructor entry-point with a pre-built Magma block is never directly compared against the oracle's `NewCTR`. The severity is appropriately low because all active XORKeyStream logic is already diffed for Magma elsewhere.

**Suggested fix:** Extend `TestDiff_PlainCTR_vs_Oracle` to add a Magma sub-case alongside the existing Kuznyechik one. Concretely, restructure the test as a table of `{name, block, iv}` entries:

```go
func TestDiff_PlainCTR_vs_Oracle(t *testing.T) {
    key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

    cases := []struct {
        name string
        blk  cipher.Block
        iv   []byte
    }{
        {
            name: "kuznyechik",
            blk:  kuznyechik.NewCipher(key),
            iv:   mustHex(t, "1234567890abcef00000000000000000"),
        },
        {
            name: "magma",
            blk:  magma.NewCipher(key),
            iv:   mustHex(t, "1234567800000000"),
        },
    }

    for _, c := range cases {
        t.Run(c.name, func(t *testing.T) {
            for _, n := range []int{1, 8, 9, 16, 33, 200, 4097} {
                plain := make([]byte, n)
                for i := range plain { plain[i] = byte(i) }

                oracle, err := ref.NewCTR(c.blk, c.iv)
                if err != nil {
                    t.Fatalf("oracle NewCTR: %v", err)
                }
                refOut := make([]byte, n)
                oracle.XORKeyStream(refOut, plain)

                myOut := make([]byte, n)
                ctracpkm.NewCTR(c.blk, c.iv).XORKeyStream(myOut, plain)

                if !bytes.Equal(refOut, myOut) {
                    t.Fatalf("%s plain CTR len=%d divergence:\n ref %x\n new %x",
                        c.name, n, refOut, myOut)
                }
            }
        })
    }
}
```

Note: `cipher.Block` is stateful after `XORKeyStream` calls, so each sub-case and each length iteration needs a freshly constructed block. Create `c.blk` inside the loop or use a factory instead.

The relevant file is `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/ctracpkm/ctracpkm_parity_test.go`, specifically lines 131–154.

### [CTRA-06] In-place (dst==src) XORKeyStream never tested or fuzzed

- **Location:** `parity/ctracpkm/ctracpkm_parity_test.go:60-65,116-121`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The clean-room implementation explicitly permits exact overlap (guard tested in gostcrypto/ctracpkm/guard_test.go TestXORKeyStream_AllowsExactOverlap, alias check at ctracpkm.go:158) and the oracle documents 'dst and src must overlap entirely or not at all' (ctr_gost.go:127-128). All parity comparisons allocate separate output buffers, so the in-place encryption path — the common real-world usage in record processing — is never diffed. Cheap to add: run one side in-place on a copy and compare.

**Evidence:** Every comparison site allocates fresh buffers: `refOut := make([]byte, n)` / `myOut := make([]byte, n)`; no call with dst==src in the package.

**Verifier confirmation:** The finding accurately describes a real test-coverage gap. All comparison sites in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/ctracpkm/ctracpkm_parity_test.go` allocate separate output buffers (lines 60-65 and 116-121); no call passes `dst==src` to either the oracle or the clean-room implementation.

The clean-room (`ctracpkm.go:158`) uses `alias.InexactOverlap` to reject shifted/partial overlap while explicitly permitting exact overlap. The oracle (`ctr_gost.go:129-157`) imposes no overlap check at all. Both implementations use a byte-at-a-time loop reading `src[i]` before writing `dst[i]`, so exact overlap is safe by construction in both — there is no structural divergence risk today.

The clean-room has its own unit test (`guard_test.go:159-188`, `TestXORKeyStream_AllowsExactOverlap`) that verifies in-place produces the same bytes as separate buffers, but that test is in the clean-room package and only exercises one side. The parity package never diffs oracle vs. clean-room on an in-place call.

Severity stays low because: (1) neither implementation has block-at-a-time writes that could clobber unread input — the aliasing behavior is deterministic and identical in both; (2) the clean-room already asserts correctness of in-place for its own implementation; (3) the gap would only matter if one side were refactored to batch-write output before finishing reads, which is not a plausible near-term regression. The finding is not a documented intentional divergence, so it is confirmed.

**Suggested fix:** Add one in-place sub-case to `TestDiff_CTRACPKM_vs_Oracle` (and a fuzz seed in `FuzzDiff_CTRACPKM_vs_Oracle`) that runs the oracle on a copy then runs the clean-room in-place and compares:

In `ctracpkm_parity_test.go`, after the existing out-of-place comparison, add:

```go
// In-place: run oracle on a fresh copy, run mine in-place, compare.
inPlain := make([]byte, n)
copy(inPlain, plain)
oracle2, _ := ref.NewCTRACPKM(c.newBlock, key, iv, section)
oracle2.XORKeyStream(inPlain, inPlain) // in-place on oracle side

myInPlace := make([]byte, n)
copy(myInPlace, plain)
mine2 := ctracpkm.NewCTRACPKM(c.newBlock, key, iv, section)
mine2.XORKeyStream(myInPlace, myInPlace) // in-place on clean-room side

if !bytes.Equal(inPlain, myInPlace) {
    t.Fatalf("%s section=%d len=%d in-place divergence:\n oracle %x\n mine %x",
        c.name, section, n, inPlain, myInPlace)
}
```

Note: the oracle's `XORKeyStream` (`ctr_gost.go`) does not enforce an alias check, so calling it with `dst==src` is safe. A corresponding fuzz seed in `FuzzDiff_CTRACPKM_vs_Oracle` can pass the same slice as both `dst` and `src` on one of the two comparison sides to exercise the path under random inputs.

---

## gost28147

**Reviewer summary:** The parity test is a genuine, non-vacuous differential: the clean-room gostcrypto/gost28147 ECB cipher is diffed byte-for-byte against the independent gogost reference (via the gostcryptocompat facade, which wraps go.stargrave.org/gogost/v7/gost28147 with SboxDefault = CryptoPro-A — verified identical to the clean-room SboxCryptoProA table), over a pinned key plus 64 deterministic keys x 64 blocks, with a fuzz target that fully varies key and block bytes and additionally diffs Decrypt and checks round-trip identity. Both sides are wired with matching key and S-box, comparisons use bytes.Equal on full outputs, all loops execute, and the suite passes. The real gaps are coverage-shaped rather than correctness-fatal: the deterministic table never calls the clean-room Decrypt (its \"decrypt\" check only round-trips the oracle through itself, leaving deterministic decrypt parity to two fuzz seeds); the exported SboxTC26Z parameter set is never directly ECB-diffed in this package (the facade oracle hardcodes CryptoPro-A) and TC26-Z Decrypt has no parity coverage anywhere in the module; and the fuzz target hardcodes the S-box dimension with only a two-entry seed corpus. The documented gogost-vs-engine S-box row-order divergence does not apply here, since the clean-room code intentionally adopts the gogost row convention and is diffed against gogost.

### [G89-01] Table test's decrypt check is an oracle self-round-trip, not a parity diff

- **Location:** `parity/gost28147/gost28147_parity_test.go:47-54`
- **Category:** correctness · **Severity:** medium · **Verifier:** sonnet

**Finding:** In TestDiff_InternalGostOracle the clean-room Cipher.Decrypt is never invoked. The block at lines 47-54 computes back = gost.GOST2814789Decrypt(key, want) where want = gost.GOST2814789Encrypt(key, p) — i.e. it verifies that the gogost oracle decrypts its own ciphertext, which exercises only the oracle and proves nothing about the BSD clean-room code. The Encrypt leg (lines 41-44) is a real byte-exact diff, so the test is not vacuous overall, but deterministic decrypt parity rests entirely on the two fuzz seeds replayed by `go test` (FuzzDiffGost28147 lines 89-107), a far thinner sample than the 65x64 key/block grid the encrypt leg gets. Clean-room Decrypt is load-bearing downstream (IMIT key meshing uses it: gostcrypto/gost28147imit/imit.go:135), so it deserves the same grid.

**Evidence:** back, err := gost.GOST2814789Decrypt(key, want) ... if !bytes.Equal(back, p[:]) { t.Fatalf("oracle decrypt mismatch key#%d", ki) } — `c.Decrypt` (clean-room) does not appear anywhere in TestDiff_InternalGostOracle; grep confirms the only clean-room Decrypt calls are in the fuzz target (lines 91, 104).

**Verifier confirmation:** The finding is accurate on every specific claim.

In `TestDiff_InternalGostOracle` (lines 28-56 of `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/gost28147/gost28147_parity_test.go`):

- Line 42: `c.Encrypt(got, p[:])` — clean-room Encrypt IS diffed against the oracle over a 65×64 deterministic key/block grid (65 keys × 64 plaintext blocks = 4,160 pairs).
- Lines 47-53: `gost.GOST2814789Decrypt(key, want)` followed by `bytes.Equal(back, p[:])` — this calls only the gogost oracle and compares its output to the original plaintext. It proves the oracle is self-consistent (decrypt∘encrypt = id), not that the clean-room `c.Decrypt` matches the oracle. `c.Decrypt` never appears in `TestDiff_InternalGostOracle`.

The only two places `c.Decrypt` (clean-room) appears are in `FuzzDiffGost28147` at lines 91 and 104. When `go test` runs in non-fuzz mode it executes the fuzz function body once per `f.Add()` seed. There are exactly two `f.Add()` calls (lines 64-69: one with a known-vector key+block pair, one all-zero). There is no committed corpus under `testdata/fuzz/FuzzDiffGost28147/` (the only fuzz corpus in this module is under `parity/gost28147imit/testdata/fuzz/`). So deterministic `go test` exercises clean-room Decrypt against exactly 2 input pairs vs. 4,160 for Encrypt.

The downstream impact is real: `gostcrypto/gost28147imit/imit.go:135` calls `cur.Decrypt(newKey[i*8:i*8+8], cryptoProKeyMeshingKey[i*8:i*8+8])` inside the CryptoPro key meshing path, making correctness of the clean-room Decrypt load-bearing for IMIT tag computation.

**Suggested fix:** In `TestDiff_InternalGostOracle`, after the existing encrypt diff block (lines 41-45), replace the oracle-only decrypt block (lines 47-54) with a true parity diff that calls both the clean-room cipher and the oracle on the same ciphertext input, then compares their outputs. Concretely:

```go
// Decrypt diff: use the oracle ciphertext (want) as input to both sides.
minePT := make([]byte, BlockSize)
c.Decrypt(minePT, want)

refPT, err := gost.GOST2814789Decrypt(key, want)
if err != nil {
    t.Fatalf("GOST2814789Decrypt key#%d: %v", ki, err)
}
if !bytes.Equal(minePT, refPT) {
    t.Fatalf("Decrypt mismatch key#%d in=%x: clean-room %x != oracle %x", ki, want, minePT, refPT)
}
// Sanity: clean-room round-trip must recover p.
if !bytes.Equal(minePT, p[:]) {
    t.Fatalf("round-trip Decrypt(Encrypt(p)) != p key#%d", ki)
}
```

This gives the decrypt leg the same 4,160-pair grid coverage the encrypt leg already has. The original oracle-only block (lines 47-54) can be dropped — the new `!bytes.Equal(minePT, p[:])` round-trip check subsumes the self-consistency it was verifying.

### [G89-02] SboxTC26Z (exported clean-room S-box) never directly parity-diffed; TC26-Z Decrypt has no parity coverage anywhere

- **Location:** `parity/gost28147/gost28147_parity_test.go:29 (SboxCryptoProA hardcoded); gostcrypto/gost28147/gost28147.go:51-60 (SboxTC26Z)`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The clean-room package exports two S-boxes; the parity test exercises only SboxCryptoProA, because the facade oracle GOST2814789Encrypt/Decrypt hardcodes gogost SboxDefault (primitives_gost.go:150,165) and exposes no S-box parameter. TC26-Z gets only indirect coverage in sibling packages: parity/gost28147cnt (CNT mode — Encrypt-only keystream) and parity/keywrap (Encrypt + CFB). No parity test anywhere diffs clean-room ECB Decrypt under SboxTC26Z against gogost, so a transposition or row-order slip confined to the TC26-Z table's decrypt path would not be caught by the parity gate. A direct two-S-box ECB diff (importing go.stargrave.org/gogost/v7/gost28147 with SboxIdtc26gost28147paramZ, as gost28147cnt already does) belongs in this package. Note the documented S-box row-order divergence in gostcrypto/TODO.md is engine-vs-gogost; the clean-room code deliberately uses the gogost row convention, so diffing against gogost is correct and this finding is not that documented divergence.

**Evidence:** Only NewCipher call in the parity test: c := NewCipher(key, SboxCryptoProA) (line 29; fuzz line 75 likewise). Oracle: gost28147.NewCipher(key, gost28147.SboxDefault) — primitives_gost.go:150. grep for SboxTC26Z under parity/ hits only gost28147cnt (encrypt-only CNT) and keywrap (wrap = Encrypt + CFB); no Decrypt path.

**Verifier confirmation:** The finding is factually accurate: `parity/gost28147/gost28147_parity_test.go` uses only `SboxCryptoProA` (lines 29 and 75), and the `gost.GOST2814789Encrypt/Decrypt` oracle hardcodes `gost28147.SboxDefault` which is `&SboxIdGost2814789CryptoProAParamSet` (primitives_gost.go lines 150 and 165; third_party/gogost/gost28147/sbox.go line 113). There is no direct ECB Decrypt diff under TC26-Z in this package or anywhere in parity/ that runs unconditionally.

However, the claimed severity of "medium" is overstated for the following structural reasons:

1. **TC26-Z S-box is already parity-verified through Encrypt.** `parity/keywrap/keywrap_parity_test.go` (`TestKeyWrapCryptoPro_Differential` + `FuzzKeyWrapCryptoPro_Differential`) calls `KeyWrapCryptoPro` with `SboxTC26Z` on both the clean-room and gogost-oracle sides, unconditionally, over multiple deterministic key/ukm/cek inputs. `keywrap.KeyWrapCryptoPro` performs four independent ECB-Encrypt blocks under the TC26-Z cipher (gostcrypto/keywrap/keywrap.go line 109) and compares the full 44-byte wrapped blob byte-for-byte against the gogost oracle. This is a direct, unconditional parity check on the TC26-Z S-box values through the ECB Encrypt path.

2. **Decrypt and Encrypt share the exact same S-box lookup code.** In gostcrypto/gost28147/gost28147.go, both `Encrypt` (line 98) and `Decrypt` (line 112) call `c.xcrypt()` (line 156), which in turn calls `c.f()` → `c.t()` (lines 136-146). The `t()` function is the single S-box lookup site: `out |= uint32(c.sbox[i][nib]) << (nibbleBits * i)`. There is no separate S-box table or lookup path for Decrypt — the cipher struct has one `sbox SBox` field. The only difference between Encrypt and Decrypt is the `seqEncrypt` vs `seqDecrypt` key schedule order (lines 64-71). A "transposition or row-order slip confined to TC26-Z's decrypt path" is structurally impossible: if the S-box table is correct for Encrypt (proven by keywrap parity), it is necessarily correct for Decrypt.

3. **Decrypt under TC26-Z does have conditional coverage** via `gost28147cnt.meshKey()` (cnt.go line 120) which calls `s.c.Decrypt()` during CryptoPro key meshing. `TestDiff_GostEngineCLI` in parity/gost28147cnt exercises this path with `tc26-Z` and lengths > 1024. This test is conditional on gost-engine CLI availability, so it does not provide an unconditional gate.

The confirmed gap: there is no unconditional, direct ECB-level parity diff of `Decrypt` under `SboxTC26Z` in `parity/gost28147/`. Adding one would be the natural completion of the two-S-box symmetric test structure (matching what `FuzzDiffGost28147` already does for CryptoPro-A). But the risk of an undetected regression is low because the same S-box entries are already parity-validated through the keywrap Encrypt path, and no separate Decrypt-specific S-box codepath exists.

**Suggested fix:** Add a TC26-Z leg to `parity/gost28147/gost28147_parity_test.go`. The parity test cannot use the internal oracle (`gost.GOST2814789Encrypt/Decrypt`) for TC26-Z because that oracle hardcodes `SboxDefault` (CryptoPro-A). Instead, import `go.stargrave.org/gogost/v7/gost28147` directly (already available via the vendored third_party/gogost) and call `gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ)` as the reference — exactly as `parity/gost28147cnt` does at line 169.

Concretely, add a `TestDiff_TC26Z_ECB` table test and extend `FuzzDiffGost28147` to parameterise over both S-boxes. The test body mirrors the existing Fuzz body: for each key/block, assert `cleanRoom.Encrypt == gogostRef.Encrypt` and `cleanRoom.Decrypt == gogostRef.Decrypt`, plus the clean-room round-trip. No oracle helper change is needed (the facade is bypassed; gogost is imported directly). This removes the structural asymmetry noted in the finding and makes the TC26-Z S-box correctness verifiable without requiring gost-engine CLI to be present.

### [G89-03] Fuzz target never varies the S-box dimension

- **Location:** `parity/gost28147/gost28147_parity_test.go:75`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** FuzzDiffGost28147 fuzzes key and block bytes fully (good — fixLen zero-pads to KeySize/BlockSize so both dimensions are fuzzer-controlled), but the S-box is hardcoded to SboxCryptoProA, mirroring the facade limitation above. Adding a selector byte that switches between {SboxCryptoProA, SboxTC26Z} on the clean-room side and the corresponding gogost Sbox on the oracle side would extend differential coverage to the second exported parameter set at near-zero cost. Message length is fixed at BlockSize, which is correct for a raw block primitive, not a gap; and no empty-input divergence applies to this primitive.

**Evidence:** f.Fuzz(func(t *testing.T, rndKey, rndBlk []byte) { key := fixLen(rndKey, KeySize); p := fixLen(rndBlk, BlockSize); c := NewCipher(key, SboxCryptoProA) ... — the only non-fuzzed semantic input is the S-box constant.

**Verifier confirmation:** The finding is accurate. The fuzz target at `parity/gost28147/gost28147_parity_test.go:75` hardcodes `SboxCryptoProA` on both sides and never exercises `SboxTC26Z` differentially.

Key facts from the source:

1. The clean-room package exports two distinct S-box values: `SboxCryptoProA` (gostcrypto/gost28147/gost28147.go:39) and `SboxTC26Z` (line 51). Their contents differ completely — 8 rows of 16 nibbles each, with no overlapping values.

2. The oracle `gost.GOST2814789Encrypt` (primitives_gost.go:145) calls `gost28147.NewCipher(key, gost28147.SboxDefault)` where `SboxDefault = &SboxIdGost2814789CryptoProAParamSet` (third_party/gogost/gost28147/sbox.go:113). So the facade's `GOST2814789Encrypt` is structurally incapable of serving as a TC26Z oracle.

3. However, the compat facade does export `NewGOST28147Cipher(key, sbox *Sbox)` (exports_gost.go:83) and `SboxTC26Z = &Sbox{inner: &gost28147.SboxIdtc26gost28147paramZ}` (primitives_gost.go:48). The gogost TC26Z table at sbox.go:72 matches the clean-room table byte-for-byte. A TC26Z oracle is therefore reachable via `gost.NewGOST28147Cipher(key, gost.SboxTC26Z).Encrypt(dst, src)`.

4. The clean-room package's own unit tests (`gostcrypto/gost28147/gost28147_test.go:109`) loop over both sboxes for round-trip identity, and KAT vectors exist for TC26Z. But these are not differential fuzz tests — they do not compare the clean-room implementation against the gogost oracle for TC26Z inputs.

5. Neither `docs/engine-vectors.md` nor `gostcrypto/TODO.md` document any intentional decision to limit the differential fuzz coverage to CryptoPro-A. The finding is not a restatement of a known divergence.

The severity is low (not medium) because: the TC26Z S-box path in the clean-room code uses identical arithmetic — only the substitution table differs. The existing KAT vectors in `gostcrypto/gost28147/gost28147_test.go` already pin the TC26Z output to reference values. The missing fuzz coverage is a gap, not a latent bug, and the risk of an undetected divergence is low given the table is trivially auditable. The fix is genuinely near-zero cost as claimed.

**Suggested fix:** Add a selector byte to `FuzzDiffGost28147` in `parity/gost28147/gost28147_parity_test.go` that switches the fuzz target between the two S-box parameter sets. The facade provides all the required pieces:

```go
func FuzzDiffGost28147(f *testing.F) {
    // existing seeds ...
    f.Add(
        seedHex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1"),
        seedHex("0011223344556677"),
        uint8(0)) // sbox selector: 0=CryptoProA, 1=TC26Z
    f.Add(
        seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
        seedHex("0000000000000000"),
        uint8(1))

    f.Fuzz(func(t *testing.T, rndKey, rndBlk []byte, sboxSel uint8) {
        key := fixLen(rndKey, KeySize)
        p   := fixLen(rndBlk, BlockSize)

        var (
            cleanSbox SBox
            oracleEnc func([]byte) []byte
            oracleDec func([]byte) []byte
        )
        if sboxSel%2 == 0 {
            cleanSbox = SboxCryptoProA
            oracleEnc = func(blk []byte) []byte { v, _ := gost.GOST2814789Encrypt(key, blk); return v }
            oracleDec = func(blk []byte) []byte { v, _ := gost.GOST2814789Decrypt(key, blk); return v }
        } else {
            cleanSbox = SboxTC26Z
            oracle := gost.NewGOST28147Cipher(key, gost.SboxTC26Z)
            oracleEnc = func(blk []byte) []byte { dst := make([]byte, BlockSize); oracle.Encrypt(dst, blk); return dst }
            oracleDec = func(blk []byte) []byte { dst := make([]byte, BlockSize); oracle.Decrypt(dst, blk); return dst }
        }

        c := NewCipher(key, cleanSbox)
        // ... existing Encrypt/Decrypt/round-trip assertions using oracleEnc/oracleDec ...
    })
}
```

Add a corresponding TC26Z seed pair to the corpus in `testdata/fuzz/FuzzDiffGost28147/` with `sboxSel=1`.

### [G89-04] Seed corpus is two entries with no committed testdata corpus

- **Location:** `parity/gost28147/gost28147_parity_test.go:64-69`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Only two f.Add seeds exist (the pinned KAT key/block and all-zeros), and there is no parity/gost28147/testdata/fuzz corpus directory, so a plain `go test` replays just two decrypt-diff cases (compounding the finding that the table test does not diff decrypt). Committing a handful of corpus entries from a `make fuzz` run (or widening the deterministic table to call clean-room Decrypt) would harden the default gate.

**Evidence:** find parity/gost28147 -name testdata returns nothing; `go test -v` output shows exactly seed#0 and seed#1.

**Verifier confirmation:** Every factual claim in the finding checks out against the actual source.

**Claim 1: "Only two f.Add seeds"** — Confirmed. Lines 64–69 of `parity/gost28147/gost28147_parity_test.go` contain exactly two `f.Add` calls: the pinned KAT key/block pair and the all-zeros pair. No other seeds exist.

**Claim 2: "No testdata/fuzz corpus directory"** — Confirmed. `find parity/gost28147 -name testdata` returns nothing. The only other parity package with a `testdata/` directory is `gost28147imit/testdata/fuzz/FuzzDiff_InternalGostOracle/`, and that directory is also empty (no committed corpus files). So gost28147 is not uniquely deficient in this respect — no parity package has committed corpus entries — but the absence is real.

**Claim 3: "go test replays just two decrypt-diff cases"** — Confirmed by running `go test -v ./parity/gost28147/`, which shows `FuzzDiffGost28147/seed#0` and `FuzzDiffGost28147/seed#1` only.

**Claim 4: "Table test does not diff decrypt"** — Confirmed. `TestDiff_InternalGostOracle` (lines 15–57) calls `c.Encrypt` (clean-room, line 42) and `gost.GOST2814789Decrypt` (oracle, line 47), but the oracle decrypt is used only to verify `oracle_decrypt(oracle_encrypt(p)) == p` — it never calls `c.Decrypt` to diff the clean-room Decrypt against the oracle. In contrast, the magma parity table test runs 50,000 iterations diffing both `MagmaEncrypt` and `MagmaDecrypt` against the oracle.

**Why severity remains low, not higher:**
- `Decrypt` in the clean-room is implemented as `xcrypt(&seqDecrypt, n1, n2)` (line 120 of `gost28147.go`) — the same Feistel body as `Encrypt` with only the key-schedule index array swapped (`seqDecrypt` vs `seqEncrypt`). A Decrypt-specific bug would have to be in the reversed schedule array (lines 68–71), not in the shared round function.
- `gostcrypto`'s own `TestECB_KAT` (lines 22–100 of `gostcrypto/gost28147/gost28147_test.go`) tests `Decrypt(KAT_ciphertext) == KAT_plaintext` for 6 known vectors across two S-boxes, which does exercise the reversed schedule against ground truth.
- The two fuzz seeds do hit the `c.Decrypt` vs `gost.GOST2814789Decrypt` diff path (lines 91–99 of the fuzz body), providing at least minimal oracle-differential coverage.

The gap is real: the deterministic gate (`go test`) only exercises clean-room Decrypt differentially at 2 fixed points. Widening `TestDiff_InternalGostOracle` to include `c.Decrypt` (as magma does) would close the coverage gap without needing a committed corpus.

**Suggested fix:** Add a `c.Decrypt` differential check inside `TestDiff_InternalGostOracle` alongside the existing encrypt loop. For each of the 4160 (key, block) pairs already being iterated, after computing `got = c.Encrypt(p)`, add:

```go
// Diff clean-room Decrypt against oracle on the just-encrypted ciphertext.
gotBack := make([]byte, BlockSize)
c.Decrypt(gotBack, got)
refBack, err := gost.GOST2814789Decrypt(key, got)
if err != nil {
    t.Fatalf("GOST2814789Decrypt key#%d: %v", ki, err)
}
if !bytes.Equal(gotBack, refBack) {
    t.Fatalf("Decrypt mismatch key#%d ct=%x: clean-room %x != oracle %x", ki, got, gotBack, refBack)
}
if !bytes.Equal(gotBack, p[:]) {
    t.Fatalf("round-trip key#%d: Decrypt(Encrypt(p)) != p", ki)
}
```

This mirrors what `parity/magma/TestMagmaDifferential` already does (lines 35–48 there) and makes the default `go test` gate exercise 4160 differential Decrypt cases instead of 2, without requiring a committed fuzz corpus or changing the fuzz test.

---

## gost28147cnt

**Reviewer summary:** This is one of the stronger parity packages in the repo. The gogost CTR oracle is provably defective for general inputs (uint32 counter loses the end-around carry — third_party/gogost/gost28147/ctr.go:41-45 with nv=uint32 — and it lacks CryptoPro key meshing), and the test handles this correctly: it restricts the gogost diff to the documented-valid zero-key/zero-IV/n<1024 regime (TestDiff_InternalGostOracle, FuzzDiff_InternalGostOracle), pins and explains the divergence boundary (TestDiff_OracleLacksMeshing — I independently reproduced the pinned post-mesh KAT 56f45eab8381b608 from the gost-engine CLI, so it is not a clean-room echo), and delegates the random key/IV/length/S-box differential to the live gost-engine CLI (TestDiff_GostEngineCLI), which exercises both CryptoPro-A and tc26-Z, meshing-straddling lengths, and random 1-13-byte non-block-aligned streaming splits. CI runs the engine differential in a dedicated parity-engine job whose setup action smoke-verifies the exact CLI path, mitigating the silent-skip risk. Sbox wiring is correct (facade SboxDefault is CryptoPro-A, matching the clean-room side). Remaining issues are low severity: the engine helper conflates mid-run CLI failure with unavailability (skip instead of fail), the parity package never crosses the second meshing boundary (max n=1299), tc26-Z parity depends entirely on the optional engine binary, and the fuzz target's chunk-split schedule has only 256 possible shapes with chunks capped at 13 bytes (key/IV/length being held fixed in the fuzzer is a documented, forced consequence of the oracle's defects, not an oversight; the clean-room module's own oracle-free FuzzSplitInvariance covers fuzzed key/IV/sbox/meshing).

### [G89C-01] engineCNT conflates engine invocation failure with unavailability, turning real failures into silent skips

- **Location:** `parity/gost28147cnt/gost28147cnt_parity_test.go:139-144`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** engineCNT returns ok=false on ANY cmd.Output() error or short output, and the caller responds with t.Skip (line 184). Availability is thus re-decided per iteration inside the 40-iteration loop: if the engine crashes or errors on a specific input at iter N (after N-1 successful diffs), the whole subtest is reported as skipped rather than failed, discarding evidence of a real problem. A stricter design probes availability once before the loop and treats any subsequent CLI error as t.Fatal. CI is partially protected because the setup-gost-engine action smoke-verifies the exact CLI invocation before tests run, but local/dev runs can mask genuine engine errors as skips.

**Evidence:** res, err := cmd.Output(); if err != nil || len(res) < n { t.Logf("engine CLI unavailable (%v); skipping", err); return nil, false } ... caller: want, ok := engineCNT(...); if !ok { t.Skip("gost-engine CLI not available") } — inside `for iter := 0; iter < 40; iter++`.

**Verifier confirmation:** The finding is structurally correct. The specific code path is:

1. `engineCNT` (lines 139-143): `opensslBin()` only checks for binary existence via `os.Stat`/`exec.LookPath` — it does not verify the gost engine loads or that the cipher works. If `cmd.Output()` fails for any reason (engine module not loaded for this specific key/IV, engine crash, cipher unavailable), the function returns `nil, false` with a `t.Logf("engine CLI unavailable (%v); skipping", err)`.

2. The caller at lines 182-185 is inside `for iter := 0; iter < 40; iter++` (line 172). `t.Skip("gost-engine CLI not available")` at line 184 calls `runtime.Goexit()`, terminating the entire subtest immediately. If iterations 0..N-1 succeed and iteration N returns `ok=false` due to a command error, the subtest is marked SKIPPED — the first N-1 successful diffs are silently discarded and the actual error is attributed to "CLI not available."

3. The skip message "gost-engine CLI not available" is also misleading when the binary exists but the engine fails: the binary was available, it was the command execution that failed.

4. The CI protection in `setup-gost-engine/action.yml` (lines 41-50) smoke-tests only one specific invocation: zero key, zero IV. It does not cover the 40 random (key, iv, n) tuples the loop generates, so an input-specific engine failure would not be caught by the smoke test.

The finding is not documented as an intentional design decision anywhere in `docs/engine-vectors.md` or `gostcrypto/TODO.md`.

The severity remains low (not medium/high) because: (a) in practice, a stable gost-engine v3.0.3 build that passes the smoke test is extremely unlikely to crash on only some random inputs; (b) the most common failure mode — engine simply not installed — is correctly handled as a skip on the very first iteration; (c) the `parity-engine` CI job builds the engine fresh and verifies it works before running the test, limiting the real-world exposure of this gap to local/dev runs.

**Suggested fix:** Separate the "is the engine available?" probe from the per-iteration invocation. Call `opensslBin()` (and optionally a single zero-key smoke invocation) once before the loop; skip the entire subtest if unavailable. Inside the loop, treat any `cmd.Output()` error as `t.Fatalf` — at that point availability has already been confirmed.

Concrete refactor of `TestDiff_GostEngineCLI` (lines 161-207):

```go
func TestDiff_GostEngineCLI(t *testing.T) {
    // Probe availability once, before any iteration.
    if _, ok := opensslBin(); !ok {
        t.Skip("gost-engine CLI not available")
    }

    r := rand.New(rand.NewSource(0x6057C17))
    for _, tc := range []struct { ... }{ ... } {
        t.Run(tc.name, func(t *testing.T) {
            for iter := 0; iter < 40; iter++ {
                // ... generate key, iv, n ...
                want, ok := engineCNT(t, key, iv, n, tc.tc26)
                if !ok {
                    // Engine binary exists but the command failed — real error.
                    t.Fatalf("iter=%d: gost-engine CLI failed (see t.Logf above)", iter)
                }
                // ... diff ...
            }
        })
    }
}
```

And update `engineCNT` to not repeat the skip logic (the caller now owns the skip decision). Keep the `t.Logf` for diagnostics but let the caller decide whether a false means skip or fatal. Alternatively, add a boolean parameter `availabilityProbe` or split into two functions: `isEngineAvailable() bool` (called once before the loop) and `mustEngineCNT` (called inside the loop, always fatals on error).

### [G89C-02] Second and later CryptoPro meshing boundaries (>=2048 bytes) never crossed by any test in the parity package

- **Location:** `parity/gost28147cnt/gost28147cnt_parity_test.go:177-179`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** TestDiff_GostEngineCLI caps n at r.Intn(1300) (max 1299) or 1024+r.Intn(48) (max 1071), so only the FIRST meshing boundary is differentially tested here. The clean-room counter logic `s.count = s.count%meshThreshold + 8` plus the reset-in-nextGamma path (gostcrypto/gost28147cnt/cnt.go:137-141,180) could harbor a bug that only manifests at the second mesh (e.g. count bookkeeping after the first reset). The 4096-byte engine fixture in gostcrypto/gost28147cnt/engine_vector_test.go does cross 3 boundaries, but that KAT lives in the BSD module, not in this parity gate; extending the engine differential to n up to ~2100 (or adding a >2048 iteration class) would close the gap within the gate itself at negligible cost.

**Evidence:** n := r.Intn(1300); if iter%5 == 0 { n = 1024 + r.Intn(48) } — maximum reachable n is 1299, below the second meshThreshold crossing at 2048.

**Verifier confirmation:** The finding is accurate. In `parity/gost28147cnt/gost28147cnt_parity_test.go:177-179`, `n` is capped at `r.Intn(1300)` (max 1299) or `1024 + r.Intn(48)` (max 1071), so `TestDiff_GostEngineCLI` — the only engine-differential test in this parity gate — never generates an input longer than 1071 bytes. The second CryptoPro meshing boundary at 2048 bytes is never crossed in any differential-against-engine test within `gostcrypto-compat/parity/gost28147cnt/`.

The clean-room meshing logic itself (`cnt.go:137-141,180`) is mathematically sound: `count` increments by exactly `blockSize=8` per `nextGamma()` call, so it hits `meshThreshold=1024` deterministically at every 128 blocks (1024 bytes) with no skip-over risk (verified by exhaustive simulation). The formula `s.count = s.count%meshThreshold + blockSize` always produces multiples of 8 in [8,1024], never jumping past the threshold.

Coverage picture:
- `TestDiff_GostEngineCLI` (parity gate): max n=1071; only the first mesh boundary is differentially tested vs. the engine.
- `TestCNT_Engine4K_CarryAndMeshing` (BSD `gostcrypto` module, `engine_vector_test.go`): uses a pre-computed 4096-byte gost-engine fixture that crosses 3 meshing boundaries — this IS a true differential against the engine reference, but it lives outside the parity gate.
- `FuzzSplitInvariance` (BSD module): seeds at 2100 bytes and covers the second boundary, but is a split-vs-one-shot self-consistency check, not a differential against an external oracle.

The practical risk is low: the 4096-byte KAT in the BSD module would catch any bug at the 2nd+ mesh boundary. However, the parity gate in `gostcrypto-compat` is supposed to be the correctness gate ("proves clean-room == gogost reference"), and it has a genuine coverage gap for multi-mesh scenarios. If the BSD module's KAT is ever weakened, modified, or the parity gate is run in isolation, the gap would matter.

The finding is not a documented intentional divergence (docs/engine-vectors.md only notes the GOSTR341194 empty-input and mac-testbig issues). Severity is low (not none) because the gap is real, even though an existing test elsewhere partially compensates.

**Suggested fix:** In `parity/gost28147cnt/gost28147cnt_parity_test.go`, add a test class that exceeds 2048 bytes so the second meshing boundary is crossed in the engine differential. Change the n-selection block (lines 177-179) to:

```go
n := r.Intn(1300)
if iter%5 == 0 {
    n = 1024 + r.Intn(48) // straddle first meshing boundary
}
if iter%7 == 0 {
    n = 2048 + r.Intn(100) // straddle second meshing boundary
}
```

Alternatively, add a dedicated sub-test that runs the engine differential for a fixed n=2200 (covering bytes 0–2200, crossing both the 1024-byte and 2048-byte mesh boundaries) with the same random key/IV approach as the existing loop. This closes the gap within the parity gate itself at negligible CI cost.

### [G89C-03] tc26-Z S-box has no gogost-based parity; its coverage depends entirely on the optional external engine binary

- **Location:** `parity/gost28147cnt/gost28147cnt_parity_test.go:168-170 and 221`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The only tc26-Z differential is TestDiff_GostEngineCLI, which t.Skips when no gost-engine openssl is found. TestDiff_InternalGostOracle and the fuzz target hardcode CryptoPro-A (via the facade's SboxDefault). gogost supports tc26-Z directly (gost28147.NewCipher(key, &SboxIdtc26gost28147paramZ).NewCTR(iv)), so a zero-key/zero-IV/n<1024 tc26-Z diff against gogost is feasible (after a one-time engine check that the zero/zero keystream stays carry-free under that S-box, as was done for CryptoPro-A). Without it, an environment lacking the engine runs zero tc26-Z parity for this primitive.

**Evidence:** Internal-oracle test: sbox := gost28147.SboxCryptoProA (line 221); facade NewGOST28147_CNT hardcodes gost28147.SboxDefault (primitives_gost.go:421), which is CryptoPro-A (third_party/gogost/gost28147/sbox.go:113). tc26-Z appears only in the engine-CLI test, which skips when the binary is absent.

**Verifier confirmation:** The finding is accurate in its core claim, though the full picture is slightly more nuanced than the description implies.

**What the code actually does (concrete lines):**

- `parity/gost28147cnt/gost28147cnt_parity_test.go:161-207` — `TestDiff_GostEngineCLI` runs a differential for BOTH CryptoPro-A and tc26-Z (lines 167-170), but issues `t.Skip("gost-engine CLI not available")` individually per sbox subtest (lines 183-185) whenever the engine binary is absent. So both sboxes skip together in a no-engine environment.

- `parity/gost28147cnt/gost28147cnt_parity_test.go:218-252` — `TestDiff_InternalGostOracle` hardcodes `sbox := gost28147.SboxCryptoProA` (line 221) because `gostcryptocompat.NewGOST28147_CNT` (used as the gogost oracle) hardcodes `gost28147.SboxDefault = CryptoPro-A` (`primitives_gost.go:421`). No tc26-Z path exists here.

- `FuzzDiff_InternalGostOracle` (lines 261-303) likewise hardcodes CryptoPro-A (line 270). No tc26-Z variant.

**The gogost oracle's tc26-Z feasibility:**

The vendored gogost at `third_party/gogost/gost28147/sbox.go:72` exports `SboxIdtc26gost28147paramZ` and `ctr.go:24` provides `NewCTR(iv)`. A tc26-Z gogost oracle can be constructed directly as `gost28147.NewCipher(key, &gost28147.SboxIdtc26gost28147paramZ).NewCTR(iv)` without needing the facade. The D4 carry defect documented in the test header (lines 22-28) affects non-zero IV; under zero-key/zero-IV with n<1024, the counter starts at zero and the C2=0x01010101 increment makes the lower word wrap only at block 4294967295/0x01010101≈16581375, far outside the 128-block window, so the carry defect does not trigger. This is the same regime already validated for CryptoPro-A by `TestDiff_InternalGostOracle`.

**Why the severity is low (not higher):**

CI explicitly builds gost-engine from source (`ci: build gost-engine from source and run the live differential` in the git log) and runs `TestDiff_GostEngineCLI`, which covers tc26-Z. The gap is only in local no-engine environments; production correctness for tc26-Z is validated in CI. The clean-room tc26-Z CNT implementation is also validated indirectly by `primitives_engine_vectors_test.go:70-85` in the root `gostcryptocompat` package, which runs engine-vector KATs using gogost directly against tc26-Z CNT static vectors (no engine skip, always runs) — but those tests exercise gogost's CTR, not the clean-room `gostcrypto/gost28147cnt.NewCNT`.

**The gap:** There is no always-running test that drives the clean-room `gostcrypto/gost28147cnt.NewCNT` with `SboxTC26Z` against a gogost oracle. In a no-engine local environment, a developer modifying the counter or carry logic in the clean-room CNT package would get zero tc26-Z feedback from `go test ./...` in `gostcrypto-compat`.

**Suggested fix:** Add a tc26-Z variant to `TestDiff_InternalGostOracle` and `FuzzDiff_InternalGostOracle` in `parity/gost28147cnt/gost28147cnt_parity_test.go`. Use the gogost oracle directly (not via the facade) to avoid the SboxDefault constraint:

```go
// In TestDiff_InternalGostOracle, add a tc26-Z sub-loop after the CryptoPro-A one:
for _, tc := range []struct{ name string; sbox gost28147.SBox; gogsbox *gogost28147.Sbox }{
    {"CryptoPro-A", gost28147.SboxCryptoProA, gogost28147.SboxDefault},
    {"tc26-Z",      gost28147.SboxTC26Z,      &gogost28147.SboxIdtc26gost28147paramZ},
} {
    t.Run(tc.name, func(t *testing.T) {
        // same zero-key/zero-IV, n < 1024 loop as today
        // oracle: gogost28147.NewCipher(key, tc.gogsbox).NewCTR(iv)
    })
}
```

The import alias for the vendored gogost package is already available in the file as `"github.com/bigbes/gostcrypto/gost28147"` for the clean-room side; the gogost side needs `gogost28147 "go.stargrave.org/gogost/v7/gost28147"` added as an import (it is already imported in `primitives_engine_vectors_test.go` in the same module).

The zero-key/zero-IV constraint keeps the D4 carry defect from triggering (the counter does not wrap within 128 blocks at C2=0x01010101), so the gogost oracle is a valid reference in this regime for tc26-Z just as it is for CryptoPro-A. No engine check is needed for this bounded case.

### [G89C-04] Fuzz chunk-split schedule limited to 256 shapes with chunk sizes capped at 13 bytes; S-box never fuzzed

- **Location:** `parity/gost28147cnt/gost28147cnt_parity_test.go:266,289-298`
- **Category:** fuzz-gap · **Severity:** informational · **Verifier:** sonnet

**Finding:** The split schedule is fully determined by a single uint8 (step = step*31+7, chunk = 1+step%13), giving at most 256 distinct schedules and never a single XORKeyStream call spanning more than 2 block boundaries (max chunk 13). Accepting a []byte of split sizes would give the fuzzer real control over boundary placement (e.g. a large multi-block call followed by a 1-byte call). The S-box dimension is also hardcoded to CryptoPro-A even though it could be varied in the oracle's valid regime by constructing the gogost CTR directly (see the related test-absence finding). Note: holding key/IV at zero and capping n<1024 is NOT a gap — it is a documented, forced consequence of the gogost oracle's carry bug and missing meshing (verified in third_party/gogost/gost28147/ctr.go:41-45), and the seed corpus correctly contains only the supported regime; fuzzed key/IV/sbox/meshing coverage exists oracle-free in gostcrypto/gost28147cnt/fuzz_test.go FuzzSplitInvariance.

**Evidence:** f.Fuzz(func(t *testing.T, pt []byte, chunkSeed uint8) { ... chunk := 1 + int(step%13) ... step = step*31 + 7 } — one byte of split entropy; sbox := gost28147.SboxCryptoProA fixed.

**Verifier confirmation:** The factual claims about `FuzzDiff_InternalGostOracle` are accurate:

**Chunk-split entropy (lines 289-298):** `chunkSeed` is `uint8` → at most 256 distinct starting states. The recurrence `step = step*31 + 7` is purely deterministic and stays within `uint8`, so the set of chunk-split schedules is fully enumerated. Max chunk is `1 + step%13 = 13`, never spanning more than 2 block-length boundaries in a single call. Both observations are correct.

**S-box hardcoded (line 270):** `sbox := gost28147.SboxCryptoProA` is fixed. The oracle `gost.NewGOST28147_CNT` calls `gost28147.NewCipher(key, gost28147.SboxDefault)` (primitives_gost.go:421) which is also CryptoPro-A, so the pairing is forced by the oracle's API. However, gogost's vendored `gost28147.NewCipher` (third_party/gogost/gost28147/cipher.go:60) accepts any `*Sbox` argument, and `SboxIdtc26gost28147paramZ` exists (sbox.go:72), so a tc26-Z oracle CTR could be built directly — this is a genuine omission in the fuzz target.

**But the net test gap is zero.** The finding itself explicitly acknowledges this:
- `TestDiff_GostEngineCLI` (lines 161-207) covers BOTH S-boxes (CryptoPro-A and tc26-Z), random key/IV, random lengths up to 1348 bytes (straddling the 1024-byte meshing boundary), and random chunk splits (1..13) against the ground-truth gost-engine CLI. This is the authoritative differential for the exact paths `FuzzDiff_InternalGostOracle` misses.
- `FuzzSplitInvariance` in `gostcrypto/gost28147cnt/fuzz_test.go` (oracle-free, lines 23-80) fuzzes both S-boxes, arbitrary key/IV, lengths up to 4096 bytes, and chunk sizes 1..17 — wider coverage than the parity fuzz target on every dimension.

`FuzzDiff_InternalGostOracle` exists only to exercise the gogost-oracle diff in the regime where the oracle is valid (zero key/IV, n < 1024, single-shot call). The 256-schedule limit still exercises all 8 partial-block-remainder positions across a plaintext of up to 1023 bytes, so the actual boundary path it targets IS covered. The S-box gap in this one function is real but is closed by the sibling tests above.

The weaknesses are present exactly as described in the code, but the effective coverage gap in the overall test suite is nil. The claimed severity of "low" is overstated; from a correctness-assurance standpoint this is "none".

---

## gost28147imit

**Reviewer summary:** The parity test for gost28147imit is substantively sound: it diffs the clean-room IMIT (own 16-round Feistel, own meshing) against a genuinely different code path (gogost's gost28147.MAC core wrapped by the compat module's GOST28147_IMIT), compares full output bytes with bytes.Equal, runs 200 random keys over a deterministic length table that hits every short-message length 1..16 plus multiple crossings of the 1024-byte key-meshing boundary (1016..1032, 2048/2049, 12345), and the fuzz target correctly skips only the documented empty-input divergence (engine returns the zero IV state; clean-room panics by design — noted in imit.go, intentional). The known gogost gotchas (raw MAC lacks meshing; MAC.Sum destructiveness) are correctly engineered around and are not re-reported as findings. The main gaps are coverage, not correctness: the second exported symbol SeqMACBlock (the TLS record-layer building block, with a fuzzable S-box parameter that IMIT hardcodes to CryptoPro-A) has no differential test anywhere despite its facade mirror existing; the fuzz corpus seeds max out at 16 bytes so seed replay never reaches the meshing path; and the oracle's mesh/finalization wrapper is same-author logic whose independence hangs on the root-package gost-engine vector tests rather than anything in the parity package itself.

### [G89I-01] SeqMACBlock has zero differential coverage despite a gogost-backed mirror existing

- **Location:** `gostcrypto/gost28147imit/imit.go:221 (untested by parity/gost28147imit/gost28147imit_parity_test.go)`
- **Category:** test-gap · **Severity:** medium · **Verifier:** opus

**Finding:** The clean-room package exports two symbols: IMIT and SeqMACBlock. The parity test exercises only IMIT. SeqMACBlock is the 16-round single-block transform consumed by the gostls TLS record layer, the facade mirror GOST28147Cipher.SeqMACBlock (gostcrypto-compat/exports_gost.go:97) exists precisely so it can be diffed, yet no parity test calls it (grep over the whole module finds no test usage). Two consequences: (a) SeqMACBlock accepts an arbitrary S-box, but IMIT hardcodes CryptoPro-A, so the tc26-Z 16-round path is never differentially validated against gogost at all (only by a same-module KAT in gostcrypto's imit_test.go); (b) IMIT truncates to 4 bytes, so the upper half of the 8-byte SeqMAC state is never directly byte-compared (only indirectly via multi-block chaining).

**Evidence:** Parity test calls only IMIT(key, msg) (gost28147imit_parity_test.go:51,94). grep -rn SeqMACBlock gostcrypto-compat/ hits only the facade definition exports_gost.go:93-101 — no parity/ or *_test.go consumer. SeqMACBlock signature: func SeqMACBlock(key []byte, sbox gost28147.SBox, block []byte) []byte (imit.go:221) — sbox is a parameter; IMIT uses only gost28147.SboxCryptoProA (imit.go:258).

**Verifier confirmation:** All factual claims in the finding hold against the source.

(1) Zero parity consumer. `grep -rn "SeqMACBlock" gostcrypto-compat/` hits only the facade definition at exports_gost.go:93 and the method body at :97. No parity/ package and no *_test.go calls GOST28147Cipher.SeqMACBlock. The parity test gost28147imit_parity_test.go calls only IMIT(key, msg) (lines 51 and 94) diffed against refgost.GOST28147_IMIT.

(2) The mirror was built specifically to be diffed. exports_gost.go:97-102 constructs a MAC over a zero IV and Sums a single block — a faithful gogost-backed image of the clean-room 16-round per-block step (imit.go:96-112 / SeqMACBlock imit.go:221-235). It exists for parity comparison yet nothing compares it.

(3) The tc26-Z 16-round path has no independent (gogost) validation. The clean-room IMIT hardcodes gost28147.SboxCryptoProA (imit.go:258) and the oracle GOST28147_IMIT hardcodes gost28147.SboxDefault (primitives_gost.go:460), which in gogost is CryptoPro-A. SeqMACBlock alone accepts an arbitrary S-box. The tc26-Z 16-round transform is pinned ONLY by a same-module KAT (gostcrypto/gost28147imit/imit_test.go:105, value 611451608741d776), and that test's own comment admits the value was "computed by the same code path"/"computed from the clean-room implementation" — i.e. self-referential, with no external oracle. So the tc26-Z 16-round path is genuinely never differentially validated against gogost.

(4) The upper 4 bytes of the 8-byte SeqMAC state are never directly byte-compared cross-module. IMIT truncates to 4 bytes (tlsTagLen, imit.go:260), so the parity diff only ever inspects bytes[0:4]; the full 8-byte state is exercised cross-module only indirectly through multi-block chaining, never as a direct 8-byte equality against gogost.

This is real test-absence, not a documented intentional divergence: TODO.md / docs/engine-vectors.md cover only empty-input and meshing divergences. I lower severity from high to medium because the production TLS path (CryptoPro-A IMIT, which composes the same 16-round transform) is well covered by the existing IMIT differential, including the streaming-composition KAT in gostcrypto; the gaps are (a) tc26-Z, which is not a shipped TLS S-box, and (b) the upper-half bytes — real but narrow. A correctness regression in the upper 4 bytes or in the tc26-Z S-box wiring of the 16-round transform could slip past the gostcrypto-compat parity gate.

**Suggested fix:** Add a SeqMACBlock differential to parity/gost28147imit/ that compares the clean-room gost28147imit.SeqMACBlock against the gogost-backed facade GOST28147Cipher.SeqMACBlock over random keys and blocks, for BOTH S-boxes, and asserting full 8-byte equality (not 4-byte truncation). Concretely, in gost28147imit_parity_test.go add a test (and a Fuzz companion) along the lines of:

  for each (sboxName, refSbox, cleanSbox) in {CryptoPro-A, tc26-Z}:
      h := refgost.NewGOST28147Cipher(key, refSbox)         // gogost oracle, exports_gost.go:83
      ref := h.SeqMACBlock(block)                            // 8 bytes, exports_gost.go:97
      got := SeqMACBlock(key, cleanSbox.inner, block)        // 8 bytes, clean-room imit.go:221
      require bytes.Equal(got, ref)                           // full 8-byte compare

This closes both gaps: it differentially validates the tc26-Z 16-round transform against gogost for the first time, and it byte-compares the full 8-byte SeqMAC state (including the upper half that IMIT truncates away). Mirror the existing seed style and add a FuzzDiff target. The facade already exposes NewGOST28147Cipher(key, *Sbox) and an Sbox type, so no new facade surface is needed.

### [G89I-02] Fuzz target skips on oracle error, masking potential oracle-only failures

- **Location:** `gostcrypto-compat/parity/gost28147imit/gost28147imit_parity_test.go:89-93`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** After fixLen forces a 32-byte key, GOST28147_IMIT's only error paths (key-size check, NewMAC validation with fixed size=8/iv=8) are unreachable, so the t.Skipf is dead code today. But if the oracle ever regressed into returning errors for some input class, the fuzzer would silently skip those inputs instead of flagging the clean-room/oracle behavioural asymmetry (clean-room IMIT would still produce a tag). A t.Fatalf would be the safer choice given the inputs are known-valid at that point.

**Evidence:** ref, err := refgost.GOST28147_IMIT(key, msg); if err != nil { t.Skipf(...) } — key := fixLen(rndKey, keySize) guarantees len(key)==32, and msg is guaranteed non-empty by the preceding empty-message skip, so no legitimate skip can occur.

**Verifier confirmation:** The finding is correct. After `key := fixLen(rndKey, keySize)` at line 87, `len(key)` is always exactly 32 bytes (keySize=32, matching `gost28147.KeySize`). The only error paths inside `GOST28147_IMIT` in `primitives_gost.go` are:

1. Key-length guard (line 456-458): unreachable — key is always 32 bytes.
2. `c.NewMAC(gost28147.BlockSize, prev)` (line 466): unreachable — gogost's `NewMAC` only errors when `size == 0 || size > 8` (8 is the boundary, not > 8) or `len(iv) != BlockSize` (prev is `make([]byte, gost28147.BlockSize)`, always 8 bytes).
3. `NewMAC` after key mesh (line 485): same arguments, same reasoning.
4. `mac.Write` (line 491): gogost's `Write` at mac.go line 70-82 always returns `len(b), nil` — no error path exists.

Additionally, the empty-message guard (lines 82-86) runs before the oracle call, and the fuzzer corpus seeds all use non-empty messages. So there is no legitimate scenario where `GOST28147_IMIT` can return an error at this point in the fuzz target.

The `t.Skipf` at lines 90-93 is dead code today. The practical risk the finding identifies is real: if the oracle ever regressed to return errors on some input class (e.g., a future version of gogost tightens validation), the fuzzer would silently skip those inputs rather than surfacing the asymmetry — the clean-room IMIT would still run and produce a tag, but the comparison would be bypassed.

This is confirmed by comparison with the table-driven test `TestDiff_InternalGostOracle` at line 54, which correctly uses `t.Fatalf` for oracle errors on the same key/message inputs. The fuzz companion is inconsistent with this safer pattern.

**Suggested fix:** Replace `t.Skipf` with `t.Fatalf` at line 92 of `gostcrypto-compat/parity/gost28147imit/gost28147imit_parity_test.go`:

```go
ref, err := refgost.GOST28147_IMIT(key, msg)
if err != nil {
    t.Fatalf("oracle GOST28147_IMIT(len=%d): %v", len(msg), err)
}
```

This matches the pattern already used in `TestDiff_InternalGostOracle` (line 54) and correctly treats any oracle error on a known-valid 32-byte key + non-empty message as a fatal test failure rather than a silent skip.

### [G89I-03] Oracle's mesh/finalization wrapper is same-author code; independence rests on the root-package engine-vector tests

- **Location:** `gostcrypto-compat/primitives_gost.go:455-533`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** Only the per-block 16-round transform of the oracle comes from gogost (mac.Write -> xcrypt(SeqMAC)); the key-meshing schedule, count bookkeeping, and the short-message trailing-zero-block finalization are reimplemented in the compat module by the same project, structurally isomorphic to the clean-room imit() (same count==1024 trigger, same 1..8-byte rule). A shared misreading of the engine semantics would pass parity. This is mitigated — not eliminated — by TestGost_GOST28147_IMIT_Wrapper_KeyMeshing and TestGost_GOST28147_IMIT_Wrapper_NoMeshing in primitives_engine_vectors_test.go, which pin the oracle to independent gost-engine vectors (test/02-mac.t:162 and :185, the latter crossing the mesh boundary). Noting as low because the anchor exists, but the parity package itself carries no independent KAT: deleting those root-package tests would silently degrade this parity gate to clean-room vs near-clone.

**Evidence:** Oracle mesh logic primitives_gost.go:472-496 mirrors clean-room imit.go:160-171 (same `if count == meshThreshold` pre-block trigger, same cryptoProKeyMeshingKey constant defined separately in each module); short-message branch primitives_gost.go:501-515 mirrors imit.go:193-203. Engine anchors: primitives_engine_vectors_test.go:355-397.

**Verifier confirmation:** The finding accurately describes the structure. Here is the concrete evidence from source inspection:

**Oracle independence is partial, not full.**

The oracle in `primitives_gost.go:455-533` calls gogost only for the 16-round per-block MAC step (`mac.Write` → `mac.go:77: m.c.xcrypt(SeqMAC, m.n1, m.n2)`). Everything else — the `count == meshThreshold` pre-block trigger, the ECB-decrypt key-mesh loop, the `count = 0` reset, and the short-message trailing-zero-block branch — is hand-written by the same author. Confirmed by inspection:
- `gost28147/mac.go` in the vendored gogost has zero mesh/1024 logic — the word does not appear in any non-test file in `third_party/gogost/gost28147/`.
- The oracle's `processBlock` closure (`primitives_gost.go:472-496`) and the clean-room's `process` closure (`imit.go:163-171`) share identical structure: `if count == threshold` → mesh → block → `count += 8`.
- The `cryptoProKeyMeshingKey` 32-byte constant is byte-for-byte identical in both files (verified by direct comparison).
- The short-message branch `primitives_gost.go:501-515` (feed data block, then zero block when `count == 0`) mirrors `imit.go:193-203` exactly.
- The `SboxDefault` in gogost resolves to `SboxIdGost2814789CryptoProAParamSet` (`gost28147/sbox.go:113`), identical to the clean-room's `SboxCryptoProA`.

**The finding's consequence is accurate:** a shared misreading of the gost-engine semantics for the mesh schedule or the finalization rule would produce two structurally-identical wrong results that satisfy `bytes.Equal` in the parity test.

**The mitigating anchor exists and is real.** `TestGost_GOST28147_IMIT_Wrapper_KeyMeshing` (`primitives_engine_vectors_test.go:360-376`) pins the oracle to the independent gost-engine vector `5efab81f` for a 266240-byte input (the `testbig.dat` case from `test/02-mac.t:185`), which crosses 260 mesh boundaries. `TestGost_GOST28147_IMIT_Wrapper_NoMeshing` (`primitives_engine_vectors_test.go:383-398`) pins the 1024-byte boundary case. These are in the root package, not in `parity/gost28147imit/`, so deleting the parity package would not affect them.

**Severity stays low** for these reasons: the independent anchor is present and exercises the critical mesh boundary; the weakness is structural not a current defect; TLS framing guarantees non-trivial MAC inputs; and `docs/engine-vectors.md:31-35` explicitly documents why gogost's raw MAC is insufficient and that the meshing wrapper was purpose-built and validated.

**Suggested fix:** Add one or two direct gost-engine KAT vectors to `parity/gost28147imit/helpers_test.go` (or a new `parity/gost28147imit/engine_vectors_test.go`), so the parity package itself carries an anchor that is independent of the compat module's oracle. Concretely:

1. Port the `testbig.dat` vector already used in `TestGost_GOST28147_IMIT_Wrapper_KeyMeshing` directly into the parity package: key=`0123456789abcdef0123456789abcdef`, msg=`strings.Repeat(strings.Repeat("12345670",8)+"\n",4096)` (266240 bytes), expected clean-room `IMIT` output = `5efab81f`. This tests the meshing path with a gost-engine-derived expected value and is independent of the oracle.

2. Similarly, port the 1024-byte no-mesh vector: key=`0123456789abcdef0123456789abcdef`, msg=`strings.Repeat("12345670",128)`, expected `2ee8d13d`.

These additions mean that if the parity test passes but the root-package KAT is deleted, correctness of the meshing logic is still proven inside the parity package itself, eliminating the "silent degradation" risk identified in the finding.

### [G89I-04] No fuzz seed reaches the 1024-byte CryptoPro key-meshing path

- **Location:** `gostcrypto-compat/parity/gost28147imit/gost28147imit_parity_test.go:71-79`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The three f.Add seeds have message lengths 16, 8, and 1 bytes, and the committed corpus directory testdata/fuzz/FuzzDiff_InternalGostOracle/ is empty. Key meshing — the most divergence-prone part of this primitive (TODO.md documents it as the engine↔gogost disagreement that forced the compat wrapper to be written) — only triggers at >1024 bytes processed. Seed-replay mode (what `go test` / CI runs) therefore never executes the mesh branch of either side inside the fuzz target, and active fuzzing must grow inputs ~64x from the largest seed before mutation can probe mesh-boundary edge cases. The deterministic test covers meshing, but the fuzz target's mutation space effectively excludes it. Add a seed of e.g. 1025 and 2049 bytes.

**Evidence:** f.Add seeds: 16-byte msg (line 73), 8-byte msg (line 76), 1-byte msg (line 79). ls -laR parity/gost28147imit/testdata/fuzz/FuzzDiff_InternalGostOracle shows an empty directory. Mesh fires only when count == meshPeriod (1024) — imit.go:164-166, primitives_gost.go:473.

**Verifier confirmation:** The finding is factually correct about the fuzz seeds but overstates the severity by ignoring the deterministic test.

CONFIRMED PART — fuzz seed gap is real:
- `FuzzDiff_InternalGostOracle` has three `f.Add` seeds: 16-byte, 8-byte, and 1-byte messages (lines 71-79, confirmed by reading the file).
- The corpus directory `testdata/fuzz/FuzzDiff_InternalGostOracle/` is empty (confirmed by `ls`).
- In seed-replay mode (`go test` without `-fuzz`), the fuzz target only exercises those three short seeds. The mesh branch in `imit.go:164-166` (`if count == meshPeriod`) fires when `count == 1024`, which requires processing at least 129 8-byte blocks (≥1025 bytes total). None of the three seeds come close.
- This means active fuzzing must mutate inputs ~64x from the 16-byte seed before the mutation engine can reach the mesh boundary.

REFUTED PART — the claim that "go test / CI never executes the mesh branch":
The finding's statement that "the deterministic test covers meshing" is acknowledged but the severity argument ("the fuzz target's mutation space effectively excludes it") conflates the fuzz target with the overall test suite. `TestDiff_InternalGostOracle` (lines 28-62) is a regular `func Test*`, not a fuzz target. It runs unconditionally on every `go test ./...` call (including CI). Its length set explicitly includes: 1016, 1017, 1023, 1024, 1025, 1031, 1032, 2048, 2049, 3072, 4097, 8192, 12345 — across 200 random key/message iterations. This means the oracle comparison at and beyond the mesh boundary IS executed on every CI run. The correctness gate is intact.

ADJUSTED SEVERITY — low (not medium):
The deterministic test fully covers the meshing paths that the fuzz seeds miss. The gap is that during active fuzzing the fuzzer starts from short seeds, making it slower to discover meshing-boundary edge cases organically. This is a test-quality / fuzzing-efficiency issue, not a correctness gap in CI. Adding long seeds is a good housekeeping improvement but not a "medium" severity finding.

**Suggested fix:** Add two long `f.Add` seeds to `FuzzDiff_InternalGostOracle` to help the fuzzer reach the mesh boundary without having to mutate from 16 bytes:

```go
// Seed that crosses the first 1024-byte mesh boundary (1025 bytes of 0x42).
f.Add(
    seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
    bytes.Repeat([]byte{0x42}, 1025))
// Seed that crosses two mesh boundaries (2049 bytes).
f.Add(
    seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
    bytes.Repeat([]byte{0x5a}, 2049))
```

This makes the fuzzer's initial corpus include the mesh path so mutation-based exploration starts from the right length scale. The `bytes` import is already transitively available; add it to the import block if not already present. Alternatively, commit these as seed files in `testdata/fuzz/FuzzDiff_InternalGostOracle/` using the Go fuzz corpus file format (`go test -fuzz=FuzzDiff_InternalGostOracle -fuzztime=1s` will also populate the corpus).

---

## gost3410curves

**Reviewer summary:** The parity package has one genuinely strong leg: FuzzScalarMult diffs clean-room base-point scalar multiplication (gost3410sign.PublicKeyRaw) against the gogost oracle (gost.PublicKeyRawFromPrivate) byte-for-byte over fuzzer-chosen scalars and all 10 standard OID curves, with correct LE key wiring on both sides — this transitively proves parity of P, A, Q, X, Y and of the Add/Double arithmetic on the k·G path. However, the named "cross-check" table test is nearly vacuous (it compares only PointSize, which both sides derive identically from P.BitLen, plus a name-non-empty check), and the package never directly compares the curve constants even though the vendored gogost exposes P/Q/A/B/X/Y/Co and a Curve.Equal helper. As a result the coefficient B and the Cofactor field are exercised by nothing in this package (short-Weierstrass add/double never read B), and IsOnCurve — the package's invalid-curve gate and the only consumer of B — is never diffed against gogost's Contains anywhere in the parity suite. The fuzz target also skips asymmetrically when the gogost oracle rejects a key, without asserting the clean-room side rejects too. No documented divergence in gostcrypto/TODO.md or docs/engine-vectors.md applies to this package (those cover S-box order, R 34.11-94 empty input, key meshing), so none of these findings restate a known intentional divergence. One legitimate name divergence observed (facade returns gogost's "id-tc26-gost-3410-2012-512-paramSetC" alias vs clean-room "id-tc26-gost-3410-12-512-paramSetC"), which explains — but only partially excuses — the non-empty-only name check.

### [CRV-01] Coefficient B, Cofactor, and IsOnCurve have zero parity coverage

- **Location:** `gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go (whole package); gostcrypto/gost3410curves/curves.go:311-336, 69-75`
- **Category:** test-gap · **Severity:** medium · **Verifier:** opus

**Finding:** Affine short-Weierstrass Add/Double/ScalarMult never read the curve coefficient B, so FuzzScalarMult passes even if every B constant in the clean-room table is wrong. No test in this package (or anywhere in parity/ — grep for IsOnCurve over parity/ returns nothing) compares clean-room B or Cofactor against gogost's B/Co, and IsOnCurve — the package's documented gate against invalid-curve attacks and the only consumer of B — is never diffed against gogost's Curve.Contains. A transcription typo in any B constant or a wrong Cofactor would sail through the entire parity gate for this package. gogost exposes the raw fields (curve.go:31-54) and even Curve.Equal (curve.go:163-173), so a direct constant-by-constant diff per OID is trivial to add.

**Evidence:** curves.go Add/Double/fromLambda use only P, A, X, Y (never c.B); FuzzScalarMult compares only PublicKeyRaw output. gogost third_party/gogost/gost3410/curve.go:163-173 provides Equal() comparing P,Q,A,B,X,Y,E,D,Co — unused by the parity test. helpers_test.go imports the clean-room package but no test touches Curve.B, Curve.Cofactor, or IsOnCurve.

**Verifier confirmation:** The literal claim is accurate. (1) grep over parity/ for IsOnCurve/Cofactor/Contains/B/Co returns nothing — the only two tests in parity/gost3410curves/ are TestCrossCheckInternalGost (compares only PointSize and Name) and FuzzScalarMult (compares only PublicKeyRaw output). (2) In ../gostcrypto/gost3410curves/curves.go the affine arithmetic Add (345-380), Double (386-410), fromLambda (450-462) and ScalarMult (429-444) read only P, A, X, Y — never c.B and never c.Cofactor. So FuzzScalarMult deriving k·G is mathematically independent of B and Cofactor; a wrong B or Cofactor constant in the clean-room table cannot make that fuzz target fail. (3) IsOnCurve (curves.go:311-336) is the only consumer of B and is never diffed against gogost's Curve.Contains. gogost exposes raw P/A/B/Q/X/Y/Co fields and Curve.Equal (third_party/gogost/gost3410/curve.go:31-54,163-173), so a per-OID constant diff is trivial and is in fact already spec'd in gost3410-curves.md:532-577,665-698 as TestCurveConformance/FuzzCurveConformance (constant-by-constant clean-room-vs-gogost incl. {"b", got.B(), ref.B}) — that test was never implemented in the parity package. The license boundary forces such a diff to live here in gostcrypto-compat, not in gostcrypto, so this is the correct home for the missing coverage.

Severity is overstated as high. The claim "a transcription typo in any B constant or a wrong Cofactor would sail through the entire parity gate" is true only for THIS parity package, not for the project's overall test surface: the clean-room module's own curves_test.go catches a wrong B via TestBasePointOnCurve (curves_test.go:41-54, calls IsOnCurve(Base()) which reads B at curves.go:332 — any plausible B typo takes the pinned base point off the curve) and TestBasePointOrderIsQ (58-81), and pins Cofactor in TestCofactorField (237-256). Additionally curve_sign_sweep_test.go:116-129 in this module runs gogost Equal/Contains/Co checks (though gogost-internal only, not a clean-room diff). So a wrong B/Cofactor is caught by existing self-consistency gates; what is genuinely missing is the differential (clean-room == gogost) cross-check for B/Cofactor and an IsOnCurve-vs-Contains diff. Real, worth fixing as defense-in-depth and to match the module's own documented spec, but it is a redundancy gap, not an undetectable-bug hole — medium.

**Suggested fix:** Add a TestCurveConstantsDifferential to parity/gost3410curves/ that, for each of the ten allOIDs, resolves the clean-room *Curve via gost3410curves.CurveByOID and the gogost reference via a referenceCurve(oid) switch over go.stargrave.org/gogost/v7/gost3410.CurveId*() (mirroring exports of the facade), then compares big.Int-by-big.Int: clean-room c.P/c.A/c.B/c.Q/c.X/c.Y against gogost P/A/B/Q/X/Y, and clean-room c.Cofactor (int) against gogost Co (*big.Int) via big.NewInt(int64(c.Cofactor)).Cmp(ref.Co)==0. This closes the B and Cofactor parity gap that the arithmetic path leaves untested. Additionally add an IsOnCurve differential: for the base point and a handful of fuzzer/random k·G points, assert clean-room c.IsOnCurve(P) == gogost ref.Contains(P.X, P.Y), and assert clean-room IsOnCurve returns false on a deliberately off-curve point (e.g. (X, Y+1)) so the invalid-curve gate is exercised both ways. The md already contains the exact harness skeleton (gost3410-curves.md:665-698) — port it into the parity package (where the gogost import is license-permitted), driving B/Co/IsOnCurve.

### [CRV-02] TestCrossCheckInternalGost is nearly vacuous: compares only PointSize and name non-emptiness

- **Location:** `gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go:31-50`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** The only table-driven differential test in the package compares mine.PointSize() vs ref.PointSize() and asserts ref.Name() != "". Both sides derive PointSize identically from P.BitLen() (clean-room curves.go:115-121, gogost curve.go:98-100), so the test passes even if every constant except P's bit-length is wrong on the clean-room side. The justifying comment ('the gogost-backed gostcryptocompat ... does not expose raw integers') only applies to the facade — the parity package can import go.stargrave.org/gogost/v7/gost3410 directly (it is vendored at ./third_party/gogost and other parity packages import gogost directly per the repo CLAUDE.md). The real parameter parity burden therefore rests entirely on FuzzScalarMult, which covers P/A/Q/X/Y but not B/Cofactor (see separate finding).

**Evidence:** Lines 40-46: `if mine.PointSize() != ref.PointSize() { ... }` and `if ref.Name() == "" { ... }` are the only assertions. No comparison of P, A, B, Q, X, Y, Cofactor, or even mine.Name vs ref.Name().

**Verifier confirmation:** TestCrossCheckInternalGost (parity/gost3410curves/gost3410curves_parity_test.go:31-50) asserts only two things: (1) mine.PointSize() == ref.PointSize(), and (2) ref.Name() != "". Both clean-room (curves.go:115-121) and gogost (curve.go:98-100) derive PointSize purely from P.BitLen(), so PointSize agreement proves nothing beyond P having the right bit-length. No field in {A, B, Q, X, Y, Cofactor} is compared. The justifying comment "does not expose raw integers" is accurate for the facade wrapper in exports_gost.go (which only exposes Name() and PointSize() on *Curve), but the parity package can and other parity packages do import go.stargrave.org/gogost/v7/... directly — for example, parity/mgm/mgm_parity_test.go imports gogost's gost3412128 and mgm packages directly. So the facade limitation is a constraint that was chosen, not a hard barrier.

FuzzScalarMult provides the real coverage: it computes scalar·G on both sides and byte-compares the LE-encoded public points. A mismatch in P, A, X, or Y would propagate into a wrong result because ScalarMult (curves.go:429-443) uses A and P in every doubling (Double → doublingXCoeff·X²+A, mod P), and X/Y as the base point. Q is indirectly covered because PublicKeyRaw reduces d mod Q before multiplying (gost3410sign.go:199); a wrong Q shifts the effective scalar domain. However, B (the constant term in y²=x³+ax+b) is not touched by ScalarMult at all — only by IsOnCurve. gogost validates B at curve construction time via NewCurve→Contains (gost3410/curve.go:66), so a wrong B in the clean-room curves.go would not cause any gogost call to fail, and FuzzScalarMult would not detect it. Cofactor is also untested — the parity package has no VKO/KEG test that exercises cofactor scaling.

The severity is adjusted to low (not medium) because: (a) the actual scalar-multiplication path exercised by all GOST TLS operations is well-covered by FuzzScalarMult; (b) B is a public standard constant transcribed from RFC 4357/7836, and a transcription error would break IsOnCurve checks in gostcrypto itself; (c) Cofactor mismatches are covered by the separate parity/vko and parity/keg tests that use the same curves. The gap is real but limited to a narrow unchecked surface (B and Cofactor in gost3410curves specifically).

**Suggested fix:** Replace TestCrossCheckInternalGost with a direct parameter comparison that imports gogost's gost3410 package directly (as parity/mgm does). For each OID, resolve the clean-room *Curve and the gogost *gost3410.Curve, then assert P, A, B, Q, X, Y, and Cofactor are equal byte-for-byte:

```go
import (
    gogostcurve "go.stargrave.org/gogost/v7/gost3410"
    . "github.com/bigbes/gostcrypto/gost3410curves"
)

func TestCrossCheckCurveParams(t *testing.T) {
    for _, tc := range allOIDs {
        t.Run(tc.name, func(t *testing.T) {
            mine := mustCurve(t, tc.oid)
            ref := mustGogostCurve(t, tc.oid) // resolves gogost curve by OID string

            assertBigEq(t, "P", mine.P, ref.P)
            assertBigEq(t, "A", mine.A, ref.A)
            assertBigEq(t, "B", mine.B, ref.B)
            assertBigEq(t, "Q", mine.Q, ref.Q)
            assertBigEq(t, "X", mine.X, ref.X)
            assertBigEq(t, "Y", mine.Y, ref.Y)
            if mine.Cofactor != int(ref.Co.Int64()) {
                t.Fatalf("Cofactor mine=%d gogost=%d", mine.Cofactor, ref.Co.Int64())
            }
        })
    }
}
```

The existing TestCrossCheckInternalGost (facade black-box check) can be kept as a smoke test that OID resolution works in the facade, but the parameter parity burden should sit in the new direct-comparison test, not in FuzzScalarMult alone.

### [CRV-03] FuzzScalarMult skips asymmetrically when the gogost oracle rejects a key

- **Location:** `gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go:91-95`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** When gost.PublicKeyRawFromPrivate fails, the fuzz body t.Skips without first asserting that the clean-room side also rejects (PublicKeyRaw returns nil). The rejection-parity direction 'gogost errors but clean-room produces a key' is therefore never checked, while the opposite direction (line 97-99) is. gogost rejects an all-zero raw key before reduction (private.go:42-44) and errors via Exp on k ≡ 0 mod Q (curve.go:145-147); the clean-room returns nil for d mod q == 0 (gost3410sign.go:200-202). They happen to agree today, but a Q-table typo or a future clean-room change that accepts a key gogost rejects would be silently skipped rather than failed. Fix: in the error branch, require gost3410sign.PublicKeyRaw(mine, prv) == nil before skipping.

**Evidence:** lines 91-95: `refPub, err := gost.PublicKeyRawFromPrivate(ref, prv); if err != nil { t.Skipf("ref key load failed on %s: %v", oid, err) }` — newPub is computed only after this skip, so clean-room behaviour on oracle-rejected inputs is unobserved.

**Verifier confirmation:** The structural gap is real and is exactly as described. At lines 91-95 of `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go`, when `gost.PublicKeyRawFromPrivate` returns an error, the fuzz body calls `t.Skipf` immediately — `gost3410sign.PublicKeyRaw(mine, prv)` on line 96 is never evaluated for those inputs. The "gogost errors but clean-room returns a key" direction is structurally unobservable by this test.

Concrete error paths in gogost that could trigger the skip:
1. `gost3410.NewPrivateKeyLE` (private.go:42-44): rejects all-zero raw bytes before reduction.
2. `gost3410.Curve.Exp` (curve.go:145-147): rejects a degree of 0, which fires when non-zero raw bytes reduce to 0 mod Q (since `NewPrivateKey` stores `k.Mod(k, c.Q)` and `PublicKey()` calls `Exp(prv.Key, ...)`).

Clean-room `gost3410sign.PublicKeyRaw` (gost3410sign.go:197-202): reverses the LE input, reduces mod q, and returns nil iff `d.Sign() == 0`.

Both paths are mathematically equivalent — both reject when and only when the LE-interpreted scalar ≡ 0 mod q — so no input currently reaches the unchecked direction. Gogost's pre-reduction zero check (all-zero bytes → zero integer → 0 mod Q) and post-reduction Exp check (non-zero → 0 mod Q) both map to the same condition the clean-room checks with a single `d.Sign() == 0` after reduction. No Q-table divergence is documented in `gostcrypto/TODO.md` or `gostcrypto-compat/docs/engine-vectors.md`.

Therefore the finding is confirmed as a latent test weakness, not an active divergence. The claimed severity of "medium" is overstated: there is no current incorrect behaviour, only a blind spot that would silently miss a future regression (e.g. a Q-table typo, or a clean-room change that loosens the zero check). Adjusted to low.

**Suggested fix:** In the error branch (lines 92-95), compute the clean-room result first and assert it is nil before skipping:

```go
refPub, err := gost.PublicKeyRawFromPrivate(ref, prv)
if err != nil {
    // Scalar reduced to zero / invalid private key: genuinely no key.
    // Assert the clean-room side also rejects before skipping, so the
    // "gogost errors but clean-room accepts" direction is not silently dropped.
    newPub := gost3410sign.PublicKeyRaw(mine, prv)
    if newPub != nil {
        t.Fatalf("%s: clean-room PublicKeyRaw returned a key where gogost rejected (prv=%x)",
            oid, prv)
    }
    t.Skipf("ref key load failed on %s: %v", oid, err)
}
```

This mirrors the existing check on lines 97-99 (clean-room nil where gogost ok) and closes the asymmetry in both directions.

### [CRV-04] helpers_test.go declares expected pointSize per OID but never asserts it

- **Location:** `gostcrypto-compat/parity/gost3410curves/helpers_test.go:13-25`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** The allOIDs table carries an independent expected `pointSize` column (32/64 per OID), but no test reads it (grep for pointSize in the package shows only the declaration). TestCrossCheckInternalGost checks only mine==ref, which would still pass if both implementations agreed on a wrong size. Asserting tc.pointSize would anchor the comparison to an independent source for free.

**Evidence:** helpers_test.go:13 `pointSize int` populated for all 10 entries; gost3410curves_parity_test.go:40-43 compares mine.PointSize() against ref.PointSize() only, never against tc.pointSize.

**Verifier confirmation:** The finding is accurate. In `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/gost3410curves/helpers_test.go`, `allOIDs` declares a `pointSize int` field (line 13) with values populated for all 10 entries (lines 15-24). The comment on line 9 explicitly says "expected PointSize", implying it should be asserted. However, a complete grep of both files in the package confirms `tc.pointSize` is never read anywhere — not in `TestCrossCheckInternalGost` (lines 31-50) nor in `FuzzScalarMult` (lines 66-105). The field is dead code.

The severity is genuinely low (not medium or higher) for this reason: the absolute anchor for `PointSize()` correctness already exists in the clean-room module's own test suite at `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto/gost3410curves/curves_test.go:178-191` (`TestPointSize`), which asserts `c.PointSize() == tc.pointSize` against the same expected values. The cross-module parity test only adds a relative check (mine == ref), and the combination of the two tests provides reasonable coverage. The missing assertion in the parity package does not leave a correctness gap that isn't covered elsewhere.

The issue is: (1) dead code with a misleading comment, and (2) the parity package misses an independent absolute anchor — if both clean-room and gogost agreed on a wrong size, the parity test would not catch it. But this scenario is already ruled out by `TestPointSize` in the clean-room module.

**Suggested fix:** In `TestCrossCheckInternalGost` in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go`, after the existing mine/ref comparison (line 40), add:

```go
if mine.PointSize() != tc.pointSize {
    t.Fatalf("%s: PointSize mine=%d want=%d (per allOIDs)",
        tc.name, mine.PointSize(), tc.pointSize)
}
```

This turns the dead `pointSize` field into a live assertion and gives the parity test an independent absolute anchor, so that agreement between the two implementations on a wrong size would no longer be a silent pass.

### [CRV-05] Point operations on arbitrary (non-base) points and their edge branches never diffed

- **Location:** `gostcrypto/gost3410curves/curves.go:345-444 vs gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go:66-105`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The only operation parity-tested is k·G (base-point ScalarMult via PublicKeyRaw). Add(p,q) for independent points, Double directly, and ScalarMult of a non-base point (the signature-verification z2·pubKey path) are never diffed against gogost's Exp(degree, xS, yS), which accepts arbitrary points. Edge branches are unreachable under k·G with k<Q: Add's q=-p identity branch (curves.go:355-365), Double's y==0 vertical-tangent branch (curves.go:392-394), and ScalarMult's k<=0 guard. Notably, gogost's add() (curve.go:108-142) does NOT handle p+(-p) — it would ModInverse a zero denominator — while the clean-room returns the identity; a direct point-op diff would surface this shape difference and should deliberately exclude that case. Partial mitigation: parity/gost3410sign's cross-verify exercises arbitrary-point ScalarMult indirectly, but there is no direct point-arithmetic parity at this package's level.

**Evidence:** FuzzScalarMult derives points only as scalar·Base via PublicKeyRaw (test line 91-96); gogost Exp(degree, xS, yS) at curve.go:144-161 supports arbitrary start points and is never called by this package's tests.

**Verifier confirmation:** The finding is accurate on its core facts, but the severity should be adjusted down from medium to low because the missing coverage gap has no practical exploitability in the actual use-paths.

**What the parity tests actually cover at the gost3410curves level:**

`parity/gost3410curves/gost3410curves_parity_test.go` has two tests:
- `TestCrossCheckInternalGost` (lines 31–50): compares only `PointSize()` and OID resolution — no arithmetic.
- `FuzzScalarMult` (lines 66–105): derives points as `scalar·Base` via `gost3410sign.PublicKeyRaw` and `gostcryptocompat.PublicKeyRawFromPrivate`. Every point ever compared is `k·G` — only the base-point multiply path is exercised at this layer.

There is no test in this package that directly calls `Add(p, q)` for independent p, q, `Double(p)`, or `ScalarMult(k, nonBasePoint)`.

**The real behavioral divergence between clean-room and gogost:**

gogost's `add()` at `third_party/gogost/gost3410/curve.go:108–142` dispatches on `p1x == p2x && p1y == p2y` for doubling, but has no guard for `p + (−p)`. When `p1x == p2x` but `p1y != p2y` (the negation case), it falls into the else branch and computes `t.ModInverse(&tx, c.P)` where `tx = p2x - p1x ≡ 0 mod P`. In Go's `math/big`, `ModInverse(0, P)` returns 0 (no error), so `t` becomes 0, and the result is `x3 = −2·px mod P`, `y3 = −py mod P` — a completely wrong non-identity point. The clean-room `Add` at `curves.go:355–365` correctly checks `(p.Y + q.Y) mod P == 0` and returns the identity.

This divergence is real and undetected by the `gost3410curves` parity package. However:

**Why severity is low, not medium:**

The partial mitigation cited in the finding is real and substantial. `parity/gost3410sign/FuzzCrossVerify` (lines 147–212) calls `VerifyDigest`, which at `gost3410sign.go:176–178` executes `c.ScalarMult(z2, pub)` where `pub` is a user-controlled arbitrary public-key point, then adds `p1 + p2`. This does exercise `Add(nonBasePoint, nonBasePoint)` indirectly over many fuzzer-chosen inputs. The `p+(-p)` case specifically would only occur when `z1·G = −(z2·Q)`, i.e., `z1·G + z2·Q = ∞`, which is caught by the `cPoint.IsInfinity()` check in `VerifyDigest` (returning false) — consistent between both impls regardless of whether the addition is computed correctly. So the shape difference in `p+(-p)` handling is masked by the caller-level infinity guard in the only path that matters for GOST correctness.

**What is genuinely missing:** Direct `curves.Add(p, q)` and `curves.Double(p)` differential tests at the `gost3410curves` parity layer, with independent on-curve points derived from two independent scalars, and with explicit exclusion of the `q = −p` case (since gogost is known-broken there). The `k <= 0` and `y == 0` edge guards are also untested, but they are pure clean-room guards with no gogost counterpart to diff against.

**Not in TODO.md or docs/engine-vectors.md** — this is not a documented intentional divergence.

**Suggested fix:** Add a `FuzzPointAdd` target to `parity/gost3410curves/gost3410curves_parity_test.go` that:

1. Derives two independent on-curve points `P1 = s1·G` and `P2 = s2·G` from fuzzer-chosen scalars (both via `gostcryptocompat.PublicKeyRaw` / `gost3410sign.PublicKeyRaw` to guarantee both are on-curve).
2. Computes `clean_result = mine.Add(P1, P2)` and `gogost_result` by calling `gogost curve.Exp(s1+s2, G.X, G.Y)` — note: `(s1+s2)·G = s1·G + s2·G` by linearity, so this is a valid oracle for `P1 + P2` without needing gogost's `add()` directly (avoiding the `p+(-p)` broken case in gogost).
3. Explicitly skip when `s1 ≡ s2 mod Q` (which would make `P1 == P2`, hitting the doubling branch) and when `s1 ≡ -s2 mod Q` (which would make `P2 = -P1`, the case where gogost is broken).
4. Compare the x and y coordinates byte-for-byte.

This surfaces any arithmetic divergence on generic `Add` without triggering gogost's known-broken `p+(-p)` path. Add a separate table-driven test (not fuzz) for the `p.IsInfinity()` and `q.IsInfinity()` identity-element branches using hardcoded zero scalars, and for `Double` with a known on-curve point, using `Exp(2, G.X, G.Y)` as the oracle.

### [CRV-06] Fuzz varies only the scalar and curve index; no boundary-scalar seeds, no committed corpus

- **Location:** `gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go:66-74`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The fuzz dimensions that exist are appropriate (scalar bytes incl. >Q values that exercise mod-Q reduction parity, curve selector covering all 10 OIDs; fixed PointSize length is forced by gogost's NewPrivateKey API so length variation is correctly not fuzzed). Gaps: only three f.Add seeds (curve indices 0, 3, 7) and no seeds pinning the reduction boundaries — LE encodings of Q-1, Q, Q+1 for at least one 256-bit and one 512-bit curve — which are exactly where a Q transcription divergence would show; the fuzzer must rediscover them by luck. There is also no testdata/ seed corpus committed, so `go test` replay covers only the 3 inline seeds. The point input itself is never fuzzed (always the base point), but that is the structural gap already filed under test-absence.

**Evidence:** Lines 67-73: three f.Add calls — one 32-byte realistic scalar (sel 0), bytes.Repeat(0x42,32) (sel 3), bytes.Repeat(0x11,64) (sel 7). No near-Q seeds; ls of parity/gost3410curves/ shows no testdata directory.

**Verifier confirmation:** The finding is factually accurate and not refuted by any documented intentional divergence.

Seed count: Lines 67-73 of gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go confirm exactly 3 f.Add calls. No testdata/ directory exists (confirmed by ls). The finding's evidence is correct.

Reduction parity exposure: The clean-room side (gostcrypto/gost3410sign/gost3410sign.go:197-198) does d.SetBytes(reverse(prv)).Mod(d, q) using the clean-room Curve.Q; the gogost oracle side (third_party/gogost/gost3410/private.go:45) does k.Mod(k, c.Q) using gogost's internal Curve.Q. If these two Q values differ by even 1 bit, scalars in the range [min(Q_mine,Q_ref), max(Q_mine,Q_ref)] will reduce to different values in each implementation, producing a public key mismatch. The 3 existing seeds (roughly 0.26·Q for 256-bit curves, far smaller for 512-bit) never probe this range, so such a divergence would not be caught by go test replay.

Partial mitigation: gostcrypto/gost3410curves/curves_test.go:TestBasePointOrderIsQ verifies Q·G == identity for all 10 curves independently of gogost. This static math property check would catch a clean-room Q transcription error before the parity layer. However, it does not cross-check that gogost's Q agrees with the clean-room Q; only the differential fuzz test does that comparison. The near-Q seed gap is therefore real: it is the only place where a silent Q disagreement between the two implementations would be caught, and no seeds currently exercise that regime.

No documentation in gostcrypto/TODO.md or gostcrypto-compat/docs/engine-vectors.md describes this as a known intentional gap.

Severity: Low. A Q transcription error is unlikely (especially with the independent math property test in place), and the fuzzer will eventually generate near-Q values through mutation. But the gap is genuine: go test replay (the CI gate) has zero coverage of the reduction boundary.

**Suggested fix:** Add near-Q boundary seeds for one 256-bit curve (index 0, CryptoPro-A) and one 512-bit curve (index 7, tc26-512-A) in the FuzzScalarMult function in gostcrypto-compat/parity/gost3410curves/gost3410curves_parity_test.go, immediately after the existing f.Add calls at lines 72-73:

// Q-1 for CryptoPro-A in LE (largest valid scalar, no reduction):
f.Add(0, []byte{
    0x92, 0xb8, 0x61, 0xb7, 0x09, 0x1b, 0x84, 0x45,
    0x00, 0xd1, 0x5a, 0x99, 0x70, 0x10, 0x61, 0x6c,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
})
// Q+1 for CryptoPro-A in LE (reduces to 1, exercises the mod path):
f.Add(0, []byte{
    0x94, 0xb8, 0x61, 0xb7, 0x09, 0x1b, 0x84, 0x45,
    0x00, 0xd1, 0x5a, 0x99, 0x70, 0x10, 0x61, 0x6c,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
})

Add analogous Q-1 and Q+1 seeds for tc26-512-A (sel=7, 64-byte scalars). The Q value for tc26-512-A is 0xFFFF...FFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275, so Q-1 in LE starts with 74b2101f...

Optionally, also create testdata/fuzz/FuzzScalarMult/ with each seed as a file so they are replayed by go test without -fuzz. This matches the pattern already used in parity/gost28147imit/testdata/fuzz/.

---

## gost3410sign

**Reviewer summary:** The parity test is genuinely differential and non-vacuous: the clean room (gostcrypto/gost3410sign) is diffed against gogost via the gostcryptocompat facade (exports_gost.go wraps gost3410.SignDigest/VerifyDigest/PublicKey directly), the pinned vector is the independent RFC 7091 §7 test vector (katPrvLE is the byte-reverse of the standard d; katR/katS match the standard), and public-key derivation is compared byte-for-byte. However, the sign path is weaker than it should be: with the fixed nonce reader both implementations provably produce byte-identical signatures (verified empirically — all 64 deterministic iterations and the pinned vector match), yet the test only cross-verifies, justified by a false comment that "raw signature bytes won't match". Cross-verification cannot detect a nonce-encoding/reduction bug that yields a different-but-still-valid signature, so the "byte-for-byte" parity claim is unproven for SignDigest. The fuzz target additionally skips (rather than fails) on one-sided degenerate-input outcomes, masking accept/reject divergences, and everything is pinned to the single 256-bit TestParamSet with all inputs clamped to exactly 32 bytes — no 512-bit curve, no variable digest length, no signature tampering. None of the gaps relate to the documented divergences (S-box order, 34.11-94 empty input, key meshing), which are irrelevant to this primitive.

### [SIG-01] Sign path never byte-compared though fixed-nonce signatures are provably byte-identical; justifying comment is false

- **Location:** `parity/gost3410sign/gost3410sign_parity_test.go:98-120 (and 140-200)`
- **Category:** correctness · **Severity:** medium · **Verifier:** opus

**Finding:** Both TestDiff_CrossVerifyRandom and FuzzCrossVerify feed the gogost oracle a fixed nonce reader and the clean room the same nonce bytes, then only cross-verify the two signatures. gogost's SignDigest interprets the nonce exactly like the clean room (bytes2big = big-endian SetBytes, then Mod q; third_party/gogost/gost3410/private.go:117-121 vs gost3410sign.go:75-76), so refSig and newSig are byte-identical — I confirmed this empirically for all 64 deterministic iterations and the pinned RFC vector. The comment at lines 143-145 ('GOST signing is randomized, so raw signature bytes won't match') is factually wrong here. Because only cross-verification is asserted, a clean-room bug in nonce handling (e.g. reading k little-endian, off-by-one in the mod-q reduction, or even ignoring k and using a different valid nonce) would produce a different but still-valid signature and pass every check — the byte-for-byte parity claim for SignDigest is unproven. Relatedly, TestDiff_PinnedVector (line 49-56) only verifies the pinned signature; it never asserts SignDigest(prv, dig, katNonce) reproduces katSigSR, despite katNonce being defined in helpers_test.go:47. Fix: add bytes.Equal(refSig, newSig) to both the table test and the fuzz body, and a pinned SignDigest==katSigSR assertion.

**Evidence:** Test asserts only VerifyDigest/VerifyDigestOnCurve combinations (lines 109-120, 189-200), never bytes.Equal(refSig, newSig). Scratch test run: SignDigest(newCurve,prv,dig,k) == gost.SignDigestOnCurve(refCurve,prv,dig,bytes.NewReader(k)) byte-for-byte for 64 iterations, and both equal katSigSR for the pinned (katPrvLE, katDigBE, katNonce) inputs — PASS.

**Verifier confirmation:** The finding's technical core is fully verified, both by source reading and empirically.

Nonce/encoding equivalence (so byte-identity is provable):
- Clean-room SignDigest (../gostcrypto/gost3410sign/gost3410sign.go:75-76) reads k as `new(big.Int).SetBytes(k)` (big-endian) then `Mod(q)`.
- gogost SignDigest (third_party/gogost/gost3410/private.go:115-116) reads `kRaw` via `bytes2big(kRaw)` then `Mod(q)`; bytes2big (third_party/gogost/gost3410/utils.go:22-24) is `big.NewInt(0).SetBytes(d)` — identical big-endian. The test feeds gogost `bytes.NewReader(k)`, so kRaw == k.
- Digest path identical (both SetBytes big-endian, mod q, e==0→1). Private-key path identical (both reverse LE then SetBytes mod q; NewPrivateKey==NewPrivateKeyLE). r = x_C mod q and s = (d·r + k·e) mod q in both; both output pad(s)||pad(r). So for equal (curve, prv, digest, k) the outputs are byte-identical, contingent only on the curve arithmetic agreeing — which the test already establishes via pubkey equality and cross-verify.

Empirical confirmation: a scratch test (since removed) asserting bytes.Equal(refSig, newSig) passed for all 64 deterministic iterations of TestDiff_CrossVerifyRandom AND the pinned vector, and both equalled katSigSR. So the "won't match" comment at lines 143-145 is factually false in this fixed-nonce context.

Test weakness is real:
- TestDiff_CrossVerifyRandom (lines 109-120) and FuzzCrossVerify (lines 189-200) assert only the four VerifyDigest/VerifyDigestOnCurve combinations; none is bytes.Equal(refSig, newSig). A clean-room nonce-handling regression that produced a *different but still valid* signature (k read little-endian, off-by-one mod-q, or k ignored for a different valid nonce) would satisfy every assertion (lines 112/115 verify the divergent newSig, which is valid). Cross-verify proves "valid signature," not "the reference signature," so the byte-for-byte parity claim for SignDigest is currently unproven by the suite.
- TestDiff_PinnedVector (lines 49-56) only VERIFIES katSigSR under both impls; it never asserts SignDigest(prv, dig, katNonce) == katSigSR. katNonce (helpers_test.go:47) is used solely as a fuzz seed (line 148); katR/katS are entirely unused. So deterministic sign-reproduces-KAT is asserted nowhere.

Not a documented divergence: TODO.md and docs/engine-vectors.md note no intentional randomization/encoding divergence for 3410 signing (engine-vectors.md:51 records a sign+verify round-trip; nothing about avoiding byte comparison). So this is not a restatement of an accepted divergence.

Severity adjusted from high to medium: this is a parity-test-coverage gap, not a live defect — the clean-room signing IS byte-correct today (proven above). But because this module's sole purpose is byte-for-byte parity (per CLAUDE.md), a sign-path parity test that cannot catch a nonce/output-encoding regression undermines the gate it is meant to be.

**Suggested fix:** Strengthen the deterministic assertions:
1. In TestDiff_CrossVerifyRandom, after computing refSig/newSig (gost3410sign_parity_test.go:103), add `if !bytes.Equal(refSig, newSig) { t.Fatalf("iter %d: sign bytes differ ref=%x new=%x", iter, refSig, newSig) }`.
2. In FuzzCrossVerify, after line 183 (guarded by the existing nil/err skips), add the same `bytes.Equal(refSig, newSig)` assertion.
3. In TestDiff_PinnedVector, add a sign-reproduces-KAT check: `newSig := SignDigest(newCurve, prv, dig, mustHex(t, katNonce)); if !bytes.Equal(newSig, sig) { t.Fatalf("new SignDigest != katSigSR: %x", newSig) }` and the corresponding `refSig, _ := gost.SignDigestOnCurve(refCurve, prv, dig, bytes.NewReader(mustHex(t, katNonce))); bytes.Equal(refSig, sig)`.
4. Fix the false comment at lines 143-145 (and the table-test header at 14-16) to state that with the fixed nonce the raw signature bytes ARE expected to match and are byte-compared, removing the "signing is randomized so bytes won't match" justification.

### [SIG-02] Only the 256-bit 2001 TestParamSet curve is exercised; no 512-bit (PointSize=64) parity at all

- **Location:** `parity/gost3410sign/gost3410sign_parity_test.go:25-26,72-73,155-156`
- **Category:** test-gap · **Severity:** medium · **Verifier:** sonnet

**Finding:** Every test and the fuzz target hardcode testParamSetCurve()/GOST2001TestParamSetCurve(). The clean-room API is generic over *curves.Curve and its own unit tests cover a 512-bit curve (gostcrypto/gost3410sign/gost3410sign_test.go: TestKAT512_A2), and the facade exposes other curves (GOST2001CryptoProAParamSetCurve, CurveByOID, including 512-bit 2012 param sets). The 512-bit path exercises different code: 64-byte halves in fillBE/putLE padding, 64-byte raw keys/signatures, and gogost's pointSize() switch. None of that is ever diffed against the oracle, so a padding or PointSize bug specific to 512-bit curves would pass the parity gate. Production-relevant curves (CryptoPro-A, the 2012 256/512 sets used by TLS certs) are likewise never compared.

**Evidence:** grep over the package: the only curve constructors referenced are testParamSetCurve() (helpers_test.go:23-40, P/Q ~2^255) and gost.GOST2001TestParamSetCurve(); no CurveByOID / 512-bit curve appears anywhere in parity/gost3410sign/.

**Verifier confirmation:** The finding is accurate and the evidence is definitive.

**What the parity tests actually cover:**
Every test function in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/gost3410sign/gost3410sign_parity_test.go` — `TestDiff_PinnedVector` (line 25-26), `TestDiff_CrossVerifyRandom` (lines 72-73), and `FuzzCrossVerify` (line 155-156) — constructs the clean-room curve via `testParamSetCurve()` (256-bit, ~2^255-order) and the gogost oracle via `gost.GOST2001TestParamSetCurve()` exclusively. There is no reference to any 512-bit curve, `CurveByOID`, or 64-byte key material anywhere in the package.

**What 512-bit exercises differently:**
In `gostcrypto/gost3410sign/gost3410sign.go`, every sizing decision is driven by `c.PointSize()`:
- `SignDigest` line 55: `pointSize := c.PointSize()` then `out := make([]byte, coordsPerKey*pointSize)` (line 104), `fillBE(out[:pointSize], s)` and `fillBE(out[pointSize:], r)` (lines 105-106).
- `VerifyDigest` line 125-126: length guards `len(sig) != coordsPerKey*pointSize`.
- `PublicKeyRaw` lines 209-213: `putLE` padding to 64-byte halves.

For a 512-bit curve these become 64-byte halves. The `fillBE` and `putLE` helpers accept the destination slice via `dst` and branch only on `len(b) > len(dst)`. No 512-bit path has ever been exercised in the parity gate.

On the gogost oracle side, `gost3410/utils.go:36-41` shows the `pointSize()` function switches on `p.BitLen() > 256`, and `private.go:135-139` uses that to pack s||r. The 512-bit encoding path is symmetrical but independent.

**Acknowledged in TODO.md:**
`/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto/gost3410sign/TODO.md` explicitly notes: "tmp/engine/test/04-pkey.t:265 — R 34.10-2012-512 sign/verify vector unported. The original 'wrapper only exposes 256-bit' blocker is gone: 512-bit curves exist (`gost3410curves` Tc26 512 A/B/C) and `SignDigest`/`VerifyDigest` are curve-agnostic. Only the vector port remains." This is an open gap, not a deliberate exclusion or a documented divergence.

**Partial mitigation from sibling package:**
`parity/gost3410curves/FuzzScalarMult` does include 512-bit OIDs (helpers_test.go line 22-24) and fuzz-tests `PublicKeyRaw` against the gogost oracle byte-for-byte on all curves including 512-bit ones. This covers `putLE` with 64-byte output. However, it does not cover `SignDigest` (which uses `fillBE` on a 64-byte dst) or `VerifyDigest` (which parses a 128-byte signature and validates `len(sig)` against `2*pointSize`). The sign/verify path is not diffed for 512-bit anywhere.

**Severity assessment:** The claimed severity of medium is appropriate. The clean-room code is generic and the 256-bit path is thoroughly tested; a 512-bit-specific padding bug would likely also break the self-contained `gostcrypto/gost3410sign/TestKAT512_A2` KAT. But `TestKAT512_A2` only checks internal self-consistency, not that the clean-room output matches the gogost oracle byte-for-byte. Production-relevant TLS curves (tc26 512-A, 512-B) used by GOST R 34.10-2012 TLS certificates are never compared against the oracle.

**Suggested fix:** Add a 512-bit differential test block to `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/gost3410sign/gost3410sign_parity_test.go`:

1. **Pinned KAT differential** — port the GOST R 34.10-2012 Appendix A.2 vector (already pinned in `gostcrypto/gost3410sign/gost3410sign_test.go:TestKAT512_A2`) as a new `TestDiff_Pinned512_A2`. Construct both sides with the 512-bit TC26 Test param-set curve: `gost.CurveByOID(asn1.ObjectIdentifier{1,2,643,7,1,2,1,2,3})` for the gogost oracle (TC26-512-C is the standard's test param set) and `curves.CurveByOID("1.2.643.7.1.2.1.2.3")` for the clean-room side. Feed the A.2 private key (64 bytes LE), digest (64 bytes), and nonce (64 bytes) to both `SignDigestOnCurve` and `SignDigest`; assert cross-verification under both.

2. **Random cross-verify for 512-bit** — add `TestDiff_CrossVerify512` mirroring `TestDiff_CrossVerifyRandom` but sizing all buffers to 64 bytes and using a 512-bit curve.

3. **Extend `FuzzCrossVerify`** — either parameterize it to accept a curve-selector byte (selecting among 256-bit and 512-bit OIDs) so the fuzzer exercises both paths, or add a separate `FuzzCrossVerify512` seeded with 64-byte scalar/digest/nonce values.

Also add the constants `katPrv512LE`, `katDig512BE`, `katNonce512`, `katR512`, `katS512` to `helpers_test.go` (they are already in `gostcrypto/gost3410sign/gost3410sign_test.go:184-198` and can be copied verbatim).

### [SIG-03] No negative-path parity: malformed/out-of-range signatures, wrong lengths, off-curve public keys

- **Location:** `parity/gost3410sign/gost3410sign_parity_test.go:58-66,202-210`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The only rejection case compared is a single flipped digest bit. The verify-side input validation — r==0, s==0, r>=q, s>=q (clean room gost3410sign.go:136 vs gogost public.go VerifyDigest), wrong-length sig/pubRaw, and off-curve public keys — is never diffed. Notably this hides a real behavioural divergence candidate: the clean-room VerifyDigest rejects off-curve points via c.IsOnCurve (gost3410sign.go:147), while gogost's NewPublicKeyLE performs no on-curve check at all and VerifyDigest proceeds with the raw coordinates; whether both ultimately reject (false vs error vs possibly different accept behaviour) is unexamined. The clean room has its own rejection_test.go for these paths, but nothing proves the oracle agrees. Tampering the signature bytes (as opposed to the digest) is also never tested.

**Evidence:** Only tamper check: `bad[0] ^= 0x01` on the digest (lines 59-66, 203-210). gogost public.go NewPublicKeyLE contains no IsOnCurve/contains check; clean room gost3410sign.go:147 `if !c.IsOnCurve(pub) || pub.IsInfinity() { return false }`.

**Verifier confirmation:** The finding is accurate. The parity test at parity/gost3410sign/gost3410sign_parity_test.go covers only one negative path: flipping a digest bit (lines 59-66, 202-210). Several rejection-path categories are tested only in the clean-room's own rejection_test.go (gostcrypto/gost3410sign/rejection_test.go) and are never cross-diffed against the gogost oracle in gostcrypto-compat.

Concrete evidence:

1. Wrong-length sig/pubRaw: clean-room gost3410sign.go:127 returns false immediately. Gogost's NewPublicKeyLE (third_party/gogost/gost3410/public.go:33-35) returns an error on wrong length, which VerifyDigestOnCurve (exports_gost.go:111-115) propagates as (false, err). Same outcome, but the parity test never verifies it.

2. r==0, s==0, r>=q, s>=q: clean-room gost3410sign.go:136 returns false. Gogost public.go:96-101 also returns (false, nil). Same outcome, unexamined by parity.

3. Off-curve public key (the most significant gap): clean-room gost3410sign.go:147 calls c.IsOnCurve(pub) and returns false before any arithmetic. Gogost NewPublicKeyLE (public.go:30-44) does NOT call Contains() on the input coordinates — the on-curve check in gogost is only applied to the base point in NewCurve (curve.go:66). VerifyDigest then calls pub.C.Exp(z2, pub.X, pub.Y) (public.go:120) using the unchecked off-curve coordinates. Exp (curve.go:144-161) also does no on-curve validation. Both implementations happen to reject in practice because the forged R won't equal r for an arbitrary off-curve point, but this is never confirmed by any parity test. A carefully crafted off-curve point that satisfies the verification equation mod p could expose a genuine behavioural divergence.

4. Tampered signature bytes: the parity test only tampers the digest, never the signature bytes themselves.

The TODO.md for gost3410sign and docs/engine-vectors.md contain no entry documenting this as an intentional accepted divergence. rejection_test.go in gostcrypto covers these paths for the clean-room alone; no equivalent cross-check exists in gostcrypto-compat.

Severity is low (not high) because: (a) the off-curve gap is a theoretical, not demonstrated, divergence — both impls reject randomly off-curve inputs; (b) the wrong-length and out-of-range cases are observably equivalent; (c) the fuzz target FuzzCrossVerify only exercises valid-input cross-verification, so it doesn't close the gap but also isn't a regression risk in production sign/verify.

**Suggested fix:** Add a new test function (e.g. TestDiff_RejectionParity) in parity/gost3410sign/gost3410sign_parity_test.go that cross-checks each rejection path against the gogost oracle:

1. Wrong-length sig/pubRaw: pass truncated/extended byte slices to both VerifyDigest (clean-room) and gost.VerifyDigestOnCurve (oracle); assert both return false/error.

2. r==0, s==0, r>=q, s>=q: build crafted sig bytes and assert both impls reject.

3. Off-curve public key: build an all-zero pubRaw and a byte-flipped pubRaw (matching the cases in rejection_test.go's TestVerify_RejectsOffCurvePub); assert both VerifyDigest (clean-room) and gost.VerifyDigestOnCurve (oracle) return reject. This is the highest-value case because gogost skips NewPublicKeyLE's Contains check entirely, so the parity is currently unverified.

4. Tampered signature bytes: flip a byte in the sig (not only the digest) and assert both impls reject — mirroring TestBitFlipSweep but cross-diffed.

The gogost oracle's VerifyDigestOnCurve signature is (bool, error); for length errors it returns (false, non-nil error) rather than (false, nil), so the assertion should check `ok == false` regardless of whether err is nil, to avoid false failures on that distinction.

### [SIG-04] Fuzz clamps every input to exactly 32 bytes — digest length, key length, and curve are never varied

- **Location:** `parity/gost3410sign/gost3410sign_parity_test.go:158-161 (fixLen), 147-153 (seeds)`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** fixLen(raw, 32) truncates or zero-extends all three fuzz inputs to exactly 32 bytes, so the fuzzer explores only a fixed-dimension slice of the input space. Both implementations accept arbitrary-length digests (plain big-endian SetBytes then mod q in both), and the real-world TLS case of a 64-byte Streebog-512 digest hashed onto a 256-bit curve is therefore never diffed; nor are short digests, empty digests (the e==0 -> e=1 substitution is reachable only via digest ≡ 0 mod q, which the fuzzer will essentially never hit with full 32-byte values but could trivially seed/explore with short inputs). The curve is hardcoded (no 512-bit dimension, see the test-absence finding), the corpus is just two f.Add seeds, signature bytes are never compared (see the correctness finding), and signature tampering is never fuzzed — only the digest bit-flip. Note this primitive has no known empty-input divergence (that caveat applies to GOST R 34.11-94, not 34.10), so variable/empty digest lengths are safe to fuzz here.

**Evidence:** lines 159-161: `prv := fixLen(rawPrv, 32); dig := fixLen(rawDig, 32); k := fixLen(rawK, 32)` — every fuzzer-supplied length is discarded. Clean room reads `new(big.Int).SetBytes(digest)` (gost3410sign.go:66) and gogost `bytes2big(digest)` (private.go:103) — both length-agnostic, so digest length is comparable parity surface the fuzzer never reaches. (Private-key length is the one dimension that legitimately must stay 32: gogost NewPrivateKeyLE hard-errors on len != PointSize while the clean room tolerates it — a documented API-shape difference, not fuzzable parity.)

**Verifier confirmation:** The claim is partially correct but overstated.

**Confirmed gap: digest length**

Both implementations are length-agnostic for the digest argument:
- Clean room (`gost3410sign.go:66`): `e := new(big.Int).SetBytes(digest)` then `.Mod(e, q)` — accepts any length.
- gogost oracle (`private.go:100` and `public.go:102`): `e := bytes2big(digest)` then `.Mod(e, q)` — accepts any length.

`fixLen(rawDig, 32)` at line 160 truncates/pads every fuzzer-supplied digest to exactly 32 bytes, so the 64-byte Streebog-512 case (the actual GOST TLS production case for a 256-bit curve) is never diffed. Both both sides perform `bigint.SetBytes(digest).Mod(q)`, so the reduction is identical in principle, but this is only asserted by the fixed KAT vectors and the 32-byte random iteration in `TestDiff_CrossVerifyRandom` — never by the fuzzer over other lengths.

**Refuted gap: nonce k length**

The claim that `fixLen(rawK, 32)` is a real fuzz gap is incorrect. In the fuzz function, `k` is passed as `bytes.NewReader(k)` to `gost.SignDigestOnCurve`, which calls `prv.SignDigest(digest, rnd)`. Inside gogost's `SignDigest` (private.go:105-115), `kRaw := make([]byte, prv.C.PointSize())` and `io.ReadFull(rand, kRaw)` always reads exactly 32 bytes from the reader, discarding anything beyond that. So gogost itself normalises the nonce to 32 bytes regardless of how much the reader supplies. `fixLen(rawK, 32)` is therefore correct and not a gap.

**Refuted gap: private key length**

Also correctly noted in the finding: `NewPrivateKeyLE` (gogost private.go:34) hard-errors if `len(raw) != pointSize`. The test skips on that error. So fixing the private-key length to 32 is the only correct behaviour; it is not a fuzz gap.

**Severity assessment**

The actual missing dimension is solely `rawDig` length. Since both implementations reduce via `.Mod(q)`, the most this gap could hide is an edge-case in big-endian parsing of non-standard-length byte slices. The implementations are both using `big.Int.SetBytes` (clean room) and `bytes2big` (gogost, also a `big.Int.SetBytes`-equivalent). In practice both would yield identical results for any digest length. The gap is real as a testing weakness — the 64-byte digest case is never fuzzed — but the risk of hiding an actual divergence is low because the numeric reduction is structurally identical. Severity is low rather than medium.

**Suggested fix:** In `FuzzCrossVerify`, remove `fixLen` only for the digest argument and let its length vary freely. Keep `fixLen(rawPrv, 32)` (gogost hard-errors on wrong key length) and keep `fixLen(rawK, 32)` (gogost reads exactly 32 bytes from the reader regardless).

Change lines 159-161 of `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/gost3410sign/gost3410sign_parity_test.go` from:

```go
prv := fixLen(rawPrv, 32)
dig := fixLen(rawDig, 32)
k   := fixLen(rawK,   32)
```

to:

```go
prv := fixLen(rawPrv, 32)
dig := rawDig  // variable length: both impls do SetBytes(dig).Mod(q), any length is valid parity surface
k   := fixLen(rawK, 32)
```

Also add a seed for the 64-byte Streebog-512 case to the `f.Add` block:

```go
f.Add(seedHex(katPrvLE), seedHex(katDigBE), seedHex(katNonce))
f.Add(
    bytes.Repeat([]byte{0x11}, 32),
    bytes.Repeat([]byte{0x22}, 32),
    bytes.Repeat([]byte{0x33}, 32),
)
// 64-byte digest: the actual GOST TLS Streebog-512 case for a 256-bit curve.
f.Add(
    bytes.Repeat([]byte{0x11}, 32),
    bytes.Repeat([]byte{0x44}, 64),
    bytes.Repeat([]byte{0x33}, 32),
)
// short digest
f.Add(
    bytes.Repeat([]byte{0x11}, 32),
    []byte{0x00},
    bytes.Repeat([]byte{0x33}, 32),
)
```

Empty-digest seeding is safe here: unlike GOST R 34.11-94, GOST R 34.10 has no known empty-input divergence. Both impls substitute `e = 1` when `digest mod q == 0` (RFC §6.1 step 2), so the zero-digest case is also parity-correct to fuzz.

### Dismissed for gost3410sign (do NOT act on these)

#### DISMISSED: Fuzz target skips instead of failing on one-sided sign/keyload outcomes, masking accept/reject divergences

- **Location:** `parity/gost3410sign/gost3410sign_parity_test.go:178-186 (also 165-167)` · **Category:** correctness · **Severity claimed:** medium · **Verifier:** sonnet

**Original claim:** In FuzzCrossVerify, if the oracle signs successfully but the clean-room SignDigest returns nil, the test calls t.Skipf('new sign nil (likely degenerate nonce)') at line 184-186 instead of t.Fatal. But if the ref succeeded with the same k, the nonce was NOT degenerate (gogost only retries/errors when k mod q == 0 or r/s == 0), so a nil from the clean room there is exactly the divergence the fuzzer exists to find — and it is silently skipped. Symmetrically, when the ref sign fails (line 178-182) the body skips before ever invoking the clean-room impl, so 'ref rejects / clean-room accepts' divergences are also invisible; same for PublicKeyRawFromPrivate error at line 165-167. The rejection-behaviour agreement between the two implementations is therefore never checked by the fuzzer. Minor related hazard: TestDiff_CrossVerifyRandom line 88 uses t.Skipf inside the iteration loop — if it ever fired it would silently abort the entire 64-iteration test rather than one iteration (currently unreachable with the deterministic byte patterns, but a trap).

**Why dismissed:** The finding claims that when `gost.SignDigestOnCurve` succeeds with nonce `k` but the clean-room `SignDigest` returns nil, `t.Skipf` at line 184-186 silently hides a divergence. The logic is flawed for the following reason:

**Why the skip at line 184-186 is unreachable dead code, not a masking bug:**

Both implementations process nonce `k` identically:
- gogost (`private.go:112-116`): `io.ReadFull(rand, kRaw)` fills `kRaw` with the exact bytes from `bytes.NewReader(k)`, then `k = bytes2big(kRaw)` reads them big-endian, then `k.Mod(k, q)`.
- Clean-room (`gost3410sign.go:75-76`): `kk := new(big.Int).SetBytes(k)` also big-endian, then `kk.Mod(kk, q)`.

Both apply the same three degeneracy checks in the same order:
1. `k mod q == 0` → gogost: goto Retry; clean-room: return nil
2. `r = x(k·P) mod q == 0` → gogost: goto Retry; clean-room: return nil
3. `s = (r·d + k·e) mod q == 0` → gogost: goto Retry; clean-room: return nil

The critical constraint: `bytes.NewReader(k)` contains exactly 32 bytes. gogost's `io.ReadFull` consumes all 32 bytes on the first read. If a retry occurs, the second `io.ReadFull` call fails with `io.ErrUnexpectedEOF`, and gogost returns an error (line 112-113: `if _, err = io.ReadFull(rand, kRaw); err != nil { return nil, ... }`). Therefore, gogost can only succeed (return non-error) if the first read produced a non-degenerate k — meaning none of the three conditions above was true.

Since the nonce bytes are read identically (big-endian) and the same arithmetic applies over the same curve parameters (both use id-GostR3410-2001-TestParamSet), if gogost succeeds without retry, the clean-room is presented with the same effective kk, the same point multiplication gives the same r, and the same (r·d + k·e) mod q gives the same s. All three nil-return guards in the clean-room will pass, so `SignDigest` will NOT return nil. The t.Skipf at line 184-186 is structurally unreachable when the ref succeeded.

**Line 165-167 skip (ref key load failure):** gogost errors only when the private key reduces to 0 mod q (after confirming `len(raw)==32`, which `fixLen` guarantees). The clean-room `PublicKeyRaw` also returns nil for d==0. Both reject zero keys. The skip correctly excludes known-invalid inputs where both implementations would reject; it does not mask a real divergence, and the code at lines 169-171 catches the reverse case (ref ok, clean-room nil) with `t.Fatalf`.

**Line 88 t.Skipf inside iteration loop (minor trap):** Real structural issue — `t.Skipf` inside a `for iter := 0; iter < 64; iter++` loop aborts the entire test, not just one iteration. But the `prv` values are computed by a deterministic formula (`prv[i] = byte(iter*7 + i*3 + 1)`), and none of them reduce to 0 mod the curve order, so this branch is currently unreachable. It is a latent trap but not an active bug.

**The finding is refuted** because the central mechanism it relies on — "ref succeeded with k, so the nonce was not degenerate for the clean-room either, but the skip hides the clean-room nil" — is impossible: gogost can only succeed on a 32-byte single-shot reader when no degeneracy condition fires, and the clean-room's degeneracy conditions are identical. The skip is dead code, not a masking bug.

---

## gostr341194

**Reviewer summary:** The parity package is genuinely sound on the correctness dimension: the oracle is the real gogost gost341194 implementation reached through the gostcryptocompat facade (primitives_gost.go:191-195 -> third_party/gogost/gost341194/hash.go), which is structurally independent of the clean-room code (different byte order, big.Int checksum, blockReverse convention), so the diff is non-tautological; all comparisons are full bytes.Equal on 32-byte digests; the deterministic test covers ~219 lengths spanning block boundaries up to 4096+ bytes, TestDiffStreaming covers multi-chunk Writes (including the buffered partial-block path), and the fuzz target diffs both one-shot and a fuzzer-chosen split. The known GOST R 34.11-94 empty-input finalization divergence (guide D1, logged in gostcrypto/TODO.md and docs/engine-vectors.md) is correctly and explicitly excluded from both the table test (lengths strictly > 0) and the fuzz target (t.Skip on len==0, non-empty seeds only) — that exclusion is the documented intentional divergence, not a defect. Remaining gaps are coverage-shaped and modest: Reset/instance reuse, the explicitly-documented non-destructive-Sum (D8) semantics, and Sum-with-prefix are never diffed against the oracle, the fuzzer can only generate two-chunk streaming sequences, and no fuzz corpus beyond the three in-code seeds is committed.

### [R94-01] Reset()/instance-reuse parity is never exercised

- **Location:** `parity/gostr341194/gostr341194_parity_test.go:89-112`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The clean-room digest exposes Reset() (gostcrypto/gostr341194/gostr341194.go:301-303) and gogost's Hash has a non-trivial Reset of its own, but every parity path constructs a fresh hash per message. A Reset-then-rehash sequence is never diffed against the oracle, so a state field accidentally left out of Reset (e.g. a future refactor splitting *d = digest{} into per-field clears) would not be caught by the parity gate.

**Evidence:** All three test paths use `Sum(msg)` or `h := New()` per message; `Reset` does not appear anywhere in parity/gostr341194/. Clean-room Reset: `func (d *digest) Reset() { *d = digest{} }`.

**Verifier confirmation:** The finding is accurate on all three factual claims.

1. Reset() is absent from parity/gostr341194/: confirmed — `grep -rn "Reset"` on that directory returns no hits. The single file `parity/gostr341194/gostr341194_parity_test.go` contains only `TestDiffAgainstInternalGost`, `FuzzDiffAgainstInternalGost`, and `TestDiffStreaming`, each of which constructs a fresh hash per message (via `gost.GOSTR341194(msg)` which calls `gost341194.New()` internally, or via `New()` in the streaming path).

2. Clean-room Reset is `*d = digest{}` (gostr341194.go:301-303). This is a total struct zero; all five fields (`h`, `sum`, `len`, `buf`, `nbuf`) are zeroed atomically. It cannot be partially wrong in its current form.

3. Gogost's Reset (third_party/gogost/gost341194/hash.go:73-83) is per-field: `h.size=0`, `h.hsh=[BlockSize]byte{...zeros...}`, `h.chk=big.NewInt(0)`, `h.buf=h.buf[:0]`. The `sbox` field is intentionally not touched (it's the parameter). Semantically equivalent to the clean-room's zero-struct, but structurally disjoint.

4. Neither TODO.md nor docs/engine-vectors.md documents this gap as intentional.

The risk the finding describes is real but narrow: the current `*d = digest{}` implementation is correct and cannot be partially wrong. The gap only matters if a future refactor replaces the single-assignment Reset with per-field clears and misses a field (e.g., forgets `nbuf` or `sum`). No such refactor exists today, hence the severity stays low. The `NewGOSTR341194CryptoProHash()` export in `exports_gost.go` returns a `hash.Hash` with a working Reset, so adding the differential is straightforward.

**Suggested fix:** Add a `TestDiffReset` function to `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/gostr341194/gostr341194_parity_test.go`:

```go
// TestDiffReset verifies that Reset() followed by re-hashing produces the
// same digest as a fresh instance, and that both match the gogost oracle.
// Guards against a partial-clear refactor of Reset leaving a stale field.
func TestDiffReset(t *testing.T) {
    rng := rand.New(rand.NewSource(0xRESET))
    oracle := gost.NewGOSTR341194CryptoProHash() // gogost-backed, also a hash.Hash

    for i := 0; i < 50; i++ {
        // First message (must be non-empty to stay outside the D1 divergence).
        n1 := 1 + rng.Intn(512)
        msg1 := make([]byte, n1)
        rng.Read(msg1)

        // Second message (also non-empty).
        n2 := 1 + rng.Intn(512)
        msg2 := make([]byte, n2)
        rng.Read(msg2)

        // Clean-room: hash msg1, Reset, hash msg2.
        h := New()
        h.Write(msg1)
        h.Reset()
        h.Write(msg2)
        gotAfterReset := h.Sum(nil)

        // Oracle: same sequence.
        oracle.Write(msg1)
        oracle.Reset()
        oracle.Write(msg2)
        wantAfterReset := oracle.Sum(nil)
        oracle.Reset()

        if !bytes.Equal(gotAfterReset, wantAfterReset) {
            t.Fatalf("post-Reset len=%d mismatch:\n clean-room %x\n gogost     %x", n2, gotAfterReset, wantAfterReset)
        }

        // Also verify it matches a freshly-constructed hash of msg2.
        fresh := Sum(msg2)
        if !bytes.Equal(gotAfterReset, fresh[:]) {
            t.Fatalf("Reset result differs from fresh hash for len=%d:\n after-Reset %x\n fresh       %x", n2, gotAfterReset, fresh[:])
        }
    }
}
```

`gost.NewGOSTR341194CryptoProHash()` is already exported from the `gostcryptocompat` package (`exports_gost.go:42`), so no new export is needed.

### [R94-02] Non-destructive Sum semantics (guide D8) untested against the oracle

- **Location:** `parity/gostr341194/gostr341194_parity_test.go:80,106`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The clean-room Sum explicitly snapshots state so that Sum is non-destructive and the hash can keep absorbing afterwards (gostcrypto/gostr341194/gostr341194.go:354-357, comment 'Snapshot state so Sum is non-destructive (guide D8)'). gogost's gost341194.Hash.Sum is also non-destructive (it copies size/chk/hsh into locals, third_party/gogost/gost341194/hash.go:246-249), so a meaningful parity check exists: Sum mid-stream, Write more, Sum again, and diff both digests. The parity test never calls Sum twice or Write-after-Sum on the same instance, so a regression that makes the clean-room Sum destructive on a pending partial block (the exact bug gogost's gost28147.MAC has) would pass the parity gate.

**Evidence:** Every parity path calls h.Sum(nil) exactly once and discards the hash. Clean-room code carries an explicit invariant comment for this behaviour that no parity test validates.

**Verifier confirmation:** The finding is factually correct on every code-level claim.

1. The clean-room `digest` struct uses only value types: `h [BlockSize]byte`, `sum [BlockSize]byte`, `len uint64`, `buf [BlockSize]byte`, `nbuf int` (lines 284-290 of gostcrypto/gostr341194/gostr341194.go). The `Sum` snapshots at lines 354-358 are therefore true value copies with no aliasing.

2. The current `Sum` at lines 354-385 is non-destructive: it reads from the snapshots (`h`, `sum`, `totalBits`) and never writes back to `d.h`, `d.sum`, `d.len`, `d.buf`, or `d.nbuf`.

3. The gogost oracle's `Sum` (third_party/gogost/gost341194/hash.go:246-267) is also non-destructive via the same local-copy pattern, so a meaningful cross-check exists: both sides should return the same digest from an intermediate `Sum` call, and both should allow a `Write`→`Sum`→`Write`→`Sum` sequence where the second `Sum` equals the digest of the full message.

4. The parity test (parity/gostr341194/gostr341194_parity_test.go) never exercises this: `FuzzDiffAgainstInternalGost` (line 80) and `TestDiffStreaming` (line 106) both call `h.Sum(nil)` exactly once on a completed hash and discard the instance. No test does `Write`→`Sum`→`Write`→`Sum` on a single hasher.

5. This is not a documented divergence: `CLAUDE.md`'s mention of destructive `Sum` is specifically about `gost28147.MAC.Sum` (a different primitive), and `TODO.md`/`docs/engine-vectors.md` address the empty-input D1 disagreement, not Sum-destructiveness. The comment "guide D8" in the clean-room source names an invariant that the parity gate does not validate.

The severity is **low** rather than medium: the current implementation is correct and non-destructive today; the risk is only that a future regression in this specific property would evade the parity gate. No consumer is known to rely on the mid-stream Sum pattern for this primitive, and the hash's value-type struct makes accidental aliasing unlikely. The gap is a test coverage weakness, not an active defect.

**Suggested fix:** Add a test in `parity/gostr341194/gostr341194_parity_test.go` that exercises the non-destructive-Sum invariant against the oracle on both sides:

```go
// TestSumNonDestructive verifies guide D8: calling Sum mid-stream must not
// corrupt the in-progress hash state so that subsequent Writes and a second
// Sum still produce the correct digest.
func TestSumNonDestructive(t *testing.T) {
    rng := rand.New(rand.NewSource(0xDEAD))

    for i := 0; i < 50; i++ {
        n := 1 + rng.Intn(2048)
        msg := make([]byte, n)
        rng.Read(msg)

        // Choose a split point to call Sum mid-stream.
        split := rng.Intn(n + 1) // 0..n inclusive

        // Clean-room: write first half, take intermediate Sum, write second half, take final Sum.
        h := New()
        h.Write(msg[:split])
        midSum := h.Sum(nil) // must not destroy state
        h.Write(msg[split:])
        finalSum := h.Sum(nil)

        // Oracle: same sequence.
        og := gost.NewGOSTR341194()
        og.Write(msg[:split])
        ogMid := og.Sum(nil)
        og.Write(msg[split:])
        ogFinal := og.Sum(nil)

        // Mid-stream digests must match each other.
        if !bytes.Equal(midSum, ogMid) {
            t.Fatalf("mid-stream split=%d len=%d mismatch:\n clean-room %x\n oracle %x", split, n, midSum, ogMid)
        }
        // Final digests (after the extra Write) must match each other and the one-shot oracle.
        wantFull := gost.GOSTR341194(msg)
        if !bytes.Equal(finalSum, ogFinal) {
            t.Fatalf("post-mid-Sum final split=%d len=%d mismatch:\n clean-room %x\n oracle %x", split, n, finalSum, ogFinal)
        }
        if !bytes.Equal(finalSum, wantFull) {
            t.Fatalf("post-mid-Sum final split=%d len=%d differs from one-shot:\n got %x\n want %x", split, n, finalSum, wantFull)
        }
        _ = midSum // already checked
    }
}
```

This requires exposing `NewGOSTR341194() hash.Hash` from `gostcryptocompat` (or using the gogost oracle directly). If the compat package already exposes a `hash.Hash`-returning constructor, use it; otherwise add a thin wrapper. The test validates both that intermediate `Sum` returns the correct partial-message digest and that the hasher remains fully functional after the call.

### [R94-03] Sum(in) append-prefix path always called with nil

- **Location:** `parity/gostr341194/gostr341194_parity_test.go:80,106`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** hash.Hash.Sum(in) must append the digest to in. Both sides implement `return append(in, h[:]...)`, but the parity test only ever passes nil, so the prefix-preserving contract (and any future off-by-one in the append) is unexercised. Minor because the one-shot Sum(b) wrapper indirectly covers Sum(nil).

**Evidence:** Only call forms are `Sum(msg)` (one-shot) and `h.Sum(nil)`; no `h.Sum(prefix)` anywhere in the package.

**Verifier confirmation:** The finding is factually correct. Every call to the `hash.Hash.Sum` method in `parity/gostr341194/gostr341194_parity_test.go` passes `nil` (lines 80 and 106). The package-level `Sum(msg)` calls at lines 38 and 70 invoke the one-shot wrapper which itself calls `d.Sum(nil)` (gostcrypto/gostr341194/gostr341194.go:403). No call in the package — not in the parity tests, not in the clean-room unit tests at `gostcrypto/gostr341194/gostr341194_test.go` — ever passes a non-nil prefix to `hash.Hash.Sum`.

Both implementations are `return append(in, digest[:]...)` — clean-room at gostr341194.go:384 and gogost oracle at gogost/gost341194/hash.go:266 — and both are structurally identical, making an actual divergence essentially impossible. This is a test-coverage gap, not a cryptographic bug. The differential nature of the missing test (comparing both sides with the same non-nil prefix) would catch any future off-by-one in the append contract. Severity is correctly low: the uncovered code path is not cryptographically sensitive and both sides implement it identically via `append`.

**Suggested fix:** Add a sub-case in `TestDiffStreaming` (or a new `TestSumAppendPrefix`) in `parity/gostr341194/gostr341194_parity_test.go` that passes a non-nil prefix to both sides and asserts the results match:

```go
prefix := []byte{0xDE, 0xAD, 0xBE, 0xEF}
msg := []byte("This is message, length=32 bytes")
h := New()
h.Write(msg)
gotWithPrefix := h.Sum(prefix)
// oracle side
ho := gogost_new()
ho.Write(msg)
wantWithPrefix := ho.Sum(prefix)
if !bytes.Equal(gotWithPrefix, wantWithPrefix) {
    t.Fatalf("Sum(prefix) mismatch: got %x want %x", gotWithPrefix, wantWithPrefix)
}
// Also verify prefix is preserved
if !bytes.Equal(gotWithPrefix[:len(prefix)], prefix) {
    t.Fatalf("Sum(prefix) dropped prefix: got %x", gotWithPrefix[:len(prefix)])
}
```

This can be appended to `FuzzDiffAgainstInternalGost` as a secondary check after the existing streaming assertion, or as a standalone table-driven test.

### [R94-04] Fuzz streaming path uses exactly one split (two Write calls)

- **Location:** `parity/gostr341194/gostr341194_parity_test.go:76-79`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** FuzzDiffAgainstInternalGost varies the message bytes and a single split offset, so the fuzzer can only produce two-chunk Write sequences. Multi-chunk fragmentation (where the clean-room buf-fill loop at gostr341194.go:308-322 interacts repeatedly with full-block processing) is only covered by TestDiffStreaming with a fixed PRNG seed (0x1234), not by fuzzing. Deriving several split points from the fuzz input (e.g. a second offset, or chunk sizes from extra bytes) would let the fuzzer explore partial-buffer carry-over sequences the fixed test cannot.

**Evidence:** f.Fuzz signature is `func(t *testing.T, msg []byte, split uint)`; the body does `h.Write(msg[:off]); h.Write(msg[off:])` — exactly two writes. The fuzz target's own comment claims it is the companion to TestDiffStreaming, but it cannot reproduce that test's many-chunk pattern.

**Verifier confirmation:** The finding's factual claims are accurate and the coverage gap is real.

**What the code actually does (lines 62-84):**
- `FuzzDiffAgainstInternalGost` takes `(msg []byte, split uint)`, computes `off := int(split % uint(len(msg)+1))`, and does exactly two writes: `h.Write(msg[:off])` then `h.Write(msg[off:])`. No more writes follow.

**What the Write method's buf-fill loop does (gostr341194.go:308-322):**
- The partial-block accumulator (`d.nbuf`, `d.buf`) is only filled-and-drained more than once if there are three or more writes where intermediate writes do not exactly align to a block boundary. Specifically: Write A partially fills buf → Write B completes the block (processes it, resets `nbuf=0`) and may leave a new partial block → Write C then exercises the buf-fill path again with fresh partial state. This three-or-more-write chaining cannot be produced by the fuzz target with a single `split` parameter.

**What TestDiffStreaming covers (lines 89-112):**
- Uses `rand.New(rand.NewSource(0x1234))`, writes chunks of size 1–40 bytes over messages up to 2048 bytes, exercising 50–2048 individual Write calls per message. This does cover multi-chunk carry-over, but only with fixed PRNG seed 0x1234 and 100 samples. The fuzzer cannot explore this space.

**No seed corpus compensates:** No `testdata/fuzz/FuzzDiffAgainstInternalGost/` directory exists, so there are no stored multi-split inputs that would give the fuzzer a head start.

**Why severity is low (not medium/high):**
- GOST R 34.11-94 is a Merkle-Damgård hash. The `Write` method's buf-fill logic is straightforward and deterministic: the only state carried between calls is `d.nbuf` bytes in `d.buf`, a running checksum `d.sum`, a running length `d.len`, and the chained hash value `d.h`. There is no conditional branching that depends on the *number* of prior writes — only on the current content of `d.nbuf`. A two-write test already exercises the single buf-fill-and-drain transition. The multi-write scenario replicates that same transition multiple times but introduces no new code paths. The risk of an undetected bug is real but small.
- `TestDiffStreaming` at seed 0x1234 with 100 samples provides substantial deterministic coverage of the multi-chunk path, just not fuzz-driven coverage.

**Suggested fix:** Add a second split parameter (or a slice of chunk sizes derived from extra fuzz bytes) to allow three or more Write calls. The minimal change is to add `split2 uint` and do three writes:

```go
f.Fuzz(func(t *testing.T, msg []byte, split uint, split2 uint) {
    if len(msg) == 0 {
        t.Skip("empty input is the documented D1 gogost/engine divergence")
    }
    want := gost.GOSTR341194(msg)

    got := Sum(msg)
    if !bytes.Equal(got[:], want) {
        t.Fatalf("one-shot len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", len(msg), got[:], want)
    }

    // Three-way streaming split.
    off1 := int(split % uint(len(msg)+1))
    off2 := off1 + int(split2%uint(len(msg)-off1+1))
    h := New()
    h.Write(msg[:off1])
    h.Write(msg[off1:off2])
    h.Write(msg[off2:])
    gotStream := h.Sum(nil)
    if !bytes.Equal(gotStream, want) {
        t.Fatalf("streaming len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", len(msg), gotStream, want)
    }
})
```

Update the seed corpus accordingly (add a third `uint` seed value to each `f.Add` call). This lets the fuzzer explore buf-fill-and-drain transitions across three consecutive writes, covering the multi-chunk carry-over path that currently only has deterministic coverage.

### Dismissed for gostr341194 (do NOT act on these)

#### DISMISSED: No committed fuzz corpus beyond three in-code seeds

- **Location:** `parity/gostr341194/ (no testdata/fuzz directory)` · **Category:** fuzz-gap · **Severity claimed:** low · **Verifier:** sonnet

**Original claim:** The package has no testdata/fuzz/FuzzDiffAgainstInternalGost corpus; `go test` replays only the three f.Add seeds (lengths 1, 32, 257). The module convention ('go test ./... replays fuzz seeds') is technically met, but interesting inputs discovered by past `make fuzz` runs were never checked in, so regular CI replay coverage stays at three points. Seeds are correctly all non-empty, matching the documented D1 empty-input exclusion (that exclusion itself is the documented divergence, not a finding).

**Why dismissed:** The finding characterises coverage as "three f.Add seeds" and concludes that regular CI replay coverage "stays at three points." That framing is wrong because it ignores the two deterministic table-driven tests that run unconditionally on every `go test` invocation:

1. `TestDiffAgainstInternalGost` (lines 23-43): builds a slice of 19 fixed boundary lengths (1, 2, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 100, 255, 256, 257, 1023, 1024, 2100) plus 200 pseudo-random lengths seeded at `0xC0FFEE`, for 219 total one-shot diffs. This covers every block-boundary and near-boundary case for the 32-byte GOST R 34.11-94 block, plus arbitrary-length messages up to 4096 bytes.

2. `TestDiffStreaming` (lines 89-112): 100 randomly-sized messages (seed `0x1234`) driven through the `hash.Hash` streaming interface in odd chunk sizes of 1-40 bytes, diffed against the oracle.

Both tests run on every `go test ./...` in CI — they are not gated on `-fuzz`. The fuzz function's three `f.Add` seeds are only replayed by `go test` as additional inputs *on top of* the 219+100 deterministic cases. The CLAUDE.md convention ("`go test` replays only the committed seed corpus") refers to `testdata/fuzz/` files; those are intentionally absent module-wide — `gost28147imit` has the `testdata/fuzz/FuzzDiff_InternalGostOracle/` directory but it is also empty, confirming this is the standard pattern, not a gap unique to `gostr341194`.

The only true statement in the finding is that `testdata/fuzz/` does not exist. But the absence of a committed fuzz corpus does not create a meaningful coverage gap here: the deterministic tests already exercise all structural block boundaries for a pure hash function with no input-dependent control flow beyond length. The claim that "interesting inputs discovered by past `make fuzz` runs were never checked in" is speculation — there is no evidence any such corpus entry was ever produced, and a missing entry would have surfaced as a test failure before being committed. Severity is none.

---

## kdftree

**Reviewer summary:** The kdftree parity test is non-vacuous and correctly engineered around the documented gogost limitation (KDF.Derive is the single-block §4.5 KDF hardcoding counter 0x01 and L=0x0100 — delta D1), gating the raw-gogost comparison to the 32-byte case and pinning the 64-byte case to an independent gost-engine etalon (test_keyexpimp.c, verified to be the source of the hardcoded vector). Comparisons are full bytes.Equal on outputs with no skips or swallowed errors, and label/seed are genuinely fuzzed. The structural weakness is oracle independence: the primary oracle (gostcryptocompat.KDFTree2012_256) reimplements the same loop in the same project, drawing only the hash from gogost, so fuzzed 64-byte comparisons validate the Streebog hash rather than the tree layering, which rests on the single fixed KAT-1. Coverage gaps are real but moderate: r is hardcoded to 1 (r=2..4, outLen>64, and final-block truncation are parity-untested, though covered by in-module clean-room tests), the fuzz key is forced to exactly 32 bytes, and — most concretely — a seed-encoding slip (lenSel&1 with even seed values 64 and 32) means the committed fuzz corpus never replays the multi-block path during ordinary `go test` runs.

### [KDF-01] Primary differential oracle is a same-project reimplementation, not gogost; multi-block independence rests on one fixed KAT

- **Location:** `parity/kdftree/kdftree_parity_test.go:57 and kdftree_gost.go:25-48`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** Reference 1 (gostref.KDFTree2012_256) is not a gogost primitive: it re-rolls the same counter/0x00-separator/L-suffix loop in this module, drawing only the inner Streebog-256 hash from gogost (hmac.New(gost34112012256.New, key)). Both sides were written by the same project from the same spec notes, so a correlated misreading of the tree layering (counter encoding, separator placement, L value) would pass the facade diff. This is a documented necessity — gogost's KDF.Derive hardcodes counter 0x01 and L=0x0100 (D1) so it cannot produce >32 bytes — and is mitigated by the independent gost-engine KAT-1 (64B, tmp/engine/test_keyexpimp.c:78-97) and by raw gogost Derive at 32B. But in the fuzz loop, every 64-byte comparison reduces to hash-level parity only; the multi-block layering is independently validated solely by the single fixed KAT-1 input.

**Evidence:** kdftree_gost.go:38-45 reimplements the loop: `h := hmac.New(gost34112012256.New, key); h.Write([]byte{byte(i)}); h.Write(label); h.Write([]byte{0x00}); h.Write(seed); h.Write(lenBE[:])` — structurally identical to clean-room kdftree.go:76-84. The only gogost code exercised at 64B is the hash constructor.

**Verifier confirmation:** The finding is structurally accurate on every factual claim but overstates the unmitigated risk.

**What is confirmed:**

1. `gostref.KDFTree2012_256` (`kdftree_gost.go:38-45`) is not a gogost primitive. It reimplements the RFC 7836 §4.4 counter loop itself and borrows only the hash constructor from gogost (`hmac.New(gost34112012256.New, key)`). The loop structure — counter byte, label, 0x00 separator, seed, L-bytes — is structurally identical to the clean-room `kdftree.go:76-84`. Both were written by the same project from the same spec guide.

2. In `FuzzKDFTree256Conformance`, the `lenSel&1` selector constrains `keyOutLen` to exactly 32 or 64. At 64B the only oracle is `gostref.KDFTree2012_256` (line 96); raw gogost `Derive` is only checked at 32B (line 101). A correlated structural error — wrong counter direction, wrong L-encoding for the 64B case, swapped separator position — affecting both implementations identically would pass every fuzz iteration.

3. The facade's L-encoding (`binary.BigEndian.PutUint16`, always 2 bytes) diverges structurally from the clean-room's `encodeNoLeadingZeros` (variable length). This difference is invisible for 32B (`0x0100`) and 64B (`0x0200`) because both encodings produce the same bytes; it would surface at 16B (`0x80` vs `0x0080`) but the fuzz never generates such lengths.

**Why severity is low, not medium:**

The finding correctly names the mitigation: `kdftree_parity_test.go:38-39` embeds KAT-1 — the 64B gost-engine etalon from `tmp/engine/test_keyexpimp.c:78-97`. That vector is external (C source, independently derived from the GOST spec), not produced by either Go implementation. KAT-1 covers the two-block tree output byte-for-byte, and both individual iterations K(1) and K(2) are separately pinned in `kdftree_test.go:TestKDFTree256_KAT1_PerIteration`. The RFC 7836 Appendix B KAT-2 independently pins the 32B case from the spec text. The correlated-error scenario the finding describes would have to survive KAT-1, which comes from a completely independent source. This is a test-architecture quality concern (the fuzz oracle could be stronger), not an undetected correctness gap.

**Specific code citations:**
- Correlated-oracle risk: `kdftree_gost.go:38-45` vs `kdftree.go:76-84` — structurally parallel loops, same project.
- Fuzz oracle gap: `kdftree_parity_test.go:91-105` — 64B path checks only `gostref`, 32B path also checks raw gogost `Derive`.
- External mitigation: `kdftree_parity_test.go:38-39` (KAT-1 pinned from gost-engine) and `kdftree_test.go:TestKDFTree256_KAT1_PerIteration` (per-block pins).
- L-encoding structural divergence: `kdftree_gost.go:34-35` (`PutUint16`) vs `kdftree.go:72-73` (`encodeNoLeadingZeros`) — only visible outside the 32B/64B fuzz range.

**Suggested fix:** Add a second independent gost-engine KAT in the parity test to cover a fuzz-reachable multi-block case, and optionally extend the fuzz oracle:

1. **Second KAT from gost-engine**: Add a KAT for a different key/label/seed to `TestKDFTree256Conformance` (or a new table row), also pinned at 64B against the gost-engine etalon. Even one additional engine KAT with a distinct key materially raises the bar for a correlated error surviving undetected.

2. **Extend fuzz to a third output length**: In `FuzzKDFTree256Conformance`, add `lenSel == 2` → `keyOutLen = 96` (3 blocks). At 96B the facade would still agree on L-encoding (0x0300 from both). The point is to have the fuzz exercise a 3-block path where the only pinned anchor for correctness is the external KAT-1, making it harder for a systematic counter or separator bug to hide.

3. **Direct gogost-level cross-check at 64B** (addresses the oracle structure concern directly): In the fuzz body, for `keyOutLen == 64`, manually call `hmac.New(gost34112012256.New, key)` twice with explicit counter bytes `[]byte{0x01}` and `[]byte{0x02}`, the literal 0x00 separator, and `lenBE = []byte{0x02, 0x00}`, and compare the concatenated result against `got`. This in-test assembly uses gogost's hash directly without relying on the compat module's loop, making it an independent oracle at hash level for the 64B multi-block case.

The KAT-1 pinning already provides the most important guard; these additions strengthen fuzz coverage quality rather than fixing an active correctness gap.

### [KDF-02] 32-byte case omits the authoritative RFC 7836 example-9 pin (want="")

- **Location:** `parity/kdftree/kdftree_parity_test.go:42-47`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** The KAT-2/32B table entry uses the exact key/label/seed of RFC 7836 Appendix B example 9, for which an authoritative pinned vector exists (a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9, documented in ../gostcrypto/kdftree/kdftree2012-256.md:257-273), yet the test sets want: "" and relies only on cross-implementation diffing. The gogost Derive check does make this case independently validated, so this is a missed free hardening rather than a vacuous test.

**Evidence:** Test comment line 31: `want string // "" => no pinned etalon, cross-check refs only` with KAT-2 entry `want: ""` despite kdftree2012-256.md §KAT-2 providing the RFC byte-pinned etalon for the same inputs.

**Verifier confirmation:** The finding is accurate. Reading the evidence directly:

1. `gostcrypto-compat/parity/kdftree/kdftree_parity_test.go:41-47`: The KAT-2/32B entry has `want: ""`, so the pinned-vector branch at lines 61-65 is skipped for this case. The test comment at line 31 confirms this is intentional: `want string // "" => no pinned etalon, cross-check refs only`.

2. `gostcrypto/kdftree/kdftree2012-256.md:257-273`: KAT-2 is explicitly documented as "RFC 7836 Appendix B example 9" with the authoritative expected output `a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9`. The md file at lines 269 and 285 explicitly names this as "authoritative RFC vector" and states `TestKDFTree256_KAT2_32B` pins it.

3. `gostcrypto/kdftree/kdftree_test.go:72-104` (`TestKDFTree256_KAT2_32B`): The clean-room module's own unit test already pins this RFC 7836 example 9 vector at line 80: `want := mustHex(t, "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")`.

4. `gostcrypto/TODO.md` and `gostcrypto-compat/docs/engine-vectors.md`: Neither file documents any known divergence for the KDF tree / RFC 7836 example 9 vector. The three known gogost/engine divergences (S-box row order, R 34.11-94 empty-input finalization, CryptoPro key meshing) do not touch this primitive (confirmed by kdftree2012-256.md §D5).

5. The parity test is NOT vacuous: lines 67-72 still cross-check the 32B output against raw `gost34112012256.NewKDF(key).Derive(nil, label, seed)`, providing independent oracle validation. But the authoritative RFC byte-pin is simply missing.

The omission is exactly as described: the parity test for the 32B case has a free authoritative pin available (from the same md spec used to build the clean-room impl) but leaves `want: ""`. This is a hardening gap — a future silent mismatch would be caught by the gogost cross-check, not by an RFC-authoritative assertion. The severity is low because `TestKDFTree256_KAT2_32B` in the clean-room module already provides the byte-level pin that's absent from the parity test.

**Suggested fix:** In `gostcrypto-compat/parity/kdftree/kdftree_parity_test.go`, change line 46 from `want: ""` to the RFC 7836 Appendix B example 9 vector:

```go
{
    name:      "KAT-2/32B",
    label:     mustHexG(t, "26BDB878"),
    seed:      mustHexG(t, "AF21434145656378"),
    keyOutLen: 32,
    want:      "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
},
```

This fills the exact same RFC 7836 Appendix B example 9 pin already present in `gostcrypto/kdftree/kdftree_test.go:80`. No other changes are needed — the existing test logic at lines 61-65 already handles a non-empty `want`.

### [KDF-03] Counter width r=2..4, outLen>64 (counter >= 3), and truncation to non-multiples of 32 never exercised in parity

- **Location:** `parity/kdftree/kdftree_parity_test.go:52,91`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The clean-room KDFTree256 publicly supports r in 1..4 (counterBytes, kdftree.go:92-98), arbitrary positive outLen with final-block truncation (kdftree.go:87 `out[:outLen]`), and up to 8160 bytes at r=1. The parity test hardcodes r=1 at both call sites and only ever requests 32 or 64 bytes, so: (a) the multi-byte counter encoding (low-r-bytes big-endian, delta D3) is never diffed against anything in this module; (b) iteration counters >= 3 are never produced; (c) the truncation path is never parity-tested. The facade oracle panics on non-multiples of 32 and only supports r=1, but an inline HMAC(gogost-hash) oracle (as the clean-room's own in-module tests already do) could cover all three. The in-module tests in ../gostcrypto/kdftree/kdftree_test.go do cover these against an in-test oracle, so this is a parity-coverage gap, not a wholly untested surface.

**Evidence:** Line 52: `got := KDFTree256(key, tc.label, tc.seed, 1, tc.keyOutLen)` and line 91: `got := KDFTree256(key, label, seed, 1, keyOutLen)` — r is the literal 1 in both; keyOutLen is drawn only from {32, 64}.

**Verifier confirmation:** The finding is correct in its factual claims but overstates the practical severity.

**What is confirmed:**

1. Both call sites in `parity/kdftree/kdftree_parity_test.go` hardcode `r=1` (lines 52 and 91), and `keyOutLen` is drawn only from {32, 64}. Counter values >= 3 and non-multiples-of-32 truncation are never exercised through the parity-test oracle.

2. The facade oracle `gostcryptocompat.KDFTree2012_256` (`kdftree_gost.go:25-48`) has no `r` parameter, hardcodes a 1-byte counter (`byte(i)` at line 40), and panics on non-multiple-of-32 lengths (line 26). This structurally prevents the parity test from diffing those paths against gogost.

3. There is no entry in `gostcrypto/TODO.md` or `gostcrypto-compat/docs/engine-vectors.md` documenting this as an intentional divergence.

**Why severity is low (not medium):**

The clean-room in-module tests at `gostcrypto/kdftree/kdftree_test.go` do exercise the uncovered paths — but against an inline HMAC oracle, not against gogost. Specifically:
- `TestKDFTree256_CounterWidth` (line 179) covers r=2,3,4 via `oracleHMAC`.
- `TestKDFTree256_Truncation` (line 113) covers outLen=40 (non-multiple-of-32) and outLen=16.
- `TestKDFTree256_CounterOverflowPanic` (line 231) exercises the full 255-iteration r=1 path.

Additionally, the clean-room implementation's doc comment (`kdftree.go:39-41`) explicitly documents: "Violations panic — callers in this repo always pass r=1 with outLen a positive multiple of 32". The r>1 and truncation paths are generalization not exercised in any actual deployment in this workspace. There is no gogost counterpart for r>1 since `gost34112012256.KDF.Derive` only produces 32 bytes (documented in the CLAUDE.md gogost gotchas). So building a gogost oracle for those paths would require a from-scratch HMAC oracle — identical in nature to the one already used in the in-module tests.

The gap is real: the parity module does not independently diff r>1 and truncation against any reference, leaving those paths covered only by internal tests but not a cross-implementation check. That is a test-coverage gap at the parity layer, not a correctness bug.

**Suggested fix:** Extend `FuzzKDFTree256Conformance` in `parity/kdftree/kdftree_parity_test.go` to use an inline HMAC-Streebog-256 oracle (like the `oracleHMAC` function already in `gostcrypto/kdftree/kdftree_test.go`, duplicated into a `helpers_test.go` here) to cover r>1 and non-multiple-of-32 outLen. Concretely:

1. Add an `oracleHMAC(key, counterBytes, label, seed, lRepr []byte) []byte` helper using `gost34112012256.New` (from gogost, already imported) as the HMAC hash.
2. In the fuzz function, additionally generate `r` from 1..4 via `lenSel >> 4 % 4 + 1` and `outLen` as any value 1..64 via `lenSel & 0x3F + 1`.
3. For these inputs, build the expected output block-by-block using `oracleHMAC` with the appropriate r-byte counter encoding and the correct `[L]_b` encoding (min big-endian of outLen*8), then compare against `KDFTree256(key, label, seed, r, outLen)`.
4. Add a deterministic table test case with r=2, outLen=40 using a pinned expected value computed by the same oracle.

This mirrors exactly what `TestKDFTree256_CounterWidth` and `TestKDFTree256_Truncation` do in the in-module tests, but rooted in the gogost HMAC primitive, making it a true parity test rather than a consistency check against an in-package oracle.

### [KDF-04] Committed fuzz seeds never replay the 64-byte multi-block path: lenSel&1 maps the seed value 64 to keyOutLen=32

- **Location:** `parity/kdftree/kdftree_parity_test.go:78-89`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Seed #0 passes uint8(64), plainly intending the 64-byte KAT-1 configuration (it reuses KAT-1's key/label/seed), but the fuzz body computes `keyOutLen = 64` only when `lenSel&1 == 1`; 64&1 == 0 and 32&1 == 0, so BOTH committed seeds resolve to keyOutLen=32. There is no testdata/ corpus directory either, so `go test` seed replay (the parity gate run in CI) never executes the two-iteration branch of the fuzz target at all — that branch only runs under active `make fuzz`. Either fix the seeds to odd values for the 64B case or decode lenSel differently.

**Evidence:** Line 80: `f.Add(..., uint8(64))`; line 87-89: `if lenSel&1 == 1 { keyOutLen = 64 }`. 64 is even, so keyOutLen stays 32. Confirmed no committed corpus: parity/kdftree/testdata does not exist.

**Verifier confirmation:** The arithmetic claim is exactly correct. In `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/kdftree/kdftree_parity_test.go`:

- Line 80: `f.Add(..., uint8(64))` — seed #0 passes lenSel=64
- Line 81: `f.Add(..., uint8(32))` — seed #1 passes lenSel=32
- Lines 87-89: `if lenSel&1 == 1 { keyOutLen = 64 }`

`64&1 == 0` and `32&1 == 0`, so both seeds leave `keyOutLen=32`. The 64-byte (`keyOutLen=64`) branch of `FuzzKDFTree256Conformance` is never reached during `go test` seed replay, confirming the fuzz seed intent is broken.

No testdata/ directory exists at `parity/kdftree/testdata/`, confirmed by `ls` returning "No such file or directory".

**Why severity is adjusted down from medium to low:** `TestKDFTree256Conformance` (lines 24-75) already exercises the 64-byte two-iteration differential path directly: the "KAT-1/64B" case at lines 33-47 calls `KDFTree256` with `keyOutLen=64` and compares against both `gostref.KDFTree2012_256` and a pinned authoritative vector. The differential parity of the multi-block path IS covered by the table-driven test on every `go test` run. The fuzz seed bug means the *fuzz target's* two-iteration branch is untested during seed replay and can only reach it under active `make fuzz` — but this is a test quality / coverage gap in the fuzz corpus rather than a missing parity check entirely.

**Suggested fix:** In `parity/kdftree/kdftree_parity_test.go`, change seed #0's `lenSel` from `uint8(64)` to `uint8(65)` (odd) so it resolves to `keyOutLen=64`:

```go
// Line 80: change uint8(64) → uint8(65)
f.Add([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"+
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
    []byte("\x26\xbd\xb8\x78"), []byte("\xaf\x21\x43\x41\x45\x65\x63\x78"), uint8(65))
```

Alternatively, decode `lenSel` more intuitively as a direct switch: `if lenSel >= 128 { keyOutLen = 64 }` (high-bit flag), or use `lenSel%2 == 0` → 32, `lenSel%2 == 1` → 64 and fix the seed to an odd value. The simplest one-line fix is changing `uint8(64)` to `uint8(65)` on line 80.

### [KDF-05] Fuzz never varies HMAC key length (forced to exactly 32 bytes) nor output length beyond {32,64}

- **Location:** `parity/kdftree/kdftree_parity_test.go:84-90`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The fuzz body does `key := make([]byte, 32); copy(key, rawKey)`, truncating/zero-padding every fuzzer-chosen key to exactly 32 bytes. Keys longer than the 64-byte HMAC block size (which trigger the hash-the-key path inside crypto/hmac, exercising clean-room vs gogost Streebog on the key itself) and short/empty keys are never differentially tested, even though both KDFTree256 and the facade accept any key length. Similarly, lenSel selects only 32 or 64; mapping it across all multiples of 32 up to 8160 would exercise per-iteration counter bytes 0x03..0xFF against the facade for free. Label/seed lengths ARE properly fuzzed, and the empty-input-divergence concern (R 34.11-94) is inapplicable here — the HMAC message always contains at least i_b||0x00||L_b, per delta D5 — so no empty-only seeding is required.

**Evidence:** Lines 84-85: `key := make([]byte, 32); copy(key, rawKey)`; lines 86-89 restrict keyOutLen to 32/64. Facade signature `KDFTree2012_256(key, label, seed []byte, keyOutLen int)` accepts any key length and any positive multiple of 32 up to 8160.

**Verifier confirmation:** The factual claims in the finding are all correct:

1. Key clamping: Lines 84-85 (`key := make([]byte, 32); copy(key, rawKey)`) unconditionally truncate/zero-pad every fuzzer-chosen key to exactly 32 bytes. Keys longer than 64 bytes (the Streebog-256 block size) are never exercised, even though both `KDFTree256` and `KDFTree2012_256` accept arbitrary key lengths and `crypto/hmac` takes a different code path when `len(key) > blocksize` (it hashes the key using the provided hash function, line 188-189 in Go's fips140/hmac).

2. lenSel restriction: `keyOutLen` is capped to 32 or 64 (line 87-89), so iteration counts 3..255 are never exercised in the fuzz target.

Both are genuine coverage gaps.

However, the severity is low rather than medium because:
- I ran a direct probe calling `KDFTree256` and `KDFTree2012_256` with keys of length 1, 0, and 100 bytes (greater than the 64-byte block size), and with output lengths of 32, 64, 96, and 128 bytes. All produce identical output between the two implementations.
- The theoretical risk (long-key path exercising clean-room streebog vs gogost streebog on the key material inside hmac.New) is already covered transitively: `parity/streebog/` independently proves the two Streebog-256 implementations are byte-for-byte identical over all inputs. If Streebog is equivalent, HMAC with any key length is also equivalent, so there is no latent bug hiding behind this gap.
- The finding's severity claim of "low" is appropriate — the test is weaker than it could be, but no actual divergence exists and the gap is covered transitively.

The finding is confirmed as a real (if minor) test-coverage weakness: the fuzz body does not exercise the full input space the production API accepts.

**Suggested fix:** In `parity/kdftree/kdftree_parity_test.go`, change the fuzz body to pass `rawKey` directly and expand `lenSel` to cover more iteration counts:

```go
f.Fuzz(func(t *testing.T, rawKey, label, seed []byte, lenSel uint8) {
    // Use rawKey directly so keys of any length (including >64 bytes,
    // which trigger the hash-the-key path inside crypto/hmac) are tested.
    key := rawKey

    // Map lenSel across multiples of 32 from 32 to 8*32=256.
    // This exercises iteration counters 1..8 for free.
    mult := int(lenSel%8) + 1 // 1..8
    keyOutLen := mult * 32

    got := KDFTree256(key, label, seed, 1, keyOutLen)
    if len(got) != keyOutLen {
        t.Fatalf("len = %d, want %d", len(got), keyOutLen)
    }

    if ref := gostref.KDFTree2012_256(key, label, seed, keyOutLen); !bytes.Equal(got, ref) {
        t.Fatalf("mismatch vs gostcryptocompat (len=%d):\n got %x\n ref %x", keyOutLen, got, ref)
    }

    if keyOutLen == 32 {
        ref := gost34112012256.NewKDF(key).Derive(nil, label, seed)
        if !bytes.Equal(got, ref) {
            t.Fatalf("mismatch vs gogost KDF.Derive:\n got %x\n ref %x", got, ref)
        }
    }
})
```

Also add a seed covering a key longer than 64 bytes:
```go
f.Add(make([]byte, 100), []byte("label"), []byte("seed"), uint8(1))
```

---

## keg

**Reviewer summary:** The keg parity package is a genuine, non-vacuous differential test: the oracle (gostcryptocompat.KEG2012_256) uses gogost's gost3410 KEK2012256 for the VKO core, the KAT test first pins the oracle itself to an independently engine-derived vector (openssl pkeyutl, keg.md) before diffing the clean-room output, and all comparisons are full [64]byte equality. The ephemeral test and fuzz target both derive valid key pairs from the gogost generator and additionally assert pair symmetry; the zero-UKM special case is in both the deterministic table and the fuzz seed corpus. The main weaknesses are: (1) the oracle's Step 1 (UKM reverse + all-zero special case) and Step 3 (KDFTree) are hand-written in the compat facade rather than taken from gogost (gogost has no KEG/64-byte KDFTree), so the zero-UKM branch is only ever checked between two co-developed implementations with no engine anchor; (2) the clean-room curve parameter is never parity-tested — every call passes nil (TC26 256-A), leaving the production-relevant CryptoPro/TC26 non-default 256-bit curves and the 512-bit rejection path with zero differential coverage; and (3) the fuzz target hardcodes the curve and only feeds generator-derived (always-valid) keys, never raw fuzzer bytes as key material.

### [KEG-01] Curve parameter never parity-tested: every clean-room call passes nil (TC26 256-A only)

- **Location:** `gostcrypto-compat/parity/keg/keg_parity_test.go:65, 109, 119, 162, 171`
- **Category:** test-gap · **Severity:** medium · **Verifier:** opus

**Finding:** All five clean-room KEG2012_256 invocations across both deterministic tests and the fuzz target pass curve=nil, which selects TC26 256-A. The clean-room API explicitly supports 'whatever 256-bit curve the certificate uses, including the CryptoPro paramsets signalled as GC256B/C/D (RFC 9189)' (keg.go:73-78), and both sides expose the needed curve lookup (clean-room gost3410curves.CurveByOID; oracle CurveByOID in primitives_gost.go:54-69 covering CryptoPro 2001 A/B/C and TC26 256 A/B/C/D). None of those non-default curves is ever diffed against gogost — neither here nor in parity/vko (which uses only the 2001 test curve and 2012 paramSetA). The clean-room's own TestKEG2012_256_CurveHonored checks only self-consistency properties (symmetry, distinctness), not reference equality. Since GC256B/C/D are real certificate curves in GOST TLS, the byte-for-byte parity claim currently holds only for TC26 256-A. The errCurve512 rejection path (keg.go:98-99) is likewise never exercised in parity.

**Evidence:** keg_parity_test.go:65: got, err := KEG2012_256(nil, pub, priv, ukm) — and the comment at :60-64 acknowledges nil is used because the two Curve wrapper types differ. Commit af39cd1 'parity/keg: pass nil curve to clean-room KEG2012_256' made all call sites nil. Both modules' CurveByOID registries support CryptoPro 256-bit OIDs (1.2.643.2.2.35.x / 36.0), so a multi-curve differential table is feasible today.

**Verifier confirmation:** Every factual claim in the finding checks out against the source.

1. All five clean-room KEG2012_256 invocations pass curve=nil: keg_parity_test.go:65, :109, :119, :162, :171. Confirmed by reading each call site.

2. nil selects TC26 256-A: gostcrypto/keg/keg.go:96-97 `if curve == nil { curve = curveTC26256A() }`, where curveTC26256A() resolves OID 1.2.643.7.1.2.1.1.1 (keg.go:60-67). The oracle curve the test pins to is exactly that same OID (keg_parity_test.go:20,24). So the clean-room/oracle diff is exercised ONLY on TC26 256-A.

3. Both registries support the non-default 256-bit curves: clean-room gost3410curves.CurveByOID covers CryptoPro 2001 A/B/C (1.2.643.2.2.35.x) and tc26 256 A/B/C/D (curves.go:256-298); oracle CurveByOID covers the same set (primitives_gost.go:54-78). The oracle's KEG2012_256 (keg_gost.go:31) and GenerateEphemeralKey (keygen_gost.go:22) both accept an arbitrary *Curve, and the raw key encodings (LE X‖Y / LE scalar) are format-identical across curves. A multi-curve differential table is therefore feasible today — the only obstacle (cited in the test comment at :60-64) is that the two wrapper types differ, which is trivially worked around by calling each module's own CurveByOID for the same OID.

4. The clean-room's own TestKEG2012_256_CurveHonored (keg_test.go:277-333) only checks self-consistency: pair-symmetry on CryptoPro-A and distinctness from TC26-256-A. It never compares against gogost, so it is NOT a reference-equality gate.

5. The errCurve512 path (keg.go:98-99) is exercised only in the clean-room's own TestKEG2012_256_Reject512 (keg_test.go:337-351), never in any parity test. Confirmed.

6. parity/vko diffs clean-room↔gogost only on the 2001 test curve and 2012 paramSetA/512-A via the fixed-paramSet wrappers vko.VKO2012_256/512 (vko_parity_test.go:69-83, fuzz at :136 uses Curve2012ParamSetA). The curve-parameterized vko.KEK2012256 (the path KEG actually uses) is never diffed on a non-default curve. Confirmed.

So the byte-for-byte KEG parity claim genuinely holds only for TC26 256-A. The finding is not a restatement of any documented intentional divergence (TODO.md / docs/engine-vectors.md contain no KEG/curve carve-out).

Why I downgrade high→medium: the constituent primitives are substantially covered elsewhere. parity/gost3410curves/FuzzScalarMult (gost3410curves_parity_test.go:66-105) already diffs clean-room↔gogost scalar·Base point arithmetic across ALL standard OID curves including CryptoPro A/B/C and GC256B/C/D, and TestCrossCheckInternalGost cross-checks the curve constants for every OID. KDFTree is curve-independent and separately diffed in parity/kdftree. (Note: curve_sign_sweep_test.go is oracle-only, gogost-vs-gogost, so it does NOT contribute clean-room coverage.) The genuine residual gap is narrow but real: VKO on a non-default curve — scalar·peer-point plus cofactor clearing and the Streebog-256 finalize — is diffed clean-room↔gogost only on paramSetA; FuzzScalarMult covers scalar·Base only, not the cofactor/peer-point path. A curve-specific cofactor or VKO-finalize divergence on the CryptoPro/GC256 certificate curves would escape every parity gate. That is a meaningful but bounded test-absence, not a high-severity one given the component coverage.

**Suggested fix:** Add a multi-curve differential to parity/keg (and ideally parity/vko) that walks the non-default 256-bit OIDs and diffs clean-room against the oracle on each. Resolve the same OID through each module's own registry rather than trying to share a wrapper object:

  var curve256OIDs = []struct{ name, oid string; asn1 asn1.ObjectIdentifier }{
      {"CryptoPro-A", "1.2.643.2.2.35.1", asn1.ObjectIdentifier{1,2,643,2,2,35,1}},
      {"CryptoPro-B", "1.2.643.2.2.35.2", ...},
      {"CryptoPro-C", "1.2.643.2.2.35.3", ...},
      {"TC26-256-B",  "1.2.643.7.1.2.1.1.2", ...},
      {"TC26-256-C",  "1.2.643.7.1.2.1.1.3", ...},
      {"TC26-256-D",  "1.2.643.7.1.2.1.1.4", ...},
  }
  for _, c := range curve256OIDs {
      oc, _ := gost.CurveByOID(c.asn1)                 // oracle wrapper
      cc, _ := gost3410curves.CurveByOID(c.oid)        // clean-room wrapper
      privA, pubA, _ := gost.GenerateEphemeralKey(oc, bytes.NewReader(seedA))
      privB, pubB, _ := gost.GenerateEphemeralKey(oc, bytes.NewReader(seedB))
      ref, _ := gost.KEG2012_256(oc, pubB, privA, ukm)
      got, _ := KEG2012_256(cc, pubB, privA, ukm)      // pass the clean-room curve, not nil
      if got != ref { t.Fatalf("%s: clean-room != oracle", c.name) }
  }

Extend the fuzz target the same way (fuzzer-selected OID index, like parity/gost3410curves/FuzzScalarMult). Separately, add a negative parity case that confirms both impls reject a 512-bit curve OID (1.2.643.7.1.2.1.2.1) from KEG2012_256, exercising the errCurve512 path.

### [KEG-02] Fuzz target hardcodes the curve to TC26 256-A

- **Location:** `gostcrypto-compat/parity/keg/keg_parity_test.go:143, 161-162`
- **Category:** fuzz-gap · **Severity:** medium · **Verifier:** sonnet

**Finding:** FuzzKEG2012_256_DiffOracle always uses oracleCurve(t) (TC26 256-A) for the oracle and nil for the clean-room. The curve is a first-class API dimension on both sides; adding a fuzzer-chosen index into the closed set of mutually supported 256-bit curve OIDs (CryptoPro A/B/C, TC26 256 A/B/C/D) would extend differential coverage to the curves real certificates use, at no oracle-availability cost.

**Evidence:** f.Fuzz(func(t *testing.T, seedA, seedB, rndUKM []byte) { curve := oracleCurve(t); ... KEG2012_256(nil, pubB, privA, ukm) — no curve byte/index in the fuzz signature.

**Verifier confirmation:** The finding is accurate. The evidence from the source:

1. `oracleCurve(t)` at line 22-29 of `keg_parity_test.go` is hardcoded to `tc26256AOID` (1.2.643.7.1.2.1.1.1, TC26 256-A). It never returns any other curve.

2. The fuzz signature on line 142 is `func(t *testing.T, seedA, seedB, rndUKM []byte)` — three byte slices, no curve selector.

3. Inside the fuzz body (line 143): `curve := oracleCurve(t)` is called unconditionally every iteration, so every fuzz run uses TC26 256-A for key generation and oracle KEG.

4. The clean-room call on line 162 uses `KEG2012_256(nil, pubB, privA, ukm)` where `nil` defaults to TC26 256-A (confirmed in `gostcrypto/keg/keg.go:96-97`: `if curve == nil { curve = curveTC26256A() }`).

5. The clean-room `KEG2012_256` docstring (`keg.go:74-76`) explicitly states: *"whatever 256-bit curve the certificate uses, including the CryptoPro paramsets signalled as GC256B/C/D (RFC 9189 §A.1.3)"*, and `gostcrypto/gost3410curves/curves.go:256-297` exposes 7 distinct 256-bit OIDs: CryptoPro A/B/C and TC26 256-A/B/C/D.

6. The oracle (`gostcryptocompat.KEG2012_256`) accepts a `*Curve` and the compat package's `CurveByOID` (confirmed in `curve_sign_sweep_test.go:97-103`) maps the same 7 256-bit OIDs.

7. Neither `gostcrypto/TODO.md` nor `gostcrypto-compat/docs/engine-vectors.md` records any intentional restriction on KEG curve coverage.

The gap is real: CryptoPro A (OID 1.2.643.2.2.35.1) is the curve Tarantool EE production certificates commonly use (per `exports_gost.go:163`). A bug in `vko.KEK2012256` or `keg.KEG2012_256` specific to that curve's cofactor or scalar arithmetic would not be caught by this fuzz target. The claimed severity of medium is appropriate — the existing TC26 256-A coverage does validate the algorithm, but the untested curves are the ones real deployments use.

**Suggested fix:** Add a `curveIdx byte` to the fuzz signature and build a lookup table of the 7 supported 256-bit curve OID strings. Use `curveIdx % 7` to pick a curve on each iteration, resolving it via `gost3410curves.CurveByOID` (clean-room) and `gost.CurveByOID` (oracle) — both support the same 7 OIDs.

Concrete change to `FuzzKEG2012_256_DiffOracle` in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/keg/keg_parity_test.go`:

```go
// Closed set of mutually-supported 256-bit curve OIDs (CryptoPro A/B/C + TC26 A/B/C/D).
var curve256OIDs = []struct {
    cleanRoom string                // dotted-decimal for gost3410curves.CurveByOID
    oracle    asn1.ObjectIdentifier // for gost.CurveByOID
}{
    {"1.2.643.2.2.35.1", asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}}, // CryptoPro-A
    {"1.2.643.2.2.35.2", asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}}, // CryptoPro-B
    {"1.2.643.2.2.35.3", asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}}, // CryptoPro-C
    {"1.2.643.7.1.2.1.1.1", asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}}, // TC26-256-A
    {"1.2.643.7.1.2.1.1.2", asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}}, // TC26-256-B
    {"1.2.643.7.1.2.1.1.3", asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}}, // TC26-256-C
    {"1.2.643.7.1.2.1.1.4", asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}}, // TC26-256-D
}

func FuzzKEG2012_256_DiffOracle(f *testing.F) {
    f.Add(seedHex(privAHex), seedHex(privBHex), seedHex(ukmHex), byte(3)) // TC26-256-A (index 3)
    f.Add(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), make([]byte, 32), byte(0)) // CryptoPro-A
    f.Add(bytes.Repeat([]byte{0xa5}, 32), bytes.Repeat([]byte{0x5a}, 32), bytes.Repeat([]byte{0xff}, 32), byte(1))

    f.Fuzz(func(t *testing.T, seedA, seedB, rndUKM []byte, curveIdx byte) {
        entry := curve256OIDs[int(curveIdx)%len(curve256OIDs)]

        crCurve, err := gost3410curves.CurveByOID(entry.cleanRoom)
        if err != nil {
            t.Fatalf("clean-room CurveByOID: %v", err)
        }
        oracleCrv, err := gost.CurveByOID(entry.oracle)
        if err != nil {
            t.Fatalf("oracle CurveByOID: %v", err)
        }

        sa := fixLen(seedA, 32)
        sb := fixLen(seedB, 32)
        ukm := fixLen(rndUKM, 32)

        privA, pubA, err := gost.GenerateEphemeralKey(oracleCrv, bytes.NewReader(sa))
        if err != nil { t.Skipf("gen A: %v", err) }
        privB, pubB, err := gost.GenerateEphemeralKey(oracleCrv, bytes.NewReader(sb))
        if err != nil { t.Skipf("gen B: %v", err) }

        ref, err := gost.KEG2012_256(oracleCrv, pubB, privA, ukm)
        if err != nil { t.Skipf("oracle KEG: %v", err) }

        got, err := KEG2012_256(crCurve, pubB, privA, ukm)
        if err != nil { t.Fatalf("clean-room KEG: %v", err) }
        if got != ref {
            t.Fatalf("clean-room != oracle (curve %s)\n got %x\n ref %x", entry.cleanRoom, got[:], ref[:])
        }

        sym, err := KEG2012_256(crCurve, pubA, privB, ukm)
        if err != nil { t.Fatalf("clean-room sym: %v", err) }
        if sym != got {
            t.Fatalf("not pair-symmetric (curve %s)\n A→B %x\n B→A %x", entry.cleanRoom, got[:], sym[:])
        }
    })
}
```

Note: this requires adding `"github.com/bigbes/gostcrypto/gost3410curves"` to the parity/keg test imports so the clean-room curve type can be resolved before passing it to `KEG2012_256`.

### [KEG-03] Zero-UKM special-case branch has no independent anchor — both sides are co-developed implementations of the same engine reading

- **Location:** `gostcrypto-compat/keg_gost.go:48-53 vs gostcrypto/keg/keg.go:115-121; exercised at parity/keg/keg_parity_test.go:88 and :139`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** gogost has no KEG, so the oracle's Step 1 (UKM byte-reverse + all-zero -> realUKM[15]=1) is hand-written in the compat facade, mirroring the clean-room code line-for-line. The non-zero-UKM path is anchored to a gost-engine vector (wantHex, verified against the oracle at keg_parity_test.go:56-58), but the all-zero-UKM branch is only ever compared between the two co-developed implementations: the clean-room's own zero-UKM KAT (gostcrypto/keg/keg_test.go:172-174) explicitly states its expected value was computed FROM the gogost-backed facade. A shared misreading of gost_ec_keyx.c:140-142 (e.g. realUKM[0]=1 instead of realUKM[15]=1) would pass every parity and KAT test. An engine-derived vector for a zero-prefixed ukm_source (openssl pkeyutl with ukmhex=00*32) would close this.

**Evidence:** keg_gost.go: 'if allZero { realUKM[15] = 1 }' and keg.go: 'if allZero { realUKM[15] = 1 }' are identical logic; keg_test.go:172-174: 'Source: the gogost-backed reference gostcryptocompat.KEG2012_256 (the de-facto spec this module matches), computed on 2026-06-10'. No engine-sourced KAT exists for the zero-UKM branch anywhere in the repo.

**Verifier confirmation:** The finding is confirmed but the claimed severity of "medium" is overclaimed; "low" is more accurate.

**What is confirmed:**

1. Both implementations use `realUKM[15] = 1` (keg_gost.go:49, keg.go:116) — they are byte-for-byte identical logic, co-developed from the same reading of gost_ec_keyx.c:140-142.

2. The `zeroUKMWantHex` KAT constant in keg_test.go:175-176 is explicitly documented as computed from the gogost-backed facade (`gostcryptocompat.KEG2012_256`, comment at keg_test.go:172-174: "Source: the gogost-backed reference gostcryptocompat.KEG2012_256 ... computed on 2026-06-10"). This is a genuine circular anchor.

3. The engine's own test suite (tmp/engine/test_derive.c:294) uses `unsigned char ukm[32] = { 1 }` for KEG — `ukm[0]=1`, rest zeros — which takes the **non-zero** reverse path in gost_keg. The engine test suite has no vector where the first 16 bytes of ukm_source are all zero, confirming there is no engine-derived independent vector for the zero-UKM branch anywhere in the repository.

4. The parity test at parity/keg/keg_parity_test.go:88 (the all-zero UKM entry in the `ukms` slice) only diffs clean-room against the gogost-backed oracle — the same co-developed implementation.

**Why the severity is low, not medium:**

The engine code at gost_ec_keyx.c:140-142 is unambiguous and trivially simple:
```c
memset(real_ukm, 0, 16);
if (memcmp(ukm_source, real_ukm, 16) == 0)
    real_ukm[15] = 1;
```
A shared misreading of `real_ukm[15]` as `real_ukm[0]` would require both developers to independently confuse index 15 with index 0 in a 3-line snippet. The engine source is present in the repo at a cited path and directly refutes any such misreading. The risk is theoretical rather than plausible.

Additionally, since UKM is treated as a little-endian integer by both gogost's `NewUKM` (ukm.go:23-28: byte-reverses then `SetBytes`) and the clean-room `leBytes2big` (vko.go:55-57), `realUKM[15]=1` means the LE value is `2^120`, while `realUKM[0]=1` would give value `1`. These produce very different VKO outputs, so a wrong-index bug would be immediately caught by the pair-symmetry test only if it happened to produce a symmetric result (it would, since VKO is symmetric for any fixed UKM value) — meaning pair-symmetry alone cannot distinguish `[15]=1` from `[0]=1`, exactly as the finding claims. The only differentiator is the exact byte value of the output, which is what the KAT pins — but the KAT's anchor is the co-developed oracle.

**Suggested fix:** Generate an engine-derived zero-UKM KEG vector by running the gost-engine against the test keypairs (privAHex/pubBHex) with a 32-byte all-zero ukm_source using `openssl pkeyutl -derive` with the GOST engine and `-pkeyopt ukmhex:00*32`, then replace the `zeroUKMWantHex` constant in keg_test.go:175-176 with the engine-produced value. The comment block at keg_test.go:165-174 should be updated to cite `tmp/engine/gost_ec_keyx.c:140-142` as the ground-truth source rather than the gogost-backed facade. If running the engine binary is not feasible in CI, document the vector's provenance with the full `openssl` command and the engine version (v3.0.3) so it can be independently reproduced. This would close the circular dependency: the zero-UKM KAT would then be anchored to the same gost-engine binary that anchors the non-zero wantHex vector (keg_parity_test.go:56-58).

### [KEG-04] Fuzz skips on oracle KEG error before running the clean-room side, hiding potential acceptance divergence

- **Location:** `gostcrypto-compat/parity/keg/keg_parity_test.go:157-160`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** In FuzzKEG2012_256_DiffOracle, `ref, err := gost.KEG2012_256(...)` followed by `t.Skipf("oracle KEG: %v", err)` skips the case entirely before the clean-room implementation runs. An input that gogost rejects but the clean-room accepts (or vice versa, since the clean-room error is a Fatal) would never be reported as a divergence. Practically near-unreachable because both keys come from the oracle's own generator and zero-UKM is special-cased, but it contradicts the comment at lines 135-136 ('never used to hide a KEG mismatch') for this specific path. Asserting that the clean-room also errors when the oracle errors would make the skip safe.

**Evidence:** ref, err := gost.KEG2012_256(curve, pubB, privA, ukm)
if err != nil {
    t.Skipf("oracle KEG: %v", err)
}
// clean-room call only happens after the skip

**Verifier confirmation:** The structural issue is real but the practical risk is nil. Here is the concrete analysis:

**What the code does** (`parity/keg/keg_parity_test.go` lines 157-160):
```go
ref, err := gost.KEG2012_256(curve, pubB, privA, ukm)
if err != nil {
    t.Skipf("oracle KEG: %v", err)
}
// clean-room KEG2012_256(nil, pubB, privA, ukm) only runs here
```
The clean-room side is never exercised on any input that causes the oracle to error. This is the structural gap the finding describes.

**Why the skip is unreachable in this specific fuzz context:**
- `pubB`/`privA` are produced by `gost.GenerateEphemeralKey` (lines 148-155). If that call succeeds, the returned keys are always: exactly 32/64 bytes, non-zero, and on the TC26-256-A curve (derived by `prv.PublicKey()` via scalar-multiplication on the base point).
- `ukm = fixLen(rndUKM, 32)` is always exactly 32 bytes.
- In `keg_gost.go` (`gostcrypto-compat/keg_gost.go`), the oracle's error paths after key-gen succeeds are: (a) `len(ukmSource) != 32` — impossible; (b) `NewPrivateKey` wrong-length or zero — impossible from keygen output; (c) `NewPublicKey` wrong-length — impossible; (d) `prv.KEK2012256` / `prv.C.Exp` fails on zero-degree — impossible because the all-zero UKM special case in both sides sets `realUKM[15]=1` making `ukmBig=1`, and `u = ukmBig * cofactor(4) = 4 ≠ 0`. For any non-zero UKM input the byte-reversal produces a non-zero big.Int.
- gogost's `NewPublicKeyLE` (`third_party/gogost/gost3410/public.go:30-44`) does **not** check on-curve membership — it only checks byte length. So the oracle has no on-curve validation that could trigger an error the clean-room might not.

**The real divergence risk:**
The clean-room `vko.loadPublicLE` (`gostcrypto/vko/vko.go:113-128`) **does** check `c.IsOnCurve(p)` (`errPubNotOn`). This means for an off-curve public key the oracle (gogost) would succeed and the clean-room would fail with `errPubNotOn` — a genuine acceptance divergence. However, keys in the fuzz are always produced by `GenerateEphemeralKey` which returns on-curve points, so this divergence cannot be triggered via the skip path.

**The comment mismatch:**
Lines 135-136 say "invalid generator inputs are skipped (never used to hide a KEG mismatch)" — but this comment covers only the generator skips at lines 149-155, not the oracle-KEG skip at 157-160. The oracle-KEG skip is a separate path the comment doesn't justify.

**Summary:** The structural weakness is confirmed — skipping before running the clean-room side means oracle-rejects/clean-room-accepts (or vice versa) divergences on that path are invisible. The adjusted severity remains low because: (1) the skip is unreachable given the current input construction; (2) no actual divergence is being hidden today; (3) it is trivially fixable.

**Suggested fix:** Replace the `t.Skipf` with a combined assertion: run the clean-room side unconditionally and then require that both sides agree on success/failure. Concretely, change lines 157-164 in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/keg/keg_parity_test.go` from:

```go
ref, err := gost.KEG2012_256(curve, pubB, privA, ukm)
if err != nil {
    t.Skipf("oracle KEG: %v", err)
}
// nil selects keg's default TC26 256-A (the oracle curve).
got, err := KEG2012_256(nil, pubB, privA, ukm)
if err != nil {
    t.Fatalf("clean-room KEG: %v", err)
}
```

to:

```go
ref, oracleErr := gost.KEG2012_256(curve, pubB, privA, ukm)
// nil selects keg's default TC26 256-A (the oracle curve).
got, cleanErr := KEG2012_256(nil, pubB, privA, ukm)
// Both sides must agree on success vs. failure.
if (oracleErr == nil) != (cleanErr == nil) {
    t.Fatalf("oracle/clean-room error mismatch: oracle=%v clean-room=%v", oracleErr, cleanErr)
}
if oracleErr != nil {
    t.Skipf("both sides reject (oracle: %v, clean-room: %v)", oracleErr, cleanErr)
}
```

This makes the skip safe: it only fires when both sides agree the input is invalid, so it can never hide a divergence. The comment at lines 135-136 should also be updated to cover the oracle-KEG skip.

### [KEG-05] Error-path behaviour never compared against the oracle

- **Location:** `gostcrypto-compat/parity/keg/keg_parity_test.go (whole file)`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The parity package never feeds either side a wrong-length ukm_source, a malformed/off-curve public key, a zero or out-of-range private key, or a 512-bit curve, so accept/reject parity with gogost is unverified. The clean-room module unit-tests these paths itself (gostcrypto/keg/keg_test.go: TestKEG2012_256_UKMLen, TestKEG2012_256_BadKeys, TestKEG2012_256_Reject512), and error-message parity is legitimately out of scope, but a small differential table asserting 'both sides error' on the same malformed inputs would guard against the clean-room silently accepting input that the reference rejects.

**Evidence:** grep over keg_parity_test.go shows no call with len(ukm) != 32, no off-curve pub, no 512-bit curve; all inputs are KAT constants or generator outputs.

**Verifier confirmation:** The finding is accurate but requires precise qualification.

**What the parity file does cover:**

`keg_parity_test.go` contains:
1. `TestKEG2012_256_DiffOracle` — KAT with valid 32-byte UKM, valid keys.
2. `TestKEG2012_256_DiffEphemeral` — 3×3 (seed×ukm) cases including all-zero UKM; all valid.
3. `FuzzKEG2012_256_DiffOracle` — fuzzes valid ephemeral keys with arbitrary UKM, but fixes UKM to 32 bytes via `fixLen(rndUKM, 32)` (line 146), so wrong-length UKM is never fed to either side.

**What is absent — confirmed by direct reading:**

- No call with `len(ukm) != 32`. The fuzz target normalises UKM to exactly 32 bytes at line 146, so the `ukmSource must be 32 bytes` error path in the oracle (`keg_gost.go:35`) and the clean-room (`keg.go:92`) is never compared.
- No off-curve or wrong-length public key fed to both sides. The fuzz target generates keys through `gost.GenerateEphemeralKey`, which produces structurally valid on-curve keys.
- No zero or wrong-length private key.
- No 512-bit curve. The oracle's `gost.KEG2012_256` takes a `*Curve` wrapper and does not itself reject 512-bit curves — it would pass the `gost3410.NewPrivateKey` call with a 512-bit curve's `PointSize()=64` and fail only on key-length mismatch if a 32-byte key is supplied; the clean-room rejects the curve explicitly at `keg.go:98` before calling VKO. These two diverge on the 512-bit path: the clean-room returns `errCurve512`, the oracle would either error on key length or compute a result on the wrong domain. That divergence is untested.

**Why severity is low, not higher:**

The clean-room unit tests (`gostcrypto/keg/keg_test.go`) cover all of these paths individually: `TestKEG2012_256_UKMLen` (lines 147–163), `TestKEG2012_256_BadKeys` (lines 200–235), `TestKEG2012_256_Reject512` (lines 337–351). The parity gap is about whether the clean-room and oracle *agree on which inputs to reject*, not about whether the clean-room itself rejects them. The risk is that the clean-room silently accepts something the oracle rejects (or vice versa), which would represent a parity divergence invisible today. This is a real gap but not a correctness hazard for the happy path, hence low severity.

**No documented intentional divergence covers this gap.** `gostcrypto/TODO.md` and `gostcrypto-compat/docs/engine-vectors.md` mention the GOSTR341194 empty-input finalization and 512-bit sign divergences, not KEG error-path parity. The finding is not restating a known intentional divergence.

**Suggested fix:** Add a `TestKEG2012_256_ErrorParity` table test in `gostcrypto-compat/parity/keg/keg_parity_test.go`. For each malformed input, call both the clean-room `KEG2012_256` and the oracle `gost.KEG2012_256` and assert that *both* return non-nil errors (not that the errors match textually — error-message parity is out of scope). Cases to cover:

1. Wrong-length UKM: `len=31` and `len=33` — feed these directly to both sides without normalising.
2. Wrong-length public key: 63-byte and 65-byte raw pub (the oracle's `NewPublicKeyLE` checks `len(raw) != 2*pointSize`; the clean-room's VKO does the same).
3. Wrong-length private key: 31 bytes and 33 bytes.
4. Zero private key: `make([]byte, 32)`.

The 512-bit curve case is structurally untestable in the parity frame because the oracle `gost.KEG2012_256` takes a `*Curve` from `gostcryptocompat.CurveByOID`, and while 512-bit curves are available via that function, the signatures differ (the oracle would need a 64-byte private key and 128-byte public key for a 512-bit curve, so feeding 32/64-byte keys would cause a key-length error on the oracle side rather than a 512-bit-curve-rejection error). Document that case as out-of-scope in a comment rather than trying to compare it.

Example skeleton:

```go
func TestKEG2012_256_ErrorParity(t *testing.T) {
    curve := oracleCurve(t)
    goodPub := mustHex(t, pubBHex)
    goodPriv := mustHex(t, privAHex)
    goodUKM := mustHex(t, ukmHex)

    cases := []struct {
        name      string
        pub, priv, ukm []byte
    }{
        {"ukm_31",      goodPub, goodPriv, goodUKM[:31]},
        {"ukm_33",      goodPub, goodPriv, append(append([]byte(nil), goodUKM...), 0x00)},
        {"pub_short_63",goodPub[:63], goodPriv, goodUKM},
        {"pub_long_65", append(append([]byte(nil), goodPub...), 0x00), goodPriv, goodUKM},
        {"priv_short",  goodPub, goodPriv[:31], goodUKM},
        {"priv_zero",   goodPub, make([]byte, 32), goodUKM},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            _, oracleErr := gost.KEG2012_256(curve, tc.pub, tc.priv, tc.ukm)
            _, cleanErr  := KEG2012_256(nil, tc.pub, tc.priv, tc.ukm)
            if oracleErr == nil {
                t.Errorf("oracle accepted malformed input %s", tc.name)
            }
            if cleanErr == nil {
                t.Errorf("clean-room accepted malformed input %s", tc.name)
            }
        })
    }
}
```

### [KEG-06] Key material is always laundered through the oracle's generator; raw fuzzer bytes never reach the pub/priv inputs

- **Location:** `gostcrypto-compat/parity/keg/keg_parity_test.go:148-155`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** seedA/seedB only seed gost.GenerateEphemeralKey, so every public key is a valid on-curve point and every private scalar is in-range. The fuzzer therefore can never probe parity on boundary scalars (q-1, values >= q in raw LE form) or on near-miss public keys, and the on-curve validation paths (clean-room vko vs gogost NewPublicKey) are structurally unreachable. A second fuzz mode that feeds fixLen'd raw bytes directly as serverPub/clientPriv and asserts agreement on accept/reject (and on bytes when both accept) would cover this. Positives: UKM bytes ARE fuzzed directly (correct, since only the 32-byte length is contractual), and the zero-UKM special-case seed is present in the corpus (line 139), which is the right call — KEG has no documented empty-input divergence (keg.md:250-252 confirms no TODO.md divergence applies).

**Evidence:** privA, pubA, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(sa)) — the only path from fuzzer bytes to key material; KEG2012_256 never receives fuzzer-controlled pub/priv directly.

**Verifier confirmation:** The finding is accurate and the described limitation is real. Here is the concrete chain of evidence.

**What the fuzz test actually does (lines 142-178 of keg_parity_test.go)**

The fuzzer receives three byte slices `seedA`, `seedB`, `rndUKM`. The first two are normalized to 32 bytes via `fixLen` and fed to `gost.GenerateEphemeralKey(curve, bytes.NewReader(sa))`. That function calls `gost3410.GenPrivateKey` (third_party/gogost/gost3410/private.go:66-72), which calls `io.ReadFull(rand, raw)` to read exactly `c.PointSize()` (32) bytes, then calls `NewPrivateKeyLE` which:
1. Reverses the bytes to big-endian.
2. Interprets as a `*big.Int`.
3. Rejects zero.
4. Reduces mod `q`.

The public key is then computed as `d·G`, which is always a valid on-curve point.

**What this means**

Every `(priv, pub)` pair reaching `KEG2012_256` is the result of `GenPrivateKey` → `PublicKey()`. That means:
- The private scalar is always in `[1, q-1]` after reduction (never a raw value >= q, never the precise value q-1 unless the seed produces it by coincidence).
- The public key is always exactly on the curve.
- Off-curve points are structurally unreachable.
- Scalars >= q or equal to zero (before reduction) are silently absorbed by `mod q` inside gogost, so the clean-room's `loadPrivateLE` (vko.go:91-108) would receive the same already-reduced value — the comparison is always on equivalent valid scalars.

**Why this is a real (if minor) coverage gap**

The clean-room `vko.loadPublicLE` has an `IsOnCurve` check (vko.go:123). The clean-room `loadPrivateLE` has a zero-after-reduction check (vko.go:103-106). These are validation paths in `KEG2012_256` whose behavior the fuzz test can never exercise because the oracle generator guarantees valid inputs before they reach the clean-room code. The parity test is therefore silent about:
1. Whether clean-room and oracle agree on rejecting an off-curve point (they do, but by different error paths not diffed here).
2. Whether a scalar that is exactly `q` (which both implementations reduce to 0 and reject) produces matching errors.
3. Whether a scalar in `(q, 2^256)` — which both reduce mod q — produces matching outputs (highly likely, but not validated).

**Why this is not a deeper problem**

The BSD module's `keg_test.go` already contains `TestKEG2012_256_BadKeys` (lines 200-235) which directly tests the clean-room error paths for off-curve pubs, wrong-length inputs, and zero privs — independently of the oracle. The parity test's job is specifically to diff agreement on valid inputs; the error-path testing lives correctly in the BSD suite. The finding is about fuzz coverage of the *parity* oracle comparison, not about the existence of error-path tests.

**Severity assessment**

The parity test covers the cryptographic core (the actual KEG bytes) thoroughly for valid inputs. The missing coverage is on error/boundary paths — whether both sides reject the same malformed inputs with the same outcome. Since error-path tests already exist in `keg_test.go`, and since the fuzz test's omission is exactly as described, the finding is confirmed but severity is appropriately low: no correctness bug is hidden, only a coverage gap in the differential fuzz target.

**Suggested fix:** Add a second fuzz mode in `FuzzKEG2012_256_DiffOracle` that bypasses `GenerateEphemeralKey` and feeds fuzzer-controlled raw bytes directly to both the oracle (`gost.KEG2012_256`) and the clean-room (`KEG2012_256`), asserting agreement on the accept/reject outcome and on the output bytes when both accept. Concretely:

```go
// Second fuzz entry: raw bytes as serverPub (64 B) and clientPriv (32 B),
// fuzzer-controlled UKM. Both sides must agree on error vs. success,
// and on the output when both succeed.
f.Fuzz(func(t *testing.T, rawPub, rawPriv, rndUKM []byte) {
    curve := oracleCurve(t)
    pub  := fixLen(rawPub,  64)
    priv := fixLen(rawPriv, 32)
    ukm  := fixLen(rndUKM,  32)

    ref, oracleErr := gost.KEG2012_256(curve, pub, priv, ukm)
    got, cleanErr  := KEG2012_256(nil, pub, priv, ukm)

    // Agreement on accept vs. reject.
    if (oracleErr == nil) != (cleanErr == nil) {
        t.Fatalf("oracle err=%v clean-room err=%v for pub=%x priv=%x",
            oracleErr, cleanErr, pub, priv)
    }
    // Agreement on output bytes when both accept.
    if oracleErr == nil && got != ref {
        t.Fatalf("output mismatch: got %x ref %x", got[:], ref[:])
    }
})
```

The existing seed corpus already includes known-good KAT vectors; add seeds with off-curve and q-scalar bytes to guide early coverage. The zero-priv and short-input cases are already covered by `keg_test.go:TestKEG2012_256_BadKeys`, so this fuzz mode is strictly additive.

---

## kexp15

**Reviewer summary:** The kexp15 parity test is genuine and non-vacuous: TestKexp15Conformance anchors BOTH the oracle and the clean-room implementation to the gost-engine Magma etalon (an independent C source), and FuzzKexp15Conformance does a real byte-for-byte differential over fuzzer-controlled shared-key content/length, both 32-byte keys, the IV, and both variants (Magma/Kuznyechik). However, the oracle is only partially gogost: gogost ships no KExp15 or CMAC/OMAC (third_party/gogost/gost3413 contains only padding helpers), so the facade Kexp15 takes only the raw block ciphers (gost3412128/gost341264) from gogost and re-implements OMAC, CTR, and the OMAC-then-CTR composition locally in code structurally parallel to the clean-room omac/ctracpkm/kexp15 packages. The differential therefore strongly proves block-cipher parity but is weaker on the composition layer, where a bug common to both same-shaped implementations would pass. This is fully mitigated for Magma by the pinned engine etalon, but the Kuznyechik variant has no independent anchor in this package even though RFC 9189 Appendix A.1.3 vectors exist (and are already used in gostcrypto's own tests). Remaining gaps are minor: no error-path parity (the fuzz harness clamps all inputs valid, making its error-mismatch branch dead), a single Magma-only fuzz seed, and no seed exercising the OMAC complete-final-block (K1) path.

### [KXP-01] No independent pinned vector for the Kuznyechik variant in the parity package

- **Location:** `gostcrypto-compat/parity/kexp15/kexp15_parity_test.go:22-44`
- **Category:** test-gap · **Severity:** medium · **Verifier:** sonnet

**Finding:** TestKexp15Conformance pins only the Magma engine etalon against both sides. The Kuznyechik variant is exercised solely through the fuzz differential, i.e. only against the partially-independent local oracle (see correctness finding). RFC 9189 Appendix A.1.3.2 provides a published Kuznyechik KExp15 vector — already used in the clean-room's own test (gostcrypto/kexp15/kexp15_test.go:88, TestKexp15_Kuznyechik_RFC9189) — but the oracle (gost.Kexp15 with KexpKuznyechik) is never checked against it anywhere in this module (grep for Kexp15 across compat *_test.go matches only the parity file). Pinning the RFC 9189 Kuznyechik (and second Magma) vectors against gost.Kexp15 here would close the shared-composition-bug hole for the 128-bit path the same way the engine etalon closes it for Magma.

**Evidence:** kexp15_parity_test.go has exactly one pinned vector (Magma, iv=67bed654, want=cfd5a12d...). The RFC 9189 A.1.3.2 Kuznyechik vector (shared=a5576ce7..., iv=214a6a298e99e325, want=250d1b67...) exists in gostcrypto/kexp15/kexp15_test.go:91-96 but is asserted only against the clean-room side, in the other module — the gogost-backed oracle is never validated against it.

**Verifier confirmation:** The finding is accurate on all three specific claims:

1. `kexp15_parity_test.go:22-44` (`TestKexp15Conformance`) pins exactly one vector (Magma, iv=67bed654, want=cfd5a12d…) against both `gost.Kexp15(gost.KexpMagma, …)` and the clean-room `Kexp15(KexpMagma, …)`. There is no analogous pinned-vector test for `KexpKuznyechik` anywhere in `*_test.go` files under `gostcrypto-compat`.

2. `FuzzKexp15Conformance` (lines 53-91) does exercise `KexpKuznyechik` via `kuz=true`, but its only seed corpus entry (lines 54-60) uses `kuz=false`. During `go test ./...` the fuzzer only replays the committed seed corpus — the `kuz=true` branch is therefore never exercised in a normal CI run. It is exercised only during active fuzzing (`make fuzz`), which is not the default gate.

3. `gostcrypto/kexp15/kexp15_test.go:88-110` (`TestKexp15_Kuznyechik_RFC9189`) asserts the clean-room against the RFC 9189 A.1.3.2 Kuznyechik vector (shared=a5576ce7…, iv=214a6a298e99e325, want=250d1b67…), but it lives in a different module and makes no call to `gost.Kexp15`. The gogost-backed facade `gost.Kexp15` with `KexpKuznyechik` is never checked against any published ground-truth vector.

4. `kexp15_gost.go` implements the Kuznyechik path using `gost3412128.NewCipher` (gogost) for both OMAC and CTR — this is non-trivial composition. A shared composition bug (wrong block cipher, wrong iv-padding, wrong OMAC truncation) in the Kuznyechik path would not be caught by `go test ./...` in this module because both oracle and clean-room would likely diverge together from the standard, and neither is pinned to a known value.

5. There are no entries in `gostcrypto/TODO.md` or `gostcrypto-compat/docs/engine-vectors.md` that document an intentional divergence for kexp15 Kuznyechik, so this is not a known-and-accepted gap.

**Suggested fix:** Add a deterministic pinned-vector test for the Kuznyechik path in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/kexp15/kexp15_parity_test.go`. The RFC 9189 A.1.3.2 vector already used in the clean-room test is the natural choice:

```go
// TestKexp15Conformance_Kuznyechik pins both the gogost-backed oracle and
// the clean-room impl against the published RFC 9189 Appendix A.1.3.2 vector
// (TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC).
func TestKexp15Conformance_Kuznyechik(t *testing.T) {
    shared    := mustHexF("a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d")
    macKey    := mustHexF("7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1")
    cipherKey := mustHexF("1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24")
    iv        := mustHexF("214a6a298e99e325")
    want      := mustHexF("250d1b67a270ab04d3f65418e1d380b4cb945f0a3dca51500cf3a1bef37f76c07" +
                          "341a9839ccf6cba7189da61eb67176c")

    ref, err := gost.Kexp15(gost.KexpKuznyechik, shared, cipherKey, macKey, iv)
    if err != nil {
        t.Fatalf("gost.Kexp15: %v", err)
    }
    if !bytes.Equal(ref, want) {
        t.Fatalf("oracle disagrees with RFC 9189 A.1.3.2:\n got  %x\n want %x", ref, want)
    }

    got, err := Kexp15(KexpKuznyechik, shared, cipherKey, macKey, iv)
    if err != nil {
        t.Fatalf("Kexp15: %v", err)
    }
    if !bytes.Equal(got, want) {
        t.Fatalf("clean-room mismatch:\n got  %x\n want %x", got, want)
    }
}
```

Additionally, add a `kuz=true` seed to `FuzzKexp15Conformance` so the Kuznyechik path is covered on every `go test` run (not just during active fuzzing):

```go
f.Add(
    mustHexF("a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d"),
    mustHexF("1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24"),
    mustHexF("7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1"),
    mustHexF("214a6a298e99e325"),
    true,  // kuz=true
)
```

### [KXP-02] Oracle's OMAC/CTR/composition layers are not gogost — only the block ciphers are independently sourced

- **Location:** `gostcrypto-compat/kexp15_gost.go:100,118 (oracle); gostcrypto-compat/omac.go, gostcrypto-compat/ctr_gost.go`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** The parity test's stated purpose is to prove the clean-room kexp15 matches the GPL gogost reference byte-for-byte, but gogost v7 has no KExp15, OMAC/CMAC, or GOST-CTR implementation (third_party/gogost/gost3413 contains only Pad1/Pad2/Pad3). The facade oracle uses gogost only for gost3412128.NewCipher/gost341264.NewCipher; the OMAC (omac.go), CTR (ctr_gost.go), and the OMAC-then-CTR composition (kexp15_gost.go) are local re-implementations in this module, structurally near-identical to the clean-room gostcrypto/omac, gostcrypto/ctracpkm, and gostcrypto/kexp15 (same Write buffering invariant, same Sum snapshot, same big-endian incCounter, same iv||zeros layout). A composition-layer bug common to both same-shaped implementations would pass the differential. The Magma path is anchored to gost-engine's independent etalon (mitigating this), but the differential alone is weaker evidence than the test's framing implies. Unavoidable given gogost's API surface, but worth documenting in the test and compensating with independent KATs for both variants (see Kuznyechik finding).

**Evidence:** kexp15_gost.go:91-95 uses gost3412128/gost341264 only for NewCipher; lines 100 and 118 call the module-local NewOMAC/NewCTR. ls third_party/gogost/gost3413 -> padding.go only; grep for CMAC/OMAC/KExp in the vendored gogost finds nothing outside gost28147 (legacy 28147 MAC, a different algorithm). Clean-room omac.go Write (omac/omac.go:151-173) and facade omac.go Write (omac.go:101-124) implement the identical buffer-a-trailing-full-block strategy.

**Verifier confirmation:** The finding's core technical claim is correct and verifiable from the source.

**What the oracle actually is:**
`gostcrypto-compat/kexp15_gost.go:91-95` instantiates two block ciphers via `gost3412128.NewCipher` / `gost341264.NewCipher` from gogost, but then at lines 100 and 118 calls the module-local `NewOMAC` and `NewCTR` — both defined in `omac.go` and `ctr_gost.go` in this same module. The vendored gogost at `third_party/gogost/gost3413/` contains only `padding.go`; `grep` confirms no CMAC, OMAC, KExp, or CTR in gogost v7 beyond the legacy `gost28147` MAC (a different algorithm entirely).

**Structural isomorphism confirmed:**
- `gostcrypto-compat/omac.go` Write (lines 101–124): buffer-a-trailing-full-block strategy, `cbcStep` flush only when `len(p) > 0`.
- `gostcrypto/omac/omac.go` Write (lines 151–173): identical strategy, same invariant.
- Both `incCounter` implementations (compat `ctr_gost.go:162–169`, clean-room `ctracpkm/ctracpkm.go:211–217`): byte-by-byte big-endian with carry, same loop shape.
- `Sum` in both: snapshot state+buf, K1 on full final block, K2+pad on partial. Byte-for-byte equivalent logic.

A composition-layer bug (e.g., wrong `incCounter` endianness, wrong subkey selection in Sum, off-by-one in Write flush) shared by both same-shaped implementations would pass the differential undetected.

**Why severity is low, not medium:**
The finding correctly notes the Magma path is "anchored to gost-engine's independent etalon." Examining the full test suite reveals this mitigation is stronger than acknowledged:

1. `parity/kexp15/kexp15_parity_test.go:27` pins *both* oracle and clean-room against `cfd5a12d…2e3a8bd9`, a hard-coded hex constant derived from `tmp/engine/test_keyexpimp.c:47-76` (gost-engine v3.0.3). Neither implementation contributed to that constant.

2. `gostcrypto/kexp15/kexp15_test.go` contains three independent KATs that are external to the parity test: `TestKexp15_Magma_EngineEtalon` (same gost-engine vector), `TestKexp15_Magma_RFC9189` (RFC 9189 Appendix A.1.3.1), and `TestKexp15_Kuznyechik_RFC9189` (RFC 9189 Appendix A.1.3.2). These directly pin both variants from two authoritative independent sources.

3. `parity/omac/omac_parity_test.go` separately validates the OMAC layer with 2048 random-key/message iterations plus a Fuzz target, anchored to GOST R 34.13-2015 A.1.6 and A.2.6 KAT vectors in `TestDiffTruncatedKATs`. The `ctr_test.go` file similarly has engine-vector KATs for both CTR variants.

The test is weaker than its framing implies (the differential is essentially oracle vs. same-shape re-impl, not oracle vs. gogost), but the overall correctness argument is not hollow: external RFC 9189 and gost-engine KATs already exist in `gostcrypto/kexp15/kexp15_test.go`. The gap is documentation and the absence of a Kuznyechik RFC 9189 KAT in the parity test itself (only Magma is tested in `TestKexp15Conformance`).

**Suggested fix:** 1. In `gostcrypto-compat/parity/kexp15/kexp15_parity_test.go`, add a `TestKexp15Conformance_Kuznyechik` test case pinning both oracle and clean-room to the RFC 9189 Appendix A.1.3.2 Kuznyechik vector (`250d1b67…189da61eb67176c`, inputs from `gostcrypto/kexp15/kexp15_test.go:TestKexp15_Kuznyechik_RFC9189`). This gives the parity test an independent external anchor for the Kuznyechik variant.

2. Add a comment block at the top of `kexp15_parity_test.go` clarifying: "The differential here proves structural identity between the clean-room and the compat-module oracle; it does NOT compare against a gogost-native KExp15 (gogost v7 has no such implementation). External correctness is established by the RFC 9189 Appendix A.1.3.1/A.1.3.2 and gost-engine KATs in gostcrypto/kexp15/kexp15_test.go."

3. Optionally, add an analogous comment to `kexp15_gost.go` at the top of `Kexp15()` noting that OMAC and CTR layers are local re-implementations (not gogost-backed) due to the absence of these primitives in gogost v7.

### [KXP-03] No error-path parity: invalid key/IV lengths, empty shared key, and unknown variant never compared

- **Location:** `gostcrypto-compat/parity/kexp15/kexp15_parity_test.go:62-85`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Both implementations validate sharedKey non-empty, 32-byte cipherKey/macKey, exact ivLen, and known variant, but the parity package never checks that they accept/reject the same inputs. The fuzz harness clamps every input valid (fixKey to 32 bytes, iv to exact ivLen, shared forced non-empty at line 63-65, variant always valid), so the error-mismatch branch at lines 81-85 is dead code — errRef and errGot are always nil. A table test mirroring gostcrypto/kexp15/kexp15_test.go TestKexp15_ErrorCases (lines 48-81) but asserting err-nil agreement on both sides would make the error contract part of the parity guarantee.

**Evidence:** fixKey (kexp15_parity_test.go:47-51) always returns exactly n bytes; line 63-65 replaces empty shared with {0x01}; lines 66-76 select valid variant constants and matching ivLen — so Kexp15 input validation (kexp15.go:106-120, kexp15_gost.go:69-80) can never fire during fuzzing, and no other test in the package feeds invalid inputs.

**Verifier confirmation:** The finding is factually accurate in every detail.

1. `fixKey` (kexp15_parity_test.go:47-51) zero-pads/truncates to exactly n bytes, so `cipherKey` and `macKey` are always 32 bytes — matching the `exportKeyLen` check at kexp15.go:110/114.

2. Lines 63-65 replace an empty `shared` with `[]byte{0x01}`, bypassing the `len(sharedKey) < 1` guard at kexp15.go:106 and kexp15_gost.go:69.

3. Lines 66-76 select either `KexpMagma`/`KexpKuznyechik` and the matching `ivLen` (4 or 8), then clamp `iv` to exactly that length via `fixKey`. This bypasses the `variant.params()` unknown-variant error (kexp15.go:88-90, kexp15_gost.go:47-49) and the iv-length check (kexp15.go:118-120, kexp15_gost.go:78-80).

4. As a result, both `gost.Kexp15` and `Kexp15` receive always-valid inputs inside the fuzz harness. Both return `nil` errors 100% of the time. The error-mismatch branch at lines 81-85 is dead code — `errRef` and `errGot` are structurally always nil.

5. The clean-room package has `TestKexp15_ErrorCases` (kexp15_test.go:48-81) with 6 invalid-input cases (empty shared, short cipherKey, short macKey, wrong Magma iv, Kuznyechik with 4-byte iv, bad variant integer). No equivalent exists in `parity/kexp15/` — `kexp15_parity_test.go` is the only file in that directory.

6. Both implementations' error contracts are identical (same guard conditions, same ordering), so there is no known active bug — but the gap means any future divergence in error handling would be invisible to the parity gate.

No entry in docs/engine-vectors.md mentions kexp15 input-validation as a documented intentional divergence. The finding is not a restatement of a known intentional difference.

**Suggested fix:** Add a `TestKexp15_ErrorCasesParity` table test in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/kexp15/kexp15_parity_test.go` mirroring the six cases from `gostcrypto/kexp15/kexp15_test.go:65-71`. For each case, call both `gost.Kexp15(...)` and `Kexp15(...)` and assert that `(errRef != nil) == (errGot != nil)`. The six cases are: empty shared key; cipherKey 31 bytes; macKey 31 bytes; Magma iv 3 bytes; Kuznyechik with a 4-byte (Magma-length) iv; and an unknown variant constant (e.g., `KexpVariant(99)`). This makes the error contract part of the parity guarantee and turns lines 81-85 from dead code into reachable coverage.

### [KXP-04] Single Magma-only fuzz seed; Kuznyechik variant and OMAC complete-final-block (K1) path unseeded

- **Location:** `gostcrypto-compat/parity/kexp15/kexp15_parity_test.go:54-60`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The corpus is one seed: the Magma etalon with kuz=false. CI (`go test`) only replays seeds, so on every non-fuzzing run the Kuznyechik path of the differential executes zero times in the fuzz target. Additionally, neither variant's seed exercises the OMAC K1 (complete final block) branch: the OMAC input is iv||shared, and 4+32=36 (Magma) / 8+32=40 (Kuznyechik, if seeded) are both non-multiples of the block size, so only the K2/padding branch is replayed. Add a kuz=true seed (e.g. the RFC 9189 A.1.3.2 inputs) and seeds with shared lengths making ivLen+len(shared) block-aligned (e.g. shared=4 or 12 bytes for Magma, 8 or 24 for Kuznyechik). Otherwise the fuzz harness itself is well-shaped — it varies shared length/content, both keys, IV, and the variant, and the non-empty clamp is appropriate since both sides reject empty shared (no documented empty-input divergence applies to kexp15 per TODO.md/engine-vectors.md, which mention it nowhere).

**Evidence:** f.Add at lines 54-60 supplies exactly one tuple ending in `false` (Magma); no testdata/ seed-corpus directory exists (ls parity/kexp15/testdata -> absent). OMAC final-block dispatch: clean-room omac.go:186-201 and facade omac.go:144-155 take the K1 branch only when the buffered tail is exactly blockSize; with the seed's 36-byte (4+32) OMAC input over an 8-byte block the tail is 4 bytes -> K2 branch only.

**Verifier confirmation:** All three claims in the finding are independently verified against the source:

1. **Single Magma-only fuzz seed**: `FuzzKexp15Conformance` at `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/kexp15/kexp15_parity_test.go:53-60` has exactly one `f.Add` call. It passes the literal `false` as the `kuz` argument. No second `f.Add` exists. No `testdata/` corpus directory exists (confirmed by `ls`).

2. **Kuznyechik path unseeded in `go test`**: The fuzz body at line 62 dispatches on `kuz bool`. In `go test` (seed-replay only), with a single seed of `kuz=false`, the block at lines 69-73 (`refVariant = gost.KexpKuznyechik`, `myVariant = KexpKuznyechik`, `ivLen = 8`) is never entered. The RFC 9189 A.1.3.2 Kuznyechik vector is present in `gostcrypto/kexp15/kexp15_test.go:88-110` but was never copied into an `f.Add` seed here.

3. **OMAC K1 branch unseeded**: The OMAC input is `iv || sharedKey`. For the single seed: Magma iv=4 bytes, shared=32 bytes → total=36 bytes. Magma block size=8. `36 % 8 = 4 ≠ 0`, so when `Sum` is called (clean-room `omac.go:186`; facade `omac.go:144`), `len(buf) = 4 ≠ blockSize=8` → always takes the K2/padding branch. The K1 branch (`len(buf) == blockSize`) is never reached in seed replay. For K1 coverage one needs `(iv_len + shared_len) % block_size == 0`, e.g. `shared_len=4` for Magma (`4+4=8`) or `shared_len=8` for Kuznyechik (`8+8=16`). No such seed exists.

4. **Not a documented divergence**: Neither `gostcrypto/TODO.md` nor `gostcrypto-compat/docs/engine-vectors.md` mention kexp15 or any OMAC K1-branch intentional divergence. The finding does not restate a known acceptable gap.

Severity is low (not none) because the fuzz target is structurally correct and does cover the K2 path; the gap is about seed coverage for `go test` rather than a logic error or missing test. The K1 path differs only in which CMAC subkey is applied to the final block — a real but lower-risk coverage gap.

**Suggested fix:** Add two more `f.Add` seeds to `FuzzKexp15Conformance`:

1. A `kuz=true` seed using the RFC 9189 A.1.3.2 inputs (already pinned in `gostcrypto/kexp15/kexp15_test.go:88`):
```go
f.Add(
    mustHexF("a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d"), // shared
    mustHexF("1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24"), // cipherKey
    mustHexF("7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1"), // macKey
    mustHexF("214a6a298e99e325"),                                                     // iv (8-byte, Kuznyechik)
    true,
)
```

2. A Magma seed whose OMAC input is block-aligned (`(iv_len + shared_len) % 8 == 0`), e.g. `shared` of 4 bytes so total = 4+4 = 8, hitting the K1 branch:
```go
f.Add(
    mustHexF("deadbeef"),                                                              // shared (4 bytes → 4+4=8, K1 path)
    mustHexF("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637"), // cipherKey
    mustHexF("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f"), // macKey
    mustHexF("67bed654"),                                                              // iv (4-byte, Magma)
    false,
)
```

Optionally, a Kuznyechik K1-path seed: shared of 8 bytes → `8+8=16`, K1 branch over the 16-byte Kuznyechik block.

---

## keywrap

**Reviewer summary:** The keywrap parity test is a real, non-vacuous differential: the clean-room side (gostcrypto/keywrap) reimplements the GOST 28147-89 cipher, CFB feedback, and 4-byte IMIT from scratch, while the oracle side (gostcryptocompat.KeyWrapCryptoPro) drives gogost's cipher/CFB/MAC primitives, and the test asserts full 44-byte equality on both S-boxes plus a tc26-Z KAT independently captured from the gost-engine 3.0.3 dylib. All inputs are wired identically to both sides, no skips or swallowed errors, and the fuzz target varies the entire kek|ukm|cek input space across both S-boxes. The main weaknesses are structural rather than bugs: the RFC 4357 §6.5 diversification orchestration is project-written on BOTH sides (gogost's own WrapGost/DiversifyCryptoPro are unused), so the gost-engine KAT is the only truly independent anchor — and it exists only for tc26-Z, leaving the CryptoPro-A leg without an independent pin even though gogost's UnwrapCryptoPro provides a free, verified-working round-trip oracle for exactly that S-box. Secondary gaps: the exported Diversify function (and the already-present-but-unused katKEKUKM intermediate vector) is untested, error paths are never exercised, and the fuzz seed corpus is minimal.

### [KWP-01] Oracle is only partially gogost: KEK diversification and wrap assembly are project-written on both sides

- **Location:** `gostcrypto-compat/primitives_gost.go:306-375 (oracle) vs gostcrypto/keywrap/keywrap.go:85-172 (clean-room)`
- **Category:** correctness · **Severity:** medium · **Verifier:** sonnet

**Finding:** The 'gogost oracle' the test diffs against (gost.KeyWrapCryptoPro) reimplements the RFC 4357 §6.5 diversification loop (s1/s2 word sums, LSB-first bit selection, LE32(s1)||LE32(s2) IV layout) and the UKM|CEK_ENC|MAC assembly in this project's own code; only the gost28147 cipher, CFB, and MAC primitives actually come from gogost. gogost ships its own DiversifyCryptoPro/WrapGost (third_party/gogost/gost28147/wrap.go) but the facade does not use them (WrapGost hardcodes CryptoPro-A and skips diversification). So a common-mode misreading of §6.5 — written twice by the same project from the same keywrap-cryptopro.md guide — would pass the differential. This is fully mitigated for tc26-Z by the pinned KAT captured from the gost-engine 3.0.3 dylib (independent source, per keywrap-cryptopro.md:317-318), but NOT for the CryptoPro-A leg (see next finding). The block-cipher/CFB/MAC layers are genuinely differential (clean-room reimplements them inline; oracle uses gogost), so the diff is meaningful below the orchestration layer.

**Evidence:** primitives_gost.go:317 `kekUKM := keyDiversifyCryptoPro(sbox, kek, ukm)` — keyDiversifyCryptoPro (lines 346-375) is facade code mirroring gost-engine's gost_keywrap.c, not gogost's DiversifyCryptoPro. keywrap-cryptopro.md:384-387 states outright: "Differential testing for this primitive has no gogost reference target ... the only oracles are (a) the in-repo internal/gost.KeyWrapCryptoPro itself and (b) the gost-engine 3.0.3 keyWrapCryptoPro dylib".

**Verifier confirmation:** The finding is accurate in every material claim. Here is what the code actually shows:

**Oracle does not call gogost.DiversifyCryptoPro**

`primitives_gost.go:346-375` (`keyDiversifyCryptoPro`) is project-written code. It calls `gost28147.NewCipher(out, sbox.inner)` + `c.NewCFBEncrypter(S[:])` + `cfb.XORKeyStream(out, out)` — it uses gogost's block cipher and CFB primitives, but the diversification orchestration (eight-round loop, LE32 word sums via `s1 += k`, IV layout `S[0..3]=LE32(s1), S[4..7]=LE32(s2)`) is written from scratch in this project.

Gogost's own `DiversifyCryptoPro` exists at `third_party/gogost/gost28147/wrap.go:60-79` — same algorithm, slightly different Go style (`uint64` accumulators with `% (1<<32)` vs `uint32` wrapping). The oracle never calls it.

**Gogost's WrapGost skips diversification**

`third_party/gogost/gost28147/wrap.go:24-38`: `WrapGost(ukm, kek, cek)` calls `NewCipher(kek, &SboxIdGost2814789CryptoProAParamSet)` directly — no diversification step, CryptoPro-A S-box hardcoded. It cannot be used as-is for a sbox-parameterized, diversification-including oracle.

**What the parity test actually diffs**

`parity/keywrap/keywrap_parity_test.go:70-80`: the clean-room (`keywrap.KeyWrapCryptoPro`, imports `github.com/bigbes/gostcrypto/gost28147`) is compared against the in-repo facade (`gostcryptocompat.KeyWrapCryptoPro`, imports `go.stargrave.org/gogost/v7/gost28147`). The block cipher underneath is genuinely from two different code bases (clean-room vs gogost), so the differential has real value at the cipher layer. However, the diversification orchestration, ECB loop, and MAC assembly in both sides were written by the same project from the same guide (`keywrap-cryptopro.md`). A common-mode misreading of RFC 4357 §6.5 in the orchestration would pass.

**tc26-Z is covered; CryptoPro-A is not**

`parity/keywrap/helpers_test.go:24` pins `katWrapped = "0102030405..."` for tc26-Z, annotated in `keywrap_test.go:21` as "captured from gost-engine 3.0.3". `parity/keywrap/keywrap_parity_test.go:56`: the `cryptopro-a` case has `wantPinned: nil` — no independent KAT is asserted. The `keywrap-cryptopro.md:384-387` document explicitly states: "Differential testing for this primitive has no gogost reference target ... the only oracles are (a) the in-repo `internal/gost.KeyWrapCryptoPro` itself and (b) the gost-engine 3.0.3 keyWrapCryptoPro dylib symbol" — and the CryptoPro-A path through the engine dylib has not been pinned as a KAT vector.

The claim that "the block-cipher/CFB/MAC layers are genuinely differential" is also correct: `keywrap.go` imports the clean-room `gostcrypto/gost28147`; the oracle imports `gogost/v7/gost28147`. So cipher-level bugs are caught. The weakness is only at the orchestration layer and the missing CryptoPro-A independent KAT.

Severity stays at medium: the cipher primitives are truly differential, the tc26-Z path has an independent engine KAT, and the algorithm is specified by an RFC (reducing the risk of a correlated orchestration bug being undetected). The gap is real but bounded.

**Suggested fix:** Two targeted actions close the gap:

1. **Pin a CryptoPro-A KAT from gost-engine.** Run the gost-engine 3.0.3 dylib's `keyWrapCryptoPro` with `sbox=CryptoPro-A` on the same KAT inputs (`katKEK`, `katUKM`, `katSession`) to get the expected 44-byte output, then add it as `katWrappedCryptoProA` in `parity/keywrap/helpers_test.go` and set `wantPinned` in the `cryptopro-a` case of `TestKeyWrapCryptoPro_Differential`. This closes the CryptoPro-A oracle gap with an independent reference.

2. **Add a diversification-only differential sub-test using gogost.DiversifyCryptoPro.** For the CryptoPro-A S-box (the only one gogost supports in `DiversifyCryptoPro`), add a test in `parity/keywrap/` that calls both `keywrap.Diversify(SboxCryptoProA, kek, ukm)` and `gost28147.DiversifyCryptoPro(kek, ukm)` (from vendored gogost) and asserts byte-for-byte equality. This makes the diversification step itself genuinely differential for at least one S-box, using gogost as an independent oracle at the orchestration layer — not just at the cipher layer.

Note: action 1 is higher priority since it's simpler (one pinned constant) and covers the entire wrap output. Action 2 is defence-in-depth for the diversification step specifically.

### [KWP-02] CryptoPro-A leg has no independent pinned vector; the genuinely-gogost UnwrapCryptoPro round-trip oracle is unused

- **Location:** `gostcrypto-compat/parity/keywrap/keywrap_parity_test.go:50-63`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** Both cryptopro-a table cases have wantPinned == nil, so the only check on the CryptoPro-A path is clean-room vs facade — two sibling implementations of the diversify/wrap orchestration written by the same project (previous finding). The clean-room guide's own re-implementation checklist (keywrap-cryptopro.md:378-380, step 7) requires generating a CryptoPro-A vector from the engine dylib and asserting it; that vector never landed here. There IS a pure-gogost oracle available for exactly this leg: gost28147.UnwrapCryptoPro(kek, wrapped) (third_party/gogost/gost28147/wrap.go:81-83) performs gogost's own DiversifyCryptoPro + UnwrapGost with the hardcoded CryptoPro-A S-box. I verified that adding `gost28147.UnwrapCryptoPro(kekCopy, wrapped)` on the clean-room CryptoPro-A output round-trips back to the original CEK — note gogost's DiversifyCryptoPro mutates kek in place (wrap.go:61 `out := kek`), so the caller must pass a copy. Wiring this round-trip into both the table test's cryptopro-a cases and the fuzz target would close the common-mode gap for that S-box with zero new vectors.

**Evidence:** keywrap_parity_test.go:33 `wantPinned []byte // nil when no KAT pinned for this S-box` — only the tc26z-kat case sets it. Verified experiment: gost28147.UnwrapCryptoPro(copy(kek), KeyWrapCryptoPro(SboxCryptoProA, kek, ukm, cek)) == cek passes.

**Verifier confirmation:** The finding is accurate in all its factual claims, though the severity should be low rather than medium.

**What is confirmed:**

1. `wantPinned == nil` for both `cryptopro-a` and `cryptopro-a-other` cases (keywrap_parity_test.go:51 and :57). Only `tc26z-kat` has a pinned external vector.

2. The oracle `gost.KeyWrapCryptoPro` (imported at line 9) resolves to `primitives_gost.go:306`, which contains the project's own reimplementation of `keyDiversifyCryptoPro` (primitives_gost.go:346-375). This is a sibling implementation by the same author written from the same RFC spec, NOT gogost's own `DiversifyCryptoPro`. Although the code differs structurally (manual byte extraction at line 353 vs `binary.LittleEndian.Uint32`; `gost28147.NewCipher` + `NewCFBEncrypter` at lines 370-372 vs clean-room's `cfbEncrypt`), it shares the same conceptual decisions.

3. `gost28147.UnwrapCryptoPro` (third_party/gogost/gost28147/wrap.go:81-83) IS an independent oracle for the CryptoPro-A path: it calls gogost's own `DiversifyCryptoPro` (line 75 uses hardcoded `SboxIdGost2814789CryptoProAParamSet`) + `UnwrapGost` (line 43 also hardcodes the same S-box), written by a different author (Sergey Matveev) from an independent implementation.

4. The mutation caveat in the finding is correct: `DiversifyCryptoPro` at line 61 does `out := kek` (slice-header alias, same backing array), then line 76 `XORKeyStream(out, out)` overwrites that memory — so the caller's kek is destroyed. A copy is required before calling `UnwrapCryptoPro`.

5. The round-trip would be valid for CryptoPro-A: the clean-room `KeyWrapCryptoPro` with `SboxCryptoProA` encrypts/MACs under the CryptoPro-A S-box (gostcrypto/keywrap/keywrap.go diversify + cfbEncrypt both use the passed sbox), and gogost's `UnwrapCryptoPro` hardcodes the same S-box throughout — so a correctly-wrapped CryptoPro-A blob should round-trip through gogost's unwrap.

**Why severity is low, not medium:**

The existing differential is not vacuous. The two compared implementations (`keywrap.KeyWrapCryptoPro` from gostcrypto vs `gost.KeyWrapCryptoPro` from gostcryptocompat) use structurally different code paths for diversification and CFB, different cipher invocation styles, and the compat facade's diversification was independently reviewed against gost-engine source. The gap is about test coverage depth (no external oracle for CryptoPro-A), not a known or suspected correctness problem. There is no indication in TODO.md or docs/engine-vectors.md of any documented divergence on this path.

**Suggested fix:** In `parity/keywrap/keywrap_parity_test.go`, add an import of the vendored gogost wrap package and wire in a round-trip assertion for the two `cryptopro-a` test cases:

1. Add import: `gogostwrap "go.stargrave.org/gogost/v7/gost28147"` (or use the existing third_party path).

2. In the table-driven loop, after computing `gotNew`, add for `sbox == "cryptopro-a"` cases:

```go
if tc.sbox == "cryptopro-a" {
    kekCopy := make([]byte, len(tc.kek))
    copy(kekCopy, tc.kek)
    got := gogostwrap.UnwrapCryptoPro(kekCopy, gotNew)
    if got == nil {
        t.Fatalf("gogost UnwrapCryptoPro returned nil (MAC mismatch or bad data)")
    }
    if !bytes.Equal(got, tc.cek) {
        t.Fatalf("gogost round-trip mismatch (sbox=cryptopro-a)\n got: %x\nwant: %x", got, tc.cek)
    }
}
```

3. Mirror the same check in `FuzzKeyWrapCryptoPro_Differential` for the `cryptopro-a` branch.

Note: the `kekCopy` is required because `gogost.DiversifyCryptoPro` aliases its argument (`out := kek`, wrap.go:61) and overwrites it via `XORKeyStream(out, out)` (line 76). Passing `tc.kek` directly would corrupt the test case's key.

### [KWP-03] Exported Diversify is never parity-tested, and the intermediate KAT constants for it sit unused in helpers_test.go

- **Location:** `gostcrypto/keywrap/keywrap.go:126-136; gostcrypto-compat/parity/keywrap/helpers_test.go:21-23`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** keywrap exports two functions: KeyWrapCryptoPro and Diversify. The parity package exercises only the former. Diversify (the RFC 4357 §6.5 step exposed for cross-checks) has no differential or KAT coverage here, even though (a) helpers_test.go defines katKEKUKM = the gost-engine-verified intermediate KEK(UKM) for the tc26-Z KAT inputs (keywrap-cryptopro.md:332) and never references it — likewise katCEKENC and katCEKMAC are dead constants — and (b) gogost's exported DiversifyCryptoPro is a direct independent oracle for the CryptoPro-A S-box. Its documented panic paths (kek != 32 B, ukm != 8 B) are also unexercised. Diversify is implicitly covered through KeyWrapCryptoPro's internal diversify call, but the exported wrapper itself (signature, panic guards, non-aliasing of the input kek) is not.

**Evidence:** grep for katKEKUKM/katCEKENC/katCEKMAC in parity/keywrap/ hits only their declarations in helpers_test.go:21-23; keywrap_parity_test.go contains no call to Diversify.

**Verifier confirmation:** All three specific claims in the finding check out against actual source:

1. Dead constants confirmed: `katKEKUKM`, `katCEKENC`, `katCEKMAC` are declared in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/keywrap/helpers_test.go:21-23` and grep produces zero hits for any reference in `keywrap_parity_test.go`. `katWrapped` covers the full-blob pin, but the three split-field constants are unreachable dead code in the parity package.

2. No differential test for `Diversify` confirmed: `parity/keywrap/keywrap_parity_test.go` contains only `TestKeyWrapCryptoPro_Differential` and `FuzzKeyWrapCryptoPro_Differential`, both of which call `KeyWrapCryptoPro` only. The exported `keywrap.Diversify` (lines 126-136 of `gostcrypto/keywrap/keywrap.go`) is never invoked from this package.

3. Oracle availability confirmed: `./third_party/gogost/gost28147/wrap.go:60` exports `DiversifyCryptoPro(kek, ukm []byte) []byte` — a directly usable independent oracle — but it is not wired into the parity tests.

Severity adjustment to LOW (down from claimed MEDIUM): The finding is real but the risk is smaller than claimed. The diversify algorithm is indirectly covered by the full-wrap differential — if `diversify` produced wrong output, the 44-byte wrap blob would differ and `TestKeyWrapCryptoPro_Differential` would fail. What is genuinely missing is: (a) a parity test that pins `Diversify`'s output against `gogost.DiversifyCryptoPro` independently (both s-boxes), and (b) coverage of `Diversify`'s exported panic guards in the parity suite. The dead constants are a cleanliness issue, not a correctness gap. The `gostcrypto/keywrap/keywrap_test.go` already tests the panic guards at the module level (lines 120-156), so this is purely a missing cross-module parity test, not a coverage hole in the overall test suite.

Note: the `gostcryptocompat` facade does NOT export a `Diversify` function (only unexported `keyDiversifyCryptoPro`), so the finding's claim that "gogost's exported DiversifyCryptoPro is a direct independent oracle" is correct — the differential would need to import `gogost/gost28147.DiversifyCryptoPro` directly, not via the facade.

**Suggested fix:** In `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/keywrap/keywrap_parity_test.go`, add a `TestDiversify_Differential` test that:

1. Calls `keywrap.Diversify(SboxTC26Z, kek, ukm)` against `gogost/gost28147.DiversifyCryptoPro(kek, ukm)` for both the tc26-Z KAT inputs (pinning against `katKEKUKM`) and at least one random input — note that gogost's `DiversifyCryptoPro` hardcodes `SboxIdGost2814789CryptoProAParamSet`, so the differential only applies for CryptoPro-A; the TC26-Z leg can only be pinned against `katKEKUKM` (no gogost oracle for TC26-Z diversification).

2. Add panic-guard sub-tests for the four bad-size cases (short kek, long kek, short ukm, long ukm) using `recover()`, mirroring `gostcrypto/keywrap/keywrap_test.go:120-156`.

3. Delete or use the three dead constants `katKEKUKM`, `katCEKENC`, `katCEKMAC` in `helpers_test.go` — either reference them in the new `TestDiversify_Differential` (for `katKEKUKM`) and in field-level assertions within `TestKeyWrapCryptoPro_Differential` (for `katCEKENC` / `katCEKMAC`), or remove them if no test will use them.

### [KWP-04] Error-path parity (wrong kek/ukm/cek lengths) never exercised

- **Location:** `gostcrypto-compat/parity/keywrap/keywrap_parity_test.go:70-77`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Both implementations validate kek=32, ukm=8, sessionKey=32 and return errors otherwise (keywrap.go:86-96; primitives_gost.go:307-315), but the test treats any error as a Fatal and never feeds an invalid length, so the rejection behaviour (both sides must error, neither may produce output) is never compared. Low severity: the error texts intentionally differ and the validation is trivial, but a one-case check that both sides reject e.g. a 31-byte kek would pin the contract.

**Evidence:** All four table cases and the fuzz body use exactly 32/8/32-byte inputs; `if err != nil { t.Fatalf(...) }` is the only error handling on both sides.

**Verifier confirmation:** The finding is accurate. Reading the actual source confirms both claims:

1. All four table cases in `TestKeyWrapCryptoPro_Differential` supply exactly 32-byte kek, 8-byte ukm, and 32-byte cek. The error handler at lines 71-73 and 75-77 is `t.Fatalf`, so any error on valid inputs would be a test failure, not a verified contract.

2. The fuzz body (`FuzzKeyWrapCryptoPro_Differential`, lines 105-107) allocates `buf := make([]byte, 72)` and hard-slices it as `k, u, c := buf[0:32], buf[32:40], buf[40:72]`. This always produces exactly the correct lengths regardless of what the fuzzer provides in `raw`, so the length-validation branches in both implementations are structurally unreachable during this test.

Both implementations do validate lengths and error on bad inputs:
- Clean-room (`keywrap.go:86-96`): checks `len(kek) != keySize`, `len(ukm) != ukmSize`, `len(sessionKey) != keySize`, returning wrapped sentinel errors.
- Oracle (`primitives_gost.go:307-315`): same checks with different error message text.

The finding is NOT mentioned in `gostcrypto/TODO.md` or `gostcrypto-compat/docs/engine-vectors.md` as an intentional omission or documented divergence. The error text difference between the two sides is expected and benign — the contract to pin is merely "both sides must return a non-nil error" on invalid input, not that the texts match.

The severity is low: the happy-path cryptographic parity is well-exercised by four table cases and a fuzz target. The gap only affects the rejection-contract parity, which is trivial validation logic unlikely to diverge.

**Suggested fix:** Add a sub-test (or a separate `TestKeyWrapCryptoPro_ErrorParity` function) in `gostcrypto-compat/parity/keywrap/keywrap_parity_test.go` that exercises one invalid-length case for each of the three parameters and asserts both sides return a non-nil error:

```go
func TestKeyWrapCryptoPro_ErrorParity(t *testing.T) {
    valid32 := bytes.Repeat([]byte{0xAA}, 32)
    valid8  := bytes.Repeat([]byte{0xBB}, 8)
    newSbox, repoSbox := pick("tc26-z")

    cases := []struct {
        name string
        kek, ukm, cek []byte
    }{
        {"short-kek", valid32[:31], valid8, valid32},
        {"short-ukm", valid32, valid8[:7], valid32},
        {"short-cek", valid32, valid8, valid32[:31]},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            _, errNew  := KeyWrapCryptoPro(newSbox, tc.kek, tc.ukm, tc.cek)
            _, errRepo := gost.KeyWrapCryptoPro(repoSbox, tc.kek, tc.ukm, tc.cek)
            if errNew == nil {
                t.Fatalf("clean-room: expected error for %s, got nil", tc.name)
            }
            if errRepo == nil {
                t.Fatalf("oracle: expected error for %s, got nil", tc.name)
            }
            // Error texts intentionally differ; only the non-nil contract is pinned.
        })
    }
}
```

### [KWP-05] Fuzz seed corpus is two identical-input seeds and the fuzz loop covers only the wrap entry point

- **Location:** `gostcrypto-compat/parity/keywrap/keywrap_parity_test.go:92-124`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The fuzz target itself is well-shaped for this fixed-size primitive: it varies the full 72 bytes of kek|ukm|cek across both S-boxes (the only meaningful dimensions — lengths are fixed by the API, and the facade's opaque *Sbox makes arbitrary S-box fuzzing impossible), and there is no empty-input divergence concern here. Remaining gaps: (1) the seed corpus is just two f.Add entries sharing the same kek/ukm/cek (only the sbox string differs) and there is no committed testdata corpus dir, so plain `go test` replays essentially one input per S-box — boundary seeds (all-zero, all-0xFF) would cost nothing; (2) the fuzz body never also diffs the exported Diversify against gogost's DiversifyCryptoPro (CryptoPro-A branch) or round-trips via gogost UnwrapCryptoPro, both of which would strengthen oracle independence per-execution at trivial cost; (3) non-{tc26-z,cryptopro-a} sbox strings are silently discarded (return at line 103), wasting a slice of fuzz executions — harmless but a byte/bool selector would be denser.

**Evidence:** Lines 94-99: both seeds built from the same katKEK/katUKM/katSession; `ls parity/keywrap/` shows no testdata/ corpus directory; fuzz body calls only KeyWrapCryptoPro on each side.

**Verifier confirmation:** All three major sub-claims are verified against the actual source:

1. Two identical-input seeds. Lines 93-99 of keywrap_parity_test.go: `kek/ukm/cek` are decoded once from `katKEK/katUKM/katSession`, then the `for _, name := range []string{"tc26-z", "cryptopro-a"}` loop appends the same three byte slices for both `f.Add` calls. The only difference between the two seeds is the sbox string. No all-zero, all-0xFF, or other boundary seeds are present.

2. No testdata corpus directory. `find parity/keywrap` returns only two files: `helpers_test.go` and `keywrap_parity_test.go`. There is no `testdata/` subdirectory and no committed seed corpus, so `go test` replays exactly those two inline seeds.

3. Fuzz body covers only KeyWrapCryptoPro. Lines 111-122 call `KeyWrapCryptoPro` on both sides and compare outputs. The clean-room primitive exports `Diversify` (keywrap.go:126), and the gogost oracle (third_party/gogost/gost28147/wrap.go:60-79 and 81-83) exports both `DiversifyCryptoPro` and `UnwrapCryptoPro`. Neither is exercised in the fuzz target. The gostcryptocompat facade's `keyDiversifyCryptoPro` is unexported, so a facade-level differential for `Diversify` would need to call gogost directly — which is straightforward given the existing import path.

4. Silent early-return for unknown sbox strings (line 102-104) wastes fuzz budget; a byte/bool selector would be denser but is cosmetic.

Severity remains low: the table test `TestKeyWrapCryptoPro_Differential` has four cases covering both S-boxes with distinct inputs, correctness of the `KeyWrapCryptoPro` path is therefore well-covered at `go test` time. The gaps are about fuzzing depth and oracle independence for the `Diversify` sub-step, not a correctness hole. No documented divergence in keywrap (gostcrypto/TODO.md and docs/engine-vectors.md make no mention of keywrap divergences).

**Suggested fix:** Three incremental improvements:

1. Add boundary seeds. In the `FuzzKeyWrapCryptoPro_Differential` seed loop, add two extra calls:
   - all-zero input: `f.Add("tc26-z", make([]byte, 72))`
   - all-0xFF input: `f.Add("cryptopro-a", bytes.Repeat([]byte{0xFF}, 72))`

2. Add a `Diversify` differential inside the fuzz body. Since `third_party/gogost/gost28147` is already available in the module, add:
   ```go
   import gogostwrap "go.stargrave.org/gogost/v7/gost28147"
   ...
   // inside the Fuzz body, after the KeyWrapCryptoPro diff:
   gotDivNew := Diversify(newSbox, k, u)
   gotDivGoGost := gogostwrap.DiversifyCryptoPro(append([]byte{}, k...), u)
   if !bytes.Equal(gotDivNew, gotDivGoGost) {
       t.Fatalf("Diversify mismatch (sbox=%s)\n new=%x\ngogost=%x", sbox, gotDivNew, gotDivGoGost)
   }
   ```
   Note: `DiversifyCryptoPro` in gogost mutates its `kek` argument in-place (it assigns `out := kek` without copying), so a defensive copy of `k` is required before calling it.

3. Replace the string sbox selector with a bool or byte to eliminate wasted fuzz iterations on invalid sbox strings:
   ```go
   f.Fuzz(func(t *testing.T, useTC26Z bool, raw []byte) {
       sboxName := "cryptopro-a"; newSbox, repoSbox := SboxCryptoProA, gost.SboxCryptoProA
       if useTC26Z { sboxName = "tc26-z"; newSbox, repoSbox = SboxTC26Z, gost.SboxTC26Z }
       _ = sboxName  // used in Fatalf format strings
       ...
   })
   ```

---

## kuznyechik

**Reviewer summary:** The kuznyechik parity package is a genuinely sound differential test. The oracle is the real vendored gogost gost3412128 (GPL, structurally independent implementation: runtime gfCache/subtle.XORBytes vs the clean-room's fused S+L tables) reached through the thin gostcryptocompat facade wrappers (primitives_gost.go:84-108), so there is no tautology or shared helper. Both sides receive the identical key/block, all assertions are bytes.Equal on full 16-byte outputs (never length/err-nil checks), errors are fatal not swallowed, the random differential runs 4096 deterministic iterations covering Encrypt, Decrypt, and cross round-trips, and FuzzDiffKuznyechik additionally diffs Decrypt on arbitrary fuzzer-chosen blocks (not just valid ciphertexts) with sensible RFC-7801 and all-zero seeds. The test passes and exercises everything that matters for byte-output parity of a fixed-size block cipher; key and block are both fully fuzzed and no documented Kuznyechik divergence exists in TODO.md/engine-vectors.md. Remaining findings are all low-severity hardening gaps: the KAT case doesn't anchor the RFC literal ciphertext within this package (it is anchored in the clean-room's own tests and the facade tests), malformed-input behaviour (panic vs error vs gogost's silent zero-pad of short src) is never pinned, and dst==src aliasing is never exercised.

### [KUZ-01] TestDiffKAT does not diff Decrypt on the pinned RFC 7801 vector nor anchor the literal expected ciphertext

- **Location:** `parity/kuznyechik/kuznyechik_parity_test.go:61-77`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The KAT case only compares clean-room Encrypt vs oracle Encrypt; it never runs Decrypt on the pinned vector and never asserts the RFC 7801 expected ciphertext 7f679d90bebc24305a468d42b9d4edcd, so within this package the KAT is only a differential, not a spec anchor. Mitigated: the literal is anchored in the clean-room's own tests (gostcrypto/kuznyechik/kuznyechik_test.go:27) and in this module's facade tests (cipher_modes_test.go:86), and the random/fuzz differentials cover Decrypt, so this is a belt-and-suspenders gap, not a correctness hole.

**Evidence:** TestDiffKAT body computes mineCT and refCT and only does `if !bytes.Equal(mineCT, refCT)`; there is no `wantCT` constant and no Decrypt call in the function.

**Verifier confirmation:** The finding is factually accurate. TestDiffKAT at lines 61-77 of parity/kuznyechik/kuznyechik_parity_test.go:

1. Computes `mineCT` and `refCT` and only asserts `bytes.Equal(mineCT, refCT)` — a pure differential with no `wantCT` constant pinning the expected value `7f679d90bebc24305a468d42b9d4edcd`.
2. Never calls `c.Decrypt` or `gost.KuznyechikDecrypt` on the pinned RFC 7801 vector.

Both gaps are exactly as described. The mitigations are also genuine:
- `gostcrypto/kuznyechik/kuznyechik_test.go:27` (TestPrimaryKAT) anchors both Encrypt and Decrypt to the literal `7f679d90bebc24305a468d42b9d4edcd` in the clean-room module.
- `TestDiffAgainstGost` (lines 40-55 of the same parity file) exercises Decrypt differentially over 4096 random inputs, including `gost.KuznyechikDecrypt` against the round-trip plaintext.
- `FuzzDiffKuznyechik` (line 85-86) seeds with the RFC 7801 vector and its fuzz body (lines 109-120) diffs Decrypt on fuzzer-supplied inputs.
- `cipher_modes_test.go:86` anchors the literal in the compat module's facade tests.

The severity stays low (not none) because TestDiffKAT's own label says "RFC 7801 §A.1 vector" but the test body does not assert the spec value — a reader auditing only this test cannot confirm correctness without chasing other files. It is a documentation/test-quality gap rather than a correctness hole.

**Suggested fix:** Add a `wantCT` constant and a Decrypt call to TestDiffKAT so the function is self-contained as a spec anchor:

```go
func TestDiffKAT(t *testing.T) {
    key, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    pt,  _ := hex.DecodeString("1122334455667700ffeeddccbbaa9988")
    wantCT, _ := hex.DecodeString("7f679d90bebc24305a468d42b9d4edcd") // RFC 7801 §5.5

    c := mynew.NewCipher(key)
    mineCT := make([]byte, 16)
    c.Encrypt(mineCT, pt)

    if !bytes.Equal(mineCT, wantCT) {
        t.Fatalf("KAT Encrypt spec mismatch: got %x want %x", mineCT, wantCT)
    }

    refCT, err := gost.KuznyechikEncrypt(key, pt)
    if err != nil {
        t.Fatalf("KuznyechikEncrypt KAT: %v", err)
    }
    if !bytes.Equal(mineCT, refCT) {
        t.Fatalf("KAT Encrypt differential mismatch: mine=%x ref=%x", mineCT, refCT)
    }

    // Decrypt the pinned ciphertext — both sides must recover the original plaintext.
    minePT := make([]byte, 16)
    c.Decrypt(minePT, wantCT)
    if !bytes.Equal(minePT, pt) {
        t.Fatalf("KAT Decrypt mismatch: got %x want %x", minePT, pt)
    }

    refPT, err := gost.KuznyechikDecrypt(key, wantCT)
    if err != nil {
        t.Fatalf("KuznyechikDecrypt KAT: %v", err)
    }
    if !bytes.Equal(refPT, pt) {
        t.Fatalf("KAT Decrypt oracle mismatch: got %x want %x", refPT, pt)
    }
}
```

### [KUZ-02] Fuzz target never exercises in-place operation (dst == src)

- **Location:** `parity/kuznyechik/kuznyechik_parity_test.go:91-128`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** cipher.Block explicitly permits dst and src to overlap entirely; both implementations currently support it because each copies src into a local block before writing dst, but the fuzz target always uses distinct freshly allocated dst buffers, so a future clean-room optimization that writes dst incrementally while still reading src would not be caught. A one-line aliased variant (`c.Encrypt(buf, buf)` diffed against the non-aliased output) would lock the semantics in.

**Evidence:** FuzzDiffKuznyechik allocates `mineCT := make([]byte, 16)` / `minePT := make([]byte, 16)` / `back := make([]byte, 16)` for every call; no path passes the same slice as both dst and src.

**Verifier confirmation:** The finding is factually correct on all points.

Evidence:
1. The fuzz target at parity/kuznyechik/kuznyechik_parity_test.go:91-128 allocates distinct buffers for every call: `mineCT := make([]byte, 16)` (line 97), `minePT := make([]byte, 16)` (line 110), and `back := make([]byte, 16)` (line 123). No path ever passes the same slice as both dst and src.

2. Both implementations are currently safe for in-place use because they copy src into a local array-typed variable before any write to dst:
   - Clean-room (kuznyechik.go:309-319): `var blk [BlockSize]byte; copy(blk[:], src)` → mutations on blk → `copy(dst, blk[:])`.
   - gogost oracle (cipher.go:228-236): `blk := new([BlockSize]byte); copy(blk[:], src)` → mutations on blk → `copy(dst, blk[:])`.
   
   Neither implementation is currently broken for the aliased case.

3. The `cipher.Block` contract (Go standard library) explicitly permits dst and src to alias completely. Any future optimization to the clean-room Encrypt or Decrypt that writes dst bytes while still consuming src bytes (e.g., inlining round outputs directly into dst) would silently break correctness for the aliased case, and the current fuzz target would not detect it.

4. TODO.md and docs/engine-vectors.md contain no mention of in-place operation as a known limitation, intentional divergence, or out-of-scope item. The finding does not restate a documented known issue.

The gap is real: the fuzz target provides no aliasing regression coverage. The severity is correctly assessed as low because (a) there is no current bug — both implementations handle the aliased case correctly by construction today, and (b) the risk is prospective, contingent on a future refactor that breaks the copy-first pattern.

**Suggested fix:** Add an aliased-call sub-check inside FuzzDiffKuznyechik, immediately after the existing Encrypt diff block (after line 107):

```go
// In-place (dst == src) must produce identical output.
inBuf := make([]byte, 16)
copy(inBuf, blk)
c.Encrypt(inBuf, inBuf) // dst == src
if !bytes.Equal(inBuf, mineCT) {
    t.Fatalf("Encrypt in-place mismatch\n key=%x blk=%x\n inplace=%x dist=%x",
        key, blk, inBuf, mineCT)
}
```

A symmetric block for Decrypt should follow after the `minePT` / `refPT` diff:

```go
inBuf2 := make([]byte, 16)
copy(inBuf2, blk)
c.Decrypt(inBuf2, inBuf2) // dst == src
if !bytes.Equal(inBuf2, minePT) {
    t.Fatalf("Decrypt in-place mismatch\n key=%x blk=%x\n inplace=%x dist=%x",
        key, blk, inBuf2, minePT)
}
```

No change to the clean-room primitive itself is needed; both implementations are safe today. The fix is purely additive test coverage that locks the aliasing semantics as a regression guard against future optimisations.

### Dismissed for kuznyechik (do NOT act on these)

#### DISMISSED: Malformed-input behaviour parity (short src/dst, wrong key length) never exercised

- **Location:** `parity/kuznyechik/kuznyechik_parity_test.go:17-57` · **Category:** test-gap · **Severity claimed:** low · **Verifier:** sonnet

**Original claim:** All cases feed exactly 32-byte keys and 16-byte blocks. The clean-room panics on len(src)<16 / len(dst)<16 (gostcrypto/kuznyechik/kuznyechik.go:300-307) and on non-32-byte keys (kuznyechik.go:283-285); gogost's raw Cipher silently zero-pads a short src (third_party/gogost/gost3412128/cipher.go:229 `copy(blk[:], src)`) while the facade oracle returns an error for non-16 inputs (primitives_gost.go:85-87). These edge behaviours diverge and are never compared or even pinned. Low severity because the crypto/cipher.Block contract makes short inputs caller error, and byte-output parity (the actual goal) is fully covered — but a guard test pinning each side's rejection behaviour would prevent silent contract drift.

**Why dismissed:** The finding makes two claims that I need to assess separately:

**Claim 1: Wrong key length diverges between clean-room and gogost.**
This is factually incorrect. Both `NewCipher` implementations panic on wrong key size:
- Clean-room (`gostcrypto/kuznyechik/kuznyechik.go:283-285`): `panic("kuznyechik: invalid key size, want 32 bytes")` if `len(key) != 32`.
- gogost (`third_party/gogost/gost3412128/cipher.go:200-203`): `panic("invalid key size")` if `len(key) != KeySize` (32).
Both sides panic identically. There is no divergence to pin.

**Claim 2: Short src/dst handling diverges — clean-room panics, gogost silently zero-pads.**
The raw gogost `Cipher.Encrypt` (`cipher.go:227-229`) does `copy(blk[:], src)` without a length check, so a short src is silently zero-padded. The clean-room panics at `kuznyechik.go:300-307`. This behavioral difference is real at the raw-cipher level.

However, the parity tests do NOT compare the clean-room directly against gogost's raw `gost3412128.Cipher`. They compare the clean-room against the **facade oracle** `gostcryptocompat.KuznyechikEncrypt` / `KuznyechikDecrypt` (`primitives_gost.go:84-103`), which validates `len(plaintext) != 16` and returns an error before ever reaching gogost's raw cipher. The facade itself already normalizes the interface — it returns an error for short inputs rather than panicking or silently zero-padding. Passing short blocks through the facade would trigger the facade's error guard, not gogost's zero-pad path. So this divergence does not exist at the parity test's comparison boundary.

**The crypto/cipher.Block contract**: short blocks are a caller violation. The Standard Library's cipher.Block interface is defined as requiring full blocks. Pinning panic-vs-panic or panic-vs-zero-pad behavior for contract violations is not a correctness concern; it is not something a parity test should cover.

**Conclusion**: The finding conflates the raw gogost cipher behavior with the facade oracle that the parity tests actually use. The facade already guards input lengths. The wrong-key claim is simply wrong (both panic). No test gap that would allow a correctness regression exists here.

---

## magma

**Reviewer summary:** The magma parity package is a genuine, non-vacuous differential: the clean-room side is dot-imported from gostcrypto/magma and the oracle is the gogost gost341264 cipher (reached via the gostcryptocompat facade), two independently derived implementations with no shared code or helpers. The table test runs 50,000 deterministic random key/block pairs with full bytes.Equal comparison on both Encrypt and Decrypt plus a round-trip check; oracle errors are t.Fatal'd, never swallowed; the test runs and passes (verified). The fuzz target varies both meaningful dimensions of this fixed-geometry block cipher (32-byte key, 8-byte block, normalized via fixLen), diffs Decrypt on arbitrary fuzzer-supplied blocks rather than only valid ciphertexts, and seeds the RFC 8891 KAT vector plus all-zeros; Magma has no documented empty-input or S-box-order divergence (TODO.md/engine-vectors.md list none for Magma, and both sides pin tc26 param-Z). The independent RFC 8891 expected-ciphertext KAT lives in gostcrypto/magma/magma_test.go, guarding against common-mode error. Remaining gaps are minor: the Cipher object surface (instance reuse, dst==src in-place aliasing, the cipher.Block composition path) is never diffed within this package — only the one-shot fresh-buffer helpers are — and wrong-length rejection paths are unexercised here (though the two sides intentionally differ there, panic vs error, so byte parity does not apply).

### [MAG-01] Cipher object API (instance reuse, dst==src aliasing) never exercised by parity

- **Location:** `parity/magma/magma_parity_test.go:24`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Both the table test and the fuzz target go exclusively through the one-shot MagmaEncrypt/MagmaDecrypt helpers, which allocate a fresh Cipher and a fresh dst per call. The exported Cipher surface (NewCipher + Encrypt/Decrypt methods, satisfying crypto/cipher.Block for CTR/OMAC/MGM composition) is never diffed under realistic mode usage: multiple sequential blocks on one instance, or in-place encryption with dst==src. The gogost oracle's Cipher reuses a shared internal blk buffer (third_party/gogost/gost341264/cipher.go:30,55-71) while the clean-room copies through a stack temp (gostcrypto/magma/magma.go:157-175); a state-carryover or aliasing bug on either side would be invisible to this parity package. Low severity because both implementations are per-call deterministic by inspection and Magma-composed modes are parity-tested elsewhere (e.g. the magma_acpkm facade tests), but the gap is real within this package.

**Evidence:** Test loop only calls `ours := MagmaEncrypt(key, pt)` / `gostref.MagmaEncrypt(key, pt)` (magma_parity_test.go:24-26); the helpers in gostcrypto/magma/magma.go:180-194 do `NewCipher(key).Encrypt(dst, pt)` with a freshly allocated dst each time, so no parity case ever calls c.Encrypt(buf, buf) or reuses one Cipher across blocks.

**Verifier confirmation:** The test-gap claim is real. Both TestMagmaDifferential (magma_parity_test.go:24-26) and FuzzMagmaDifferential (lines 68-70) exclusively invoke the one-shot wrappers MagmaEncrypt/MagmaDecrypt, which each call NewCipher(key).Encrypt(dst, pt) with a freshly allocated dst (gostcrypto/magma/magma.go:180-185, primitives_gost.go:119-122). No parity test ever holds a single Cipher across two block operations or passes dst==src.

However, the finding's threat model for why this matters is overstated:

(1) gogost state-carryover: gost341264/cipher.go lines 55-62 overwrite c.blk unconditionally byte-by-byte from src before any computation. After Encrypt returns, c.blk holds the ciphertext, but on the next call it is fully overwritten before use. No state leaks across calls.

(2) gogost in-place aliasing: gost341264.Cipher.Encrypt passes c.blk[:] as both src and dst to gost28147.Cipher.Encrypt (cipher.go:63). The gost28147 Encrypt reads src into local variables n1, n2 := block2nvs(src) (gost28147/cipher.go:112) before writing to dst via nvs2block (line 114), making in-place safe by construction. The outer wrapper further insulates the caller's buffers by going through c.blk as an intermediate.

(3) Clean-room side: crypt() uses var tmp [BlockSize]byte (magma.go:157), overwrites it completely from src (lines 159-161), then writes to dst (lines 173-175) — in-place safe regardless of aliasing.

Both implementations are per-call stateless (ECB block cipher, no mode state). The gap is a genuine coverage hole — confirmed — but no actual defect path exists in either current implementation under multi-block reuse or aliasing. Severity stays low: the test gap is real, not cosmetic, but carrying the finding as low rather than none is appropriate because future refactors of either side could introduce a state bug that would remain invisible without this coverage.

**Suggested fix:** Add a sub-test to parity/magma/magma_parity_test.go that exercises Cipher instance reuse across sequential blocks and dst==src aliasing on both sides:

func TestMagmaCipherReuse(t *testing.T) {
    key := mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    blocks := [][]byte{
        mustHex("fedcba9876543210"),
        mustHex("0102030405060708"),
        mustHex("aabbccddeeff0011"),
    }

    ourC := NewCipher(key)
    theirC := gost341264ref.NewCipher(key) // import "go.stargrave.org/gogost/v7/gost341264"

    for i, pt := range blocks {
        ourDst := make([]byte, BlockSize)
        ourC.Encrypt(ourDst, pt)

        theirDst := make([]byte, BlockSize)
        theirC.Encrypt(theirDst, pt)

        if !bytes.Equal(ourDst, theirDst) {
            t.Fatalf("block %d encrypt mismatch: ours=%x ref=%x", i, ourDst, theirDst)
        }
    }
}

func TestMagmaEncryptInPlace(t *testing.T) {
    key := mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    pt := mustHex("fedcba9876543210")

    // Clean-room in-place
    ourBuf := make([]byte, BlockSize)
    copy(ourBuf, pt)
    NewCipher(key).Encrypt(ourBuf, ourBuf)

    // Fresh-dst reference
    expected := MagmaEncrypt(key, pt)
    if !bytes.Equal(ourBuf, expected) {
        t.Fatalf("in-place mismatch: got=%x want=%x", ourBuf, expected)
    }
}

This requires importing gost341264 directly; add "go.stargrave.org/gogost/v7/gost341264" to the test file imports.

### [MAG-02] Invalid-length rejection behaviour untested (informational: shapes intentionally differ)

- **Location:** `parity/magma/magma_parity_test.go:64-66`
- **Category:** test-gap · **Severity:** informational · **Verifier:** sonnet

**Finding:** Neither the table test nor the fuzz target ever feeds a wrong-sized key or block to either side: fixLen() normalizes every fuzz input to exactly KeySize/BlockSize before use. The clean-room rejects via panic (magma.go:82-84, 147-152) while the facade oracle returns an error for bad block length (primitives_gost.go:115-117) and gogost panics on bad key (gost341264/cipher.go:34-36) — so byte-for-byte parity does not apply to these paths and this is not a parity bug, just an uncovered behavioural corner. The clean-room panic paths are covered by gostcrypto's own guard_test.go, which is the appropriate home.

**Evidence:** fixLen at magma_parity_test.go:107-111 always returns a slice of exactly n bytes (zero-padded/truncated), so MagmaEncrypt/MagmaDecrypt are never invoked with len(key)!=32 or len(block)!=8 anywhere in the parity package.

**Verifier confirmation:** All factual claims in the finding are accurate:

1. fixLen() at magma_parity_test.go:107-111 always produces a slice of exactly n bytes via zero-pad/truncate, so MagmaEncrypt/MagmaDecrypt are never called with len(key)!=32 or len(block)!=8 anywhere in the parity package.

2. The clean-room panics on bad key (magma.go:81-84: `if len(key) != KeySize { panic(...) }`) and on short src/dst blocks (magma.go:147-152).

3. The facade oracle (primitives_gost.go:114-117) returns an error for bad block length, not a panic.

4. gogost's gost341264.NewCipher (cipher.go:34-36) panics on bad key, matching the clean-room.

5. gostcrypto/magma/guard_test.go exists and covers both panic paths completely: TestNewCipherPanicsOnBadKey exercises 0-, 31-, and 33-byte keys; TestEncryptDecryptPanicsOnShortBuffer exercises short src/dst for both Encrypt and Decrypt.

However, the severity must be adjusted to "none" rather than "low". The finding itself acknowledges the correct design: parity tests compare byte-for-byte outputs of two implementations on valid inputs, and these error/panic paths are intentionally not subject to parity comparison because the two sides have different interfaces (clean-room: panic; facade oracle: error return). Testing invalid-length rejection in a parity package would not constitute a parity test at all — it would either compare incompatible exception models or duplicate the guard tests that already live in the appropriate home (gostcrypto/magma/guard_test.go). The omission is by design, not a gap.

---

## mgm

**Reviewer summary:** The parity test is genuinely differential and non-vacuous: both layers differ on each side (clean-room MGM over clean-room kuznyechik/magma vs gogost MGM over gogost gost3412128/gost341264), Seal outputs are compared byte-for-byte over 500 randomized iterations per cipher with varied key/nonce/aad/plaintext lengths (0..69, covering empty-AD, empty-PT, block-aligned and partial blocks), and all errors are fatal rather than swallowed. No documented MGM divergence exists in gostcrypto/TODO.md or docs/engine-vectors.md, and the empty pt+aad case (a panic on both sides) is correctly avoided. The main defects are in coverage, not correctness: the fuzz target's cipher-selection predicate (sel&1) maps BOTH committed seeds (sel=16 and sel=8, clearly intended as block sizes) to Magma, so the Kuznyechik arm of the fuzz body is dead under seed-replay-only `go test` and seed #0's RFC Kuznyechik vector runs mangled (nonce truncated 16→8); the tag size is hardcoded to the full block everywhere, so truncated tags (4..blockSize-1) — a supported NewMGM parameter that changes Open's ct/tag split — are never differentially exercised; and Open is only self-round-tripped on the clean-room side, never run against the gogost oracle or fed a forgery.

### [MGM-01] Tag size hardcoded to full block — truncated tags (4..blockSize-1) never differentially tested

- **Location:** `parity/mgm/mgm_parity_test.go:38,45,74,81,129,133`
- **Category:** test-gap · **Severity:** medium · **Verifier:** sonnet

**Finding:** Both the table test and the fuzz target always construct MGM with tagSize == blockSize (16 for Kuznyechik, 8 for Magma). The clean-room NewMGM accepts any tagSize in [4, blockSize] (mgm.go:98), and the tag size changes real behaviour: Seal's output layout (ciphertext||truncated-tag), Open's ct/tag split at len(ciphertext)-m.tagSize (mgm.go:174-175), and the MSB_S truncation copy(tag, m.ek[:m.tagSize]) (mgm.go:431). None of that surface is ever compared against gogost, so a truncation off-by-one (e.g. copying the LSB instead of MSB bytes) would pass this parity suite. Fuzzing the tag size (e.g. 4 + sel%（bs-3)) would close this cheaply.

**Evidence:** variant defs: `tagSize: 16` / `tagSize: 8` equal to blockSize; every NewMGM call passes v.tagSize: `ref, err := gogostmgm.NewMGM(v.newRef(key), v.tagSize)` and `mine, err := NewMGM(v.newMine(key), v.tagSize)` in both TestMGM_Differential and FuzzMGM_Differential — tagSize is never varied.

**Verifier confirmation:** The finding is factually correct. Reading the evidence directly:

1. `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/mgm/mgm_parity_test.go` lines 34-49: both `variant` structs hardcode `tagSize == blockSize` (16 / 8). The fuzz target at lines 117-150 picks a variant with `sel&1` but always passes `v.tagSize` — which is always equal to `v.blockSize` — to both `gogostmgm.NewMGM` and `NewMGM`.

2. `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto/mgm/mgm.go` line 98 accepts `4 <= tagSize <= bs`. Line 431 `copy(tag, m.ek[:m.tagSize])` is the MSB_S truncation. Lines 154-156 show `Seal` sizes the output as `len(plaintext)+m.tagSize`. Lines 174-175 split `Open` input as `ciphertext[:len(ciphertext)-m.tagSize]` / `ciphertext[len(ciphertext)-m.tagSize:]`.

3. `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/third_party/gogost/mgm/mode.go` lines 52-54 also accept `4 <= tagSize <= blockSize`. Its MSB_S truncation is at line 168: `copy(out, mgm.bufP[:mgm.TagSize])`. Same semantics as the clean-room.

4. `gostcrypto/TODO.md` and `docs/engine-vectors.md` contain no mention of MGM truncated-tag divergences or intentional skipping of this surface. This is not a documented intentional omission.

The clean-room and gogost implementations happen to agree on MSB truncation semantics, so no current bug is present at the code level — but the parity gate never exercises any tagSize in [4, blockSize-1]. A future regression (e.g. accidentally copying LSB bytes, or an off-by-one in the ct/tag split in Open) would pass this suite undetected. The coverage gap is real and closing it is cheap.

**Suggested fix:** In `FuzzMGM_Differential`, derive a per-variant tagSize from `sel` instead of always using `v.tagSize`. Since `minTagSize=4` and blockSizes are 8 and 16:

```go
// Pick a tagSize in [4, v.blockSize]: 4 + (sel>>1) % (v.blockSize - 3)
tagSize := 4 + int((sel>>1))%(v.blockSize-3)
ref, err := gogostmgm.NewMGM(v.newRef(key), tagSize)
...
mine, err := NewMGM(v.newMine(key), tagSize)
```

Also add a table-driven row (or a loop) in `TestMGM_Differential` that iterates tagSize from 4 to v.blockSize for at least one fixed key/nonce/aad/pt vector per block size — this verifies both `Seal` output layout and `Open`'s ct/tag split at every permitted tag length, including the MSB_S truncation path.

### [MGM-02] Both fuzz seeds select Magma — Kuznyechik fuzz arm dead under seed replay, RFC Kuznyechik seed mangled

- **Location:** `parity/mgm/mgm_parity_test.go:106-121`
- **Category:** fuzz-gap · **Severity:** medium · **Verifier:** sonnet

**Finding:** The cipher selector is `sel&1`: odd keeps variants[0] (Kuznyechik), even switches to variants[1] (Magma). The two committed seeds pass sel=byte(16) and sel=byte(8) — obviously intended as block sizes — and both are even, so BOTH seeds run the Magma path. Under plain `go test` (which replays only seeds) the Kuznyechik branch of FuzzMGM_Differential never executes. Worse, seed #0 is the RFC 9058 Kuznyechik vector (32-byte key 8899aabb..., 16-byte nonce) but is executed as Magma with the nonce silently truncated to 8 bytes by fixLen, so the intended known-answer seed is mangled. The deterministic TestMGM_Differential still covers Kuznyechik, but the fuzz corpus does not encode the intended per-cipher seeds and CI seed replay never touches the Kuznyechik fuzz path.

**Evidence:** f.Add(byte(16), mustHex("8899aabb..."), mustHex("1122334455667700ffeeddccbbaa9988"), ...) and f.Add(byte(8), ...) followed by: `v := variants[0] // Kuznyechik; if sel&1 == 0 { v = variants[1] // Magma }` — 16&1==0 and 8&1==0, so both seeds take the Magma branch; nonce := fixLen(rndNonce, v.blockSize) truncates the 16-byte Kuznyechik nonce to 8 bytes.

**Verifier confirmation:** The finding is confirmed by direct inspection of /Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/mgm/mgm_parity_test.go.

The selector logic at lines 118-121:
  v := variants[0] // Kuznyechik
  if sel&1 == 0 {
      v = variants[1] // Magma
  }

Seed #0 passes byte(16) as sel: 16 & 1 == 0 → condition is true → Magma is selected (NOT Kuznyechik).
Seed #1 passes byte(8) as sel: 8 & 1 == 0 → condition is true → Magma is selected (correct for this seed).

Both inline seeds drive the Magma branch. Under plain "go test" — which only replays f.Add seeds — the Kuznyechik arm of FuzzMGM_Differential is never reached.

Seed #0 was clearly intended as the RFC 9058 Kuznyechik worked example: key=8899aabb... (matches gostcrypto/mgm/mgm_test.go katCases[0].key verbatim), nonce=1122334455667700ffeeddccbbaa9988 (16 bytes, Kuznyechik nonce length). But because sel=16 is even, fixLen at line 123 truncates that 16-byte nonce to 8 bytes (v.blockSize for Magma), discarding the second half, and the seed runs as Magma with a different key-nonce pair from what was intended — it is neither a KAT for Kuznyechik nor a KAT for the correct Magma vector.

No entry in docs/engine-vectors.md or gostcrypto/TODO.md documents this as an intentional divergence or known limitation. The deterministic TestMGM_Differential (lines 51-103) correctly exercises both variants by ranging over all entries in the variants slice, so correctness of the implementation is maintained — the deficit is entirely in the fuzz corpus, which fails to provide any seed that exercises the Kuznyechik differential path.

**Suggested fix:** Change the first f.Add call to use an odd sel value so it takes the Kuznyechik branch. The minimal fix is to replace byte(16) with byte(1):

  f.Add(byte(1),       // odd → Kuznyechik
      mustHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
      mustHex("1122334455667700ffeeddccbbaa9988"),
      mustHex("0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505"),
      mustHex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0aaabbcc"))
  f.Add(byte(0),       // even → Magma (was byte(8), same parity but clearer intent)
      mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
      mustHex("12def06b3c130a59"),
      mustHex("0101010101010101020202020202020203030303030303030404040404040404"),
      mustHex("ffeeddccbbaa998811223344556677008899aabbcceeff0aaabbcc"))

With sel=1 (odd), 1&1==1 != 0, so the Kuznyechik path is taken. The 16-byte nonce is passed to fixLen(rndNonce, 16) intact. With sel=0 (even), 0&1==0, so Magma is taken and the 8-byte Magma nonce is used correctly.

An alternative fix is to invert the selector predicate from "sel&1 == 0 → Magma" to "sel&1 != 0 → Magma", keeping byte(16) and byte(8) as seeds — but that would then make byte(8) (which was the Magma seed) take the Kuznyechik branch, breaking that seed's intent. The cleanest approach is the one above: use byte(1) for the Kuznyechik seed and byte(0) for the Magma seed, making the even/odd alignment explicit.

### [MGM-03] Open never run against the gogost oracle and no forgery-rejection case in parity

- **Location:** `parity/mgm/mgm_parity_test.go:92-99,143-149`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Open is exercised only as a clean-room self round-trip (mine.Open of mine.Seal). gogost's Open is never invoked, and no tampered ciphertext/tag, short-ciphertext (< tagSize), or cross-decryption (clean-room Open over gogost Seal output, with non-identical buffers) case appears in the parity package. Because clean-room Open recomputes the tag with the same auth() used by Seal, the self round-trip cannot detect a shared Seal/Open bug by itself — it is the Seal byte-parity that carries the proof, and that only holds for the full-block tag actually tested (see the tagSize finding). Mitigation: gostcrypto's own mgm_test.go covers tamper rejection and Open error paths, so this is a low-severity parity-coverage gap rather than an untested behaviour overall.

**Evidence:** Only Open call sites in the package: `back, err := mine.Open(nil, nonce, gotMine, aad)` (test and fuzz). No `ref.Open` call and no negative/tamper assertion exists anywhere in parity/mgm/.

**Verifier confirmation:** The finding's factual claims are accurate. In `parity/mgm/mgm_parity_test.go`:

1. `ref.Open` is never called anywhere in the package (confirmed by grep — zero results).
2. The only Open call is `mine.Open(nil, nonce, gotMine, aad)` at lines 93 and 143, where `gotMine` was produced by `mine.Seal`. This is a pure self-round-trip.
3. There is no forgery/tamper assertion (no byte flip followed by an expected-error check) anywhere in the parity package.

However, the practical severity is genuinely low — not higher — for the following reason: the existing test already asserts `bytes.Equal(gotRef, gotMine)` (lines 87–90, 140–141) before calling `mine.Open(gotMine)`. Because `gotRef == gotMine` by that point, `mine.Open(ref.Seal(...))` would trivially succeed if written, and `ref.Open(mine.Seal(...))` is equally implicit. The cross-decryption gap is logically collapsed by the prior byte-equality check: if Seal bytes are identical, both cross-directions of Open are guaranteed to agree. Similarly, the finding's own mitigation note is correct: `gostcrypto/mgm/mgm_test.go` has explicit tamper rejection at lines 96–111, 286–292, 403–409, and 542–548 covering both ciphertext and tag flips, so the forgery-rejection property is proven at the unit level. The parity package's gap is real but redundant given these two compensating factors.

**Suggested fix:** Add two assertions to the existing differential loop in `TestMGM_Differential` (and mirror them in `FuzzMGM_Differential`):

1. Cross-decryption: after confirming `bytes.Equal(gotRef, gotMine)`, call `mine.Open(nil, nonce, gotRef, aad)` and assert it succeeds and returns `plain`. This makes the interoperability in both directions explicit rather than implicit.

2. Forgery rejection: pick a random byte position in `gotMine`, XOR it with `0x01`, and assert `mine.Open` returns a non-nil error. Example addition after line 99:

```go
// Cross-decryption: mine must also accept gogost's sealed output.
back2, err2 := mine.Open(nil, nonce, gotRef, aad)
if err2 != nil {
    t.Fatalf("iter %d mine Open rejected ref Seal: %v", iter, err2)
}
if !bytes.Equal(back2, plain) {
    t.Fatalf("iter %d cross-decrypt mismatch: got %x want %x", iter, back2, plain)
}

// Forgery rejection: a single bit flip must cause Open to fail.
badMine := append([]byte{}, gotMine...)
badMine[rng.Intn(len(badMine))] ^= 0x01
if _, err3 := mine.Open(nil, nonce, badMine, aad); err3 == nil {
    t.Fatalf("iter %d mine Open accepted tampered ciphertext", iter)
}
```

These additions are cosmetically redundant with the existing coverage but make the parity test self-contained and more clearly document the expected contract.

### Dismissed for mgm (do NOT act on these)

#### DISMISSED: AEAD instance reuse across multiple Seal calls and dst-append paths not parity-tested

- **Location:** `parity/mgm/mgm_parity_test.go:74-85,129-139` · **Category:** test-gap · **Severity claimed:** low · **Verifier:** sonnet

**Original claim:** Every iteration constructs fresh ref/mine MGM values and always passes dst=nil. The clean-room MGM deliberately reuses internal scratch across calls 'mirroring gogost' (mgm.go:65-85: icn/yi/zi/ek/sum/pad/mul/lenB), and gogost mutates mgm.icn in-place (mode.go:116 `mgm.icn[0] |= 0x80`); stale-scratch bugs only surface when the SAME instance Seals twice with different nonces/lengths, which the parity suite never does (the single Seal+Open per instance only partially exercises it). Likewise sliceForAppend's cap-reuse branch (mgm.go:447-448) and dst-prefix preservation are never hit. gostcrypto's own TestMGM_SealAppends covers the append path non-differentially, so severity is low, but a sequential-Seal parity loop on one shared instance per side would be a one-line strengthening.

**Why dismissed:** The finding's core premise — that reusing one MGM instance across multiple Seal calls could expose stale-scratch divergence between the clean-room and gogost — is incorrect. Both implementations unconditionally reinitialize all mutable state at the start of every Seal call:

**gogost (`third_party/gogost/mgm/mode.go`)**:
- `Seal()` line 199: `copy(mgm.icn, nonce)` — overwrites icn before any internal call.
- `auth()` line 116 does mutate `mgm.icn[0] |= 0x80` in-place, and `crypt()` line 172 does `mgm.icn[0] &= 0x7F`, but both happen *after* `icn` was refreshed. On the next `Seal()`, `copy(mgm.icn, nonce)` at line 199 erases whatever icn contained, so the previous call's mutation is irrelevant.
- `auth()` line 113: `clear(mgm.sum)` — sum accumulator is zeroed.
- The crypt pass seeds `bufP` from `icn` each time; auth seeds `bufP` from `icn` each time.

**Clean-room (`gostcrypto/mgm/mgm.go`)**:
- `Seal()` line 152: `copy(m.icn, nonce)` — identical pattern.
- The clean-room never mutates `m.icn` during computation: `crypt()` lines 333–335 do `copy(m.ek, m.icn)` then `m.ek[0] &= 0x7f`, leaving `m.icn` intact. `auth()` lines 359–361 do `copy(m.ek, m.icn)` then `m.ek[0] |= 0x80`. The `yi`, `zi`, `sum`, `pad` scratch buffers are all re-seeded from `icn`/zeroed at the start of each crypt/auth call.

So both sides are fully stateless across calls: any instance could be called any number of times with different nonces and data and the outputs would be identical to creating a fresh instance each time. There is no stale-scratch path that could cause divergence.

**dst-append gap**: the finding also claims `sliceForAppend`'s cap-reuse branch (mgm.go:447–448) is never exercised in the parity test (dst always nil). This is factually true, but it is not a parity gap — the clean-room module's own `TestMGM_SealAppends` (mgm_test.go:117) already covers prefix preservation and the append path for correctness. The parity suite's job is to compare clean-room vs. gogost output byte-for-byte; since both use the same sliceForAppend pattern and the correctness property is already checked, the missing differential coverage here carries no realistic risk of an undetected divergence.

The finding contains no documented intentional divergence in TODO.md or docs/engine-vectors.md — it simply misreads the state-management pattern of both implementations.

---

## omac

**Reviewer summary:** Mechanically the parity test is sound: 2048-iteration randomized differential plus a fuzz target, byte-exact comparison, correct key/msg wiring, message lengths spanning empty/partial/block-aligned cases for both Kuznyechik (16-byte block) and Magma (8-byte block), and pinned GOST R 34.13-2015 A.1.6/A.2.6 KATs that match the published standard. Its structural weakness is the oracle: gogost/v7 ships no CMAC (third_party/gogost/gost3413 contains only padding.go), so the "gogost reference" is gostcryptocompat's own from-scratch OMAC whose mode logic is a near line-for-line twin of the clean-room implementation — the random differential therefore only independently validates the block-cipher layer (already covered by parity/kuznyechik and parity/magma), and a shared CMAC-mode bug would pass. The fixed standard/engine KATs partially compensate, but the Magma K2 (partial-final-block) path and the empty-message path have no independent anchor anywhere. Secondary gaps: tag truncation is exercised only at two fixed widths and never fuzzed, and Sum-reuse/Write-after-Sum semantics are never compared differentially.

### [OMAC-01] Oracle is a sibling reimplementation, not gogost: CMAC mode logic is effectively self-compared

- **Location:** `parity/omac/omac_parity_test.go:35 (oracle = gostcryptocompat.NewOMAC, defined in omac.go:35)`
- **Category:** correctness · **Severity:** minor · **Verifier:** opus

**Finding:** gogost/v7 has no CMAC/OMAC implementation (third_party/gogost/gost3413/ contains only padding.go), so the facade OMAC the parity test diffs against is a from-scratch CMAC written in this same repo. Its mode logic — subkey derivation, the big-endian shiftLeftXorRb, the keep-last-full-block Write buffering rule, and the K1/K2 Sum finalization — is structurally near-identical to the clean-room gostcrypto/omac. Only the underlying block cipher (gost3412128/gost341264) is genuinely gogost, and cipher parity is already proven by parity/kuznyechik and parity/magma. A shared CMAC-mode bug (e.g. identical subkey or padding mistake in both twins) would pass every random differential iteration and every fuzz input. The pinned standard KATs partially anchor correctness, but coverage of independent anchors is uneven: all Magma anchors (A.2.6 KAT, engine tcl full-width vector in the clean-room module) are block-aligned K1-path messages — the Magma K2 (partial-final-block, 0x80-padding) path and the empty-message path for both ciphers are verified ONLY by the twin-vs-twin diff. The Kuznyechik K2 path at least has the independent gost-engine 'hello' vector (omac_engine_test.go:17 on the oracle side, gostcrypto/omac/omac_test.go:29 on the clean-room side).

**Evidence:** third_party/gogost/gost3413/ ships only padding.go (no MAC). Facade omac.go:81-92 shiftLeftXorRb is logic-identical to clean-room ../gostcrypto/omac/omac.go:127-142; facade Write (omac.go:101-124) mirrors clean-room Write (omac.go:151-173) including the 'flush full block only if more data follows' invariant. Independent Magma vectors are A.2.6 (32 bytes = 4 blocks, K1 path) and mac.try full-width (same 32-byte block-aligned message); no independent Magma partial-block or empty-input vector exists in parity/omac, the facade tests, or gostcrypto/omac tests (TestOMAC_EmptyMessage at omac_test.go:198 only checks Sum self-consistency, no pinned value).

**Verifier confirmation:** The finding's structural claims are all verified against source.

1. gogost ships NO CMAC/OMAC mode. third_party/gogost/gost3413/ contains only padding.go (Pad1/Pad2/Pad3 + PadSize). A recursive grep for cmac/omac across the entire vendored gogost tree returns zero MAC-mode hits (gost28147/mac.go is the unrelated GOST 28147-89 imitovstavka). So the parity oracle gostcryptocompat.NewOMAC (omac.go:35) is a from-scratch CMAC written in THIS repo.

2. The facade and clean-room CMAC mode logic are near-identical twins:
   - shiftLeftXorRb: facade omac.go:81-92 vs clean-room ../gostcrypto/omac/omac.go:127-142 are logic-identical (same big-endian carry, same MSB-conditional Rb XOR into last byte).
   - Write buffering: both keep the last full block buffered, flushing only "if len(o.buf)==blockSize && len(p)>0" (facade omac.go:117, clean-room omac.go:165).
   - Sum finalization: both use the K1 path for a complete final block, else 0x80-pad + K2 (facade omac.go:145-155, clean-room omac.go:186-201).
   - cmacSubkeys K1/K2 derivation identical (facade omac.go:57-77, clean-room omac.go:108-117).
   Only the underlying block cipher (gost3412128 / gost341264) is genuinely gogost, and that is already proven by parity/kuznyechik and parity/magma. So TestDiffAgainstGost and FuzzDiffAgainstGost compare CMAC-mode logic against itself: a shared mode bug (identical subkey/padding/shift mistake) would pass every differential iteration and fuzz input.

3. Independent-anchor coverage is exactly as the finding states. I confirmed there are precisely two Magma OMAC pinned vectors (gostcrypto/omac/omac_test.go:77 and :109), both over the 32-byte A.2.6 message — block-aligned, K1 path. No Magma partial-block (K2) or empty-input pinned vector exists in parity/omac, the facade tests, or the clean-room tests. TestOMAC_EmptyMessage (clean-room omac_test.go:198) only asserts Sum self-consistency, no pinned value.

This is NOT a documented intentional divergence: TODO.md has no OMAC entry; engine-vectors.md:29 only says the engine tcl magma-mac/kuznyechik-mac rows were "out of scope" for that porting pass (the tcl full-width rows were in fact ported, omac_test.go:95). So the finding survives the "merely restates documented divergence" refutation test.

WHY I DOWNGRADE FROM high TO low: the practical exposure is small because the CMAC mode code is block-size-agnostic — the same shiftLeftXorRb/Write/K1-K2 code runs for both ciphers, parameterized only by (blockSize, rb).
   - The K2/0x80-padding + K2-subkey finalization path IS independently anchored: the gost-engine "hello" vector (5 bytes < 16, so K2 path) is pinned on BOTH the facade side (omac_engine_test.go:29) and the clean-room side (gostcrypto/omac/omac_test.go:29) to the engine-produced value 96e6c1913fd788e3922e617fdd341edf. A K2-path mode bug (wrong pad position, wrong subkey selection, K2 derivation error) would be caught there.
   - The Magma-specific elements (rb64=0x1b and the 8-byte big-endian shift through shiftLeftXorRb) ARE exercised by the A.2.6 K1-path vectors, since K1 = shiftLeftXorRb(L, rb64) and K2 = shiftLeftXorRb(K1, rb64) are both computed at construction regardless of message path. So an 8-byte-shift or rb64 bug would surface on the K1 Magma KATs.
   The genuinely-unanchored sliver is narrow: a bug that manifests ONLY for an 8-byte block AND ONLY on the K2 finalization path AND is replicated identically in both twins — e.g. a Magma-specific empty-message edge or an 8-byte 0x80-pad index miscalculation that the 16-byte "hello" path happens not to trigger. Real but a thin residual, hence low rather than none.

**Suggested fix:** Add one independent (engine/standard-derived) Magma OMAC partial-block vector and one empty-message vector for both ciphers, pinned on both the clean-room and facade sides, so the Magma K2 path and empty-input path stop being twin-vs-twin only. Concretely: generate a magma-mac tag over a non-block-aligned message (e.g. the A.2.6 plaintext truncated to 20 bytes) and an empty message via gost-engine `openssl dgst -engine gost -mac magma-mac -macopt hexkey:...`, and likewise an empty-message kuznyechik-mac tag, then pin those values in gostcrypto/omac/omac_test.go and gostcryptocompat's omac_engine_test.go (mirroring the existing "hello" engine anchor at omac_engine_test.go:17). Cite the openssl invocation in the test comment as is done for the kuznyechik "hello" vector. This closes the remaining unanchored K2/empty corners without needing a gogost CMAC (which does not exist).

### [OMAC-02] Tag truncation parity only at two fixed widths; tagSize-out-of-range semantics never pinned

- **Location:** `parity/omac/omac_parity_test.go:31,50,140-159`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The clean-room New accepts any tagSize in [1, blockSize], but the parity tests exercise only the full widths (16 for Kuznyechik, 8 for Magma) plus exactly two KAT truncations (8 and 4). No randomized truncation sweep diffs the two implementations across the rest of [1, blockSize]. Truncation is a leading-bytes slice in both implementations so risk is low, but it is exported behaviour with zero differential coverage outside four points. Additionally, the out-of-range behaviour intentionally diverges (clean-room omac.go:69-71 panics; oracle omac.go:37-39 returns an error) and this divergence is neither tested nor documented as intentional anywhere.

**Evidence:** omac_parity_test.go:31 'mynew.New(kuznyechik.NewCipher(key), 16)' and :50 '..., 8' are the only tag sizes in the differential loop; TestDiffTruncatedKATs covers only tagSize 8 (kuz) and 4 (magma). Clean-room New: 'panic("omac: tagSize out of range [1, blockSize]")' vs oracle NewOMAC: 'return nil, fmt.Errorf(...)'.

**Verifier confirmation:** Both sub-claims in the finding are real, but the claimed severity is at the right level (low).

**Truncation sweep gap — confirmed, low risk.**
`TestDiffAgainstGost` (lines 31, 50) and `FuzzDiffAgainstGost` (lines 95–100) hard-code only the two full-width tag sizes: 16 for Kuznyechik, 8 for Magma. `TestDiffTruncatedKATs` (lines 140–159) adds exactly two more points: tagSize=8 (kuz) and tagSize=4 (magma). No test or fuzz target exercises tagSize ∈ {1..7} for Kuznyechik or tagSize ∈ {1..3, 5..7} for Magma against the oracle. However, the risk is genuinely low: truncation in both implementations is a single leading-byte slice — `t[:o.tagSize]` (clean-room omac.go:212) and `stateSnap[:o.tagSize]` (compat omac.go:159). A bug in that slice would have to be something like an off-by-one in tagSize arithmetic that disagreed between the two, but both store tagSize as provided and slice it identically. The underlying CMAC computation is identical code paths in both; tagSize only gates the final append. A fuzz sweep would be comprehensive insurance, not bug-finding at any realistic probability.

**Out-of-range divergence — confirmed, undocumented.**
Clean-room `omac.New` (gostcrypto/omac/omac.go:69–71): `panic("omac: tagSize out of range [1, blockSize]")`. Compat `NewOMAC` (gostcrypto-compat/omac.go:37–39): `return nil, fmt.Errorf(...)`. This behavioral difference is real and is not documented anywhere — not in `gostcrypto/TODO.md`, not in `docs/engine-vectors.md`, not in the parity test file itself. It is a deliberate API contract difference (the clean-room API returns `*OMAC` with no error, so panic is the only error channel; the compat facade returns `(*OMAC, error)`) rather than a correctness bug. But it is unexplained exported behavior that no test pins, which is what the finding claims.

**No documentation of intentional divergence exists** — neither `gostcrypto/TODO.md` nor `docs/engine-vectors.md` mentions the panic-vs-error difference, which rules out refutation on "documented intent" grounds.

The overall severity stays low: there is no correctness risk from the truncation gap given the trivial slice mechanism, and the panic/error divergence is an API contract choice rather than a bug.

**Suggested fix:** Two independent improvements:

1. **Truncation sweep in the fuzz target.** Extend `FuzzDiffAgainstGost` to include a fuzz-selected `tagSize` parameter. Add a seed that sets it to an intermediate width, and clamp it to `[1, blockSize]` before constructing both sides:

```go
// In FuzzDiffAgainstGost signature, add: tagSizeHint byte
f.Add(byte(0), ..., uint(13), byte(7))   // tagSizeHint=7 (kuz, truncated)
f.Add(byte(1), ..., uint(7),  byte(3))   // tagSizeHint=3 (magma, truncated)

f.Fuzz(func(t *testing.T, sel byte, rndKey, msg []byte, split uint, tagSizeHint byte) {
    key := fixLen(rndKey, 32)
    var blockSize int
    if sel&1 == 0 { blockSize = 16 } else { blockSize = 8 }
    tagSize := int(tagSizeHint%byte(blockSize)) + 1  // [1, blockSize]
    ...
    mine = mynew.New(cipher, tagSize)
    ref, err = gost.NewOMAC(compatCipher, tagSize)
    ...
})
```

2. **Document the panic/error divergence.** Add a comment in `parity/omac/omac_parity_test.go` (near the top of the file, before `TestDiffAgainstGost`) and a line in `docs/engine-vectors.md` or `gostcrypto/TODO.md` explaining that `omac.New` panics on out-of-range tagSize (programmer-error contract, no error return) while `gost.NewOMAC` returns an error, and that this divergence is intentional by API design. No test needed for the panic path specifically, but a `TestNew_OutOfRange_Panics` unit test in `gostcrypto/omac/omac_test.go` using `defer+recover` would pin the behavior.

### [OMAC-03] Sum non-destructiveness and Write-after-Sum continuation never compared differentially

- **Location:** `parity/omac/omac_parity_test.go:33,52,114`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The clean-room OMAC documents Sum as non-destructive and explicitly supports Write-after-Sum continuation (../gostcrypto/omac/omac.go:42-45, 175-179). The parity package calls Sum exactly once per instance and never Writes after Sum, so the snapshot/restore semantics are only covered by each module's own unit tests (TestOMAC_SumIdempotent / TestOMAC_SumAfterWrite), never by the clean-room-vs-oracle diff. This matters in this codebase because a gogost MAC (gost28147.MAC.Sum) is known-destructive on pending partial blocks — Sum-reuse is exactly the class of bug this family of primitives has shipped before.

**Evidence:** omac_parity_test.go uses the pattern 'mine.Write(msg); got := mine.Sum(nil)' in all three test functions; no instance is Sum-ed twice or Written to after Sum. CLAUDE.md gogost gotcha: 'gost28147.MAC.Sum: destructive on a pending partial block'.

**Verifier confirmation:** The finding is structurally correct but the claimed severity (low) is appropriate and the threat model needs a minor correction.

**What the parity test does:** All three functions in `parity/omac/omac_parity_test.go` — `TestDiffAgainstGost`, `FuzzDiffAgainstGost`, and `TestDiffTruncatedKATs` — call `Sum(nil)` exactly once per instance, after all `Write` calls complete. No instance is `Sum`-ed twice, and no `Write` follows a `Sum`. This is confirmed at lines 33, 52, 114, 169, 179 of the parity test file.

**What the oracle actually is:** The finding implies the oracle is gogost's `gost28147.MAC`, citing the CLAUDE.md gotcha. This is incorrect — `gost.NewOMAC` (imported as `gost "github.com/bigbes/gostcrypto-compat"`) wraps `gostcrypto-compat/omac.go`, which is a clean re-implementation using `crypto/cipher.Block` only (imports: `crypto/cipher`, `crypto/subtle`, `fmt`; no gogost). The `gostcryptocompat.OMAC.Sum` is explicitly non-destructive: it snapshots both `state` (line 139-141) and `buf` (lines 141-143 of `omac.go`) before computing the final block, leaving the receiver unchanged. The CLAUDE.md gotcha about `gost28147.MAC.Sum` being "destructive on a pending partial block" applies to gogost's GOST 28147 CBC-MAC, not to this OMAC facade.

**Why the finding is still confirmed:** Despite the oracle being non-destructive, the parity test gap is real. If the clean-room `gostcrypto/omac.OMAC.Sum` were accidentally destructive (e.g., a regression that corrupted `o.buf` or `o.state` in-place), the one-shot parity tests would not detect it — they would still pass because both sides compute the correct single-shot MAC. The differential test would only catch the bug if it also checked that a subsequent `Write` + `Sum` on the same instance gives the same result as a fresh instance over the concatenated input.

**Mitigating factors that keep severity low:** (1) `TestOMAC_SumIdempotent` and `TestOMAC_SumAfterWrite` already exist in `gostcrypto/omac/omac_test.go` (lines 147, 166) and `gostcrypto-compat/omac_test.go` (lines 116, 152) as per-module unit tests — the property is tested, just not cross-validated differentially. (2) Both the clean-room `Sum` (`omac/omac.go` lines 180–212: allocates fresh `stateSnap`, `last`, `tmp`, `t` slices; reads from but never writes to `o.state` or `o.buf`) and the facade `Sum` (`gostcrypto-compat/omac.go` lines 137–159: copies state and buf into snapshots before any mutation) are structurally non-destructive — the receiver mutation bug would have to be introduced deliberately or through a refactor that changes slice aliasing. (3) The structural symmetry of the two implementations means a differential test catching divergence in Sum-after-Write would require both implementations to diverge in opposite directions simultaneously, which is unlikely.

**Suggested fix:** Add a differential Sum-after-Write test to `parity/omac/omac_parity_test.go`. The test should: (1) Write the first half of a message to both clean-room and oracle instances; (2) call `Sum(nil)` on both (discarding the result, testing non-destructiveness); (3) Write the second half to both; (4) call `Sum(nil)` on both and assert byte-exact agreement; (5) also assert each result matches a fresh instance over the full concatenated message. Cover both Kuznyechik (16-byte block) and Magma (8-byte block). Additionally, add a differential idempotent-Sum test that calls `Sum(nil)` twice on both instances (after one `Write`) and asserts both sides return identical bytes on the second call. This closes the gap without removing any existing tests.

### [OMAC-04] Fuzz target hardcodes tagSize to the full block width

- **Location:** `parity/omac/omac_parity_test.go:95,99`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** FuzzDiffAgainstGost always constructs both sides with tagSize=16 (Kuznyechik) or tagSize=8 (Magma). The truncation dimension — leading-bytes selection across [1, blockSize], the one parameter the GOST standard's own vectors vary (A.1.6 truncates to 8, A.2.6 to 4) — is never fuzzed. Deriving tagSize from a fuzz byte (e.g. 1 + int(b)%bs) would cost nothing and close the gap.

**Evidence:** omac_parity_test.go:95 'mine = mynew.New(kuznyechik.NewCipher(key), 16)' and :99 'mine = mynew.New(magma.NewCipher(key), 8)' — the literal 16/8 are the only tag sizes the fuzzer ever sees.

**Verifier confirmation:** The finding is factually correct: `FuzzDiffAgainstGost` in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/omac/omac_parity_test.go` hardcodes tagSize=16 at line 95 (Kuznyechik branch) and tagSize=8 at line 99 (Magma branch). The fuzzer never varies the tagSize parameter.

However, the claimed severity of "medium" is too high. The analysis of the clean-room implementation (omac.go:212, `return append(b, t[:o.tagSize]...)`) and the gogost-backed oracle (omac.go:159, `return append(b, stateSnap[:o.tagSize]...)`) shows that truncation is a structurally identical leading-prefix slice in both implementations. The entire CMAC computation is performed at full block width; tagSize only governs how many leading bytes of the final encryption result are returned. There is no divergence-prone logic that varies by tagSize — no conditional branch, no different subkey, no different padding.

Furthermore, `TestDiffTruncatedKATs` (lines 129-186 of the same file) already explicitly cross-checks both implementations at non-full tag widths: tagSize=8 for Kuznyechik (GOST R 34.13-2015 A.1.6) and tagSize=4 for Magma (A.2.6). These are exactly the standard-mandated truncation sizes. The existing static KATs prove agreement at every truncation width the standard specifies.

The docs/engine-vectors.md and ../gostcrypto/TODO.md do not mention any OMAC/tagSize divergence. This is not a documented intentional divergence — the gap is simply that the fuzz target does not vary tagSize, leaving the coverage to the two static KATs.

The confirmed gap: a latent bug where one side truncates from the wrong end (e.g. trailing bytes instead of leading bytes) or off by one in tagSize would not be caught by the fuzzer (only by TestDiffTruncatedKATs). Given the structural simplicity and existing KAT coverage, the practical risk is low, not medium.

**Suggested fix:** Add a fuzz byte that drives tagSize selection, replacing the hardcoded 16/8 literals in FuzzDiffAgainstGost. The sel byte already selects the cipher; use a second byte for tagSize:

```go
f.Fuzz(func(t *testing.T, sel byte, rndKey, msg []byte, split uint) {
    key := fixLen(rndKey, 32)

    var bs int
    var mine *mynew.OMAC
    var ref *gost.OMAC
    var err error
    if sel&1 == 0 {
        bs = 16
        ts := 1 + int(sel>>1)%bs  // tagSize in [1, 16]
        mine = mynew.New(kuznyechik.NewCipher(key), ts)
        ref, err = gost.NewOMAC(gost.NewKuznyechikCipher(key), ts)
    } else {
        bs = 8
        ts := 1 + int(sel>>1)%bs  // tagSize in [1, 8]
        mine = mynew.New(magma.NewCipher(key), ts)
        ref, err = gost.NewOMAC(gost.NewMagmaCipher(key), ts)
    }
    ...
}
```

Alternatively, accept a dedicated `tagSeed byte` parameter from the fuzzer engine and derive `ts = 1 + int(tagSeed)%bs`. Add seeds for tagSize=8 (Kuznyechik A.1.6) and tagSize=4 (Magma A.2.6) to the f.Add corpus so the seed corpus immediately exercises the standard truncation widths.

### [OMAC-05] Streaming coverage limited to a single 2-way split on the clean-room side; seed corpus lacks a partial-final-block seed

- **Location:** `parity/omac/omac_parity_test.go:75-85,106-113`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The fuzz target splits the clean-room Write into exactly two chunks at one offset; multi-chunk streams (3+ Writes, 1-byte Writes) are never generated, so repeated buffer-fill/flush cycles across many Write boundaries get less exercise than a generic chunking scheme would give. The three f.Add seeds also all land on the K1-complete or K2-empty finalization paths: seed#0 is 32 bytes (2 Kuznyechik blocks, block-aligned), seed#1 is 32 bytes (4 Magma blocks, block-aligned), seed#2 is empty. No seed starts the corpus on the K2 partial-final-block path (the 0x80-padding branch), leaving it to active fuzzing / the random table test to discover. Note: seeding an empty message is fine here — OMAC has no documented empty-input divergence (the GOST R 34.11-94 caveat does not apply; docs/engine-vectors.md:29 lists the engine mac vectors only as out-of-scope for that file).

**Evidence:** omac_parity_test.go:108-110 'off := int(split % uint(len(msg)+1)); mine.Write(msg[:off]); mine.Write(msg[off:])' — always exactly two Writes; f.Add seeds at lines 75-85 carry 32-, 32-, and 0-byte messages, all block-aligned or empty for their selected cipher.

**Verifier confirmation:** Both sub-claims are real, though one is overstated.

**Seed corpus gap (primary claim — confirmed, concrete).**
Lines 75–85 of `parity/omac/omac_parity_test.go` add exactly three seeds:
- seed#0: `sel=0` (Kuznyechik, 16-byte block), `msg=32 bytes` → `32 % 16 = 0` → K1 (complete final block) path.
- seed#1: `sel=1` (Magma, 8-byte block), `msg=32 bytes` → `32 % 8 = 0` → K1 path.
- seed#2: `sel=0`, `msg=[]` → K2 path, but with an *empty* buffer — `Sum()` at line 196 of `omac.go` branches on `len(o.buf) == 0`, so only the full-padding sub-branch (`last[0] = 0x80; last[1..n-1] = 0`) is exercised.

The K2 branch where `0 < len(buf) < blockSize` (partial data before the `0x80` pad byte, i.e. `last[0..k-1] = buf[0..k-1]; last[k] = 0x80; last[k+1..] = 0`) is absent from all three seeds. A seed of e.g. 17 bytes for Kuznyechik (`17 % 16 = 1`) would cover this sub-branch immediately. The seed corpus gap is genuine.

**Mitigation that limits severity.** `TestDiffAgainstGost` (lines 20–67) runs 2048 random iterations with `msg = rng.Intn(70)` bytes. Since most random lengths are not multiples of 16 or 8, the partial-block K2 path is hit on the vast majority of table-test iterations. The gap is therefore only in the *fuzz* seed corpus, not in overall test coverage. No correctness bug is hidden; it affects how quickly the fuzzer bootstraps onto this sub-branch.

**2-way split claim (secondary — technically true but overstated).**
Lines 106–113 do constrain the clean-room side to exactly two `Write` calls. However, `Write()` (omac.go lines 151–173) is itself a loop: it fills `buf` to `blockSize`, flushes when `len(buf)==blockSize && len(p)>0`, and repeats. So `Write(A)` followed by `Write(B)` is state-equivalent to `Write(A+B)` — the internal flush cycles for a large message are traversed either way. The fuzzer with `off=0` produces `Write([]); Write(msg)`, which exercises the full internal loop for any message length. The correctness path for "3+ Writes, 1-byte Writes" is not structurally different. This part of the finding is not wrong but is weaker than presented.

**No documented divergence applies.** `docs/engine-vectors.md` line 29 explicitly marks `kuznyechik-mac` / `magma-mac` (OMAC/CMAC) as "out of scope" for the engine-vector porting effort — it does not record any OMAC divergence between clean-room and gogost. `gostcrypto/TODO.md` lists only R 34.11-94 empty-input and IMIT key-meshing divergences. There is no documented intentional divergence that would refute this finding.

**Summary:** The seed corpus genuinely lacks a partial-final-block (K2, non-empty buf) entry; that is the concrete and accurate part of the finding. The 2-way split concern is real but mild given the internal loop. `TestDiffAgainstGost` provides compensating coverage, making the practical impact low. Severity `low` as claimed is correct.

**Suggested fix:** Add one or two partial-block seeds to `FuzzDiffAgainstGost` in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/omac/omac_parity_test.go`:

```go
// Kuznyechik: 17 bytes (16+1), partial final block → K2 path with non-empty buf.
f.Add(byte(0),
    seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
    seedHex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a11"),
    uint(9))
// Magma: 7 bytes (< 8-byte block), partial final block → K2 path.
f.Add(byte(1),
    seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
    seedHex("92def06b3c130a"),
    uint(3))
```

Optionally, to make 3-way streaming explicit, change the fuzz body to loop over a slice of offsets derived from `split`, e.g.:

```go
offs := []int{0, int(split % uint(len(msg)+1)), len(msg)}
// sort and deduplicate offs, then Write each segment
```

This is a cosmetic improvement; the seed additions are the higher-value fix.

---

## streebog

**Reviewer summary:** A genuinely strong parity package. The oracle (gostcryptocompat.Streebog256/512 -> vendored gogost internal/gost34112012) is structurally independent from the clean-room code (gogost uses byte-position precalc tables and a uint64 bit counter; clean-room uses an lpTable of [8]uint64 and a 512-bit LE counter), so the diff is not tautological. All comparisons are byte-for-byte bytes.Equal on full digests; the table test covers length 0 plus block boundaries (63/64/65/127/128/...) and 200 random lengths; the fuzz target varies both message bytes/length and a streaming split offset, and correctly seeds empty input (Streebog has no documented empty-input divergence — that note applies to GOST R 34.11-94 only, per docs/engine-vectors.md and gostcrypto TODO.md). All tests pass (go test -count=1). Gaps are modest: Reset/reuse and Sum-then-continue-writing semantics are never diffed against the oracle, the New256 streaming path is never exercised directly (only New512 is streamed), the facade's streaming oracles (NewStreebog256Hash/NewStreebog512Hash) are unused, and one doc comment overstates what the streaming test does.

### [STB-01] Reset/reuse and Sum-non-destructiveness never parity-tested

- **Location:** `parity/streebog/streebog_parity_test.go (whole file); ../gostcrypto/streebog/streebog.go:377-391, 443-447`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Every parity check constructs a fresh digest. Neither Reset()-then-rehash nor the hash.Hash contract that Sum does not alter state (Sum, keep Writing, Sum again) is diffed against the oracle. The clean-room Sum deliberately snapshots h/n/sum and copies d.buf into a local before padding (streebog.go:443-455), and gogost's Sum likewise works on copies (third_party/gogost/internal/gost34112012/hash.go:139-151) — so both sides claim non-destructive semantics, but a regression in the clean-room snapshot (e.g. padding into d.buf directly, or Reset missing a field) would pass the entire parity suite.

**Evidence:** All call sites use streebog.Sum256/Sum512 or a freshly New512()'d digest with exactly one Sum; grep shows no Reset() call and no second Sum/Write-after-Sum anywhere in parity/streebog/streebog_parity_test.go.

**Verifier confirmation:** The finding is accurate on the facts:

1. `parity/streebog/streebog_parity_test.go` (all 107 lines) contains exactly three tests — `TestDiffAgainstGost`, `FuzzDiffAgainstGost`, `TestDiffStreamingAgainstGost`. None call `Reset()` on any hash object. None exercise "Sum, keep Writing, Sum again" against the gogost oracle. The grep for `Reset` across the entire `parity/streebog/` directory returns nothing.

2. The clean-room `Sum` (streebog.go:443-481) correctly snapshots `h`, `n`, `sum` as value copies and copies `d.buf` into a local `m` before padding — it is non-destructive as implemented. gogost's `Sum` (third_party/gogost/.../hash.go:139-151) likewise works on stack-local copies `buf`, `hsh`, `tmp`. So both sides *claim* and *implement* non-destructive semantics today.

3. However, a differential parity test for Reset-then-rehash or Sum-then-Write-then-Sum-again is indeed absent from `parity/streebog/`. A regression that, e.g., missed zeroing `d.nbuf` in `Reset()`, or that started writing the padding byte into `d.buf[d.nbuf]` in-place in `Sum`, would pass the entire parity suite.

4. The gap is partially mitigated: `gostcrypto/streebog/streebog_test.go:175-200` (`TestSumNonDestructive`) tests exactly the Sum-then-Write-then-Sum contract — calls `h.Sum(nil)` twice (checking idempotence), then writes more data, calls `Sum` again, and diffs against a fresh digest of the concatenated input. This is a unit test, not a parity test, so it verifies the clean-room's self-consistency but does NOT diff against gogost.

5. Neither `TODO.md` nor `docs/engine-vectors.md` document this as an intentional divergence or known omission.

Severity is downgraded from medium to low because: the current code is correct; `TestSumNonDestructive` in `gostcrypto` already catches the most likely regression (mutating Sum); the parity gap is about reset-cycle coverage only. The risk is narrow: a future change to `Reset()` that misses a field would produce wrong output in reset-reuse scenarios that the parity suite would not catch.

**Suggested fix:** Add two parity tests to `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/streebog/streebog_parity_test.go`:

**1. TestSumNonDestructiveParity** — verifies that Sum does not alter state on either side, diffed against the oracle:
```go
func TestSumNonDestructiveParity(t *testing.T) {
    msg1 := []byte("abc")
    msg2 := []byte("def")

    // Clean-room: Sum twice, then Write more, Sum again.
    h := streebog.New512()
    h.Write(msg1)
    d1a := h.Sum(nil)
    d1b := h.Sum(nil) // second Sum — must equal first
    if !bytes.Equal(d1a, d1b) {
        t.Fatalf("clean-room Sum mutated receiver: %x != %x", d1a, d1b)
    }
    h.Write(msg2)
    d2 := h.Sum(nil)

    // Oracle: same sequence.
    ref := gost.Streebog512(append(msg1, msg2...))
    if !bytes.Equal(d2, ref) {
        t.Fatalf("clean-room post-Sum Write mismatch\n got %x\n ref %x", d2, ref)
    }

    // Also diff the intermediate d1a against oracle of msg1 alone.
    ref1 := gost.Streebog512(msg1)
    if !bytes.Equal(d1a, ref1) {
        t.Fatalf("clean-room Sum(msg1) mismatch\n got %x\n ref %x", d1a, ref1)
    }
}
```

**2. TestResetReuseParity** — verifies that Reset() produces the same result as a fresh digest, diffed against the oracle:
```go
func TestResetReuseParity(t *testing.T) {
    rng := rand.New(rand.NewSource(0xDEADBEEF))
    for i := 0; i < 20; i++ {
        n := rng.Intn(300)
        msg1 := make([]byte, n)
        rng.Read(msg1)
        m2 := rng.Intn(300)
        msg2 := make([]byte, m2)
        rng.Read(msg2)

        h := streebog.New512()
        h.Write(msg1)
        _ = h.Sum(nil) // consume once, then reset
        h.Reset()
        h.Write(msg2)
        got := h.Sum(nil)

        ref := gost.Streebog512(msg2)
        if !bytes.Equal(got, ref) {
            t.Fatalf("reset-reuse mismatch len1=%d len2=%d\n got %x\n ref %x", n, m2, got, ref)
        }
    }
}
```

These two tests close the parity gap: the first catches a mutating `Sum`, the second catches a `Reset()` that fails to zero any field (particularly `d.nbuf` or `d.buf`).

### [STB-02] New256 streaming path never diffed; oracle streaming hashes unused

- **Location:** `parity/streebog/streebog_parity_test.go:67,91`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Only New512() is exercised via chunked Writes (test line 91, fuzz line 67). The 256-bit variant is only ever hit through one-shot Sum256, which performs a single internal Write. The Write/compress machinery is shared between the two sizes, so coverage is largely indirect, but the 256 IV + MSB_256 truncation combined with buffered/partial-block state is never directly diffed. The facade also exposes streaming oracles (gostcryptocompat.NewStreebog256Hash/NewStreebog512Hash, exports_gost.go:34-38) that the parity package never uses — the oracle side is always one-shot.

**Evidence:** parity test creates only streebog.New512() (lines 67 and 91); 'New256' does not appear in the parity package. Comment at streebog_parity_test.go:82-83 ("exercises chunked Write against the oracle's hash.Hash streaming path") is also inaccurate — the oracle side is the one-shot gost.Streebog512(msg) at line 102, not a chunked hash.Hash. The comparison is still meaningful (clean-room streaming vs reference one-shot), so this is a doc inaccuracy plus a coverage gap, not a vacuous test.

**Verifier confirmation:** All three sub-claims in the finding are confirmed by reading the actual source.

**1. New256 streaming path absent (confirmed)**
`streebog_parity_test.go` lines 67 and 91 both instantiate `streebog.New512()`. The identifier `New256` does not appear anywhere in the parity package. The 256-bit `hash.Hash` path — which uses a different IV (all `0x01` bytes, `streebog.go:382-385`) and the `MSB_256` truncation (`out[32:64]`, `streebog.go:478`) — is only reached indirectly through `streebog.Sum256(msg)` at line 28, which internally does `New256()` → `Write(b)` (a single call) → `Sum(nil)`. Multi-block messages do go through `compress()` correctly, but the partial-buffer boundary cases (e.g. a split that lands exactly on a 64-byte boundary, or across two calls where the first fills the buffer partway and the second crosses it) are only exercised for the 512-bit digest.

**2. Comment at lines 82-83 is inaccurate (confirmed)**
`TestDiffStreamingAgainstGost` (line 84) is documented as "exercises chunked Write against the oracle's hash.Hash streaming path." However the oracle side at line 102 is `gost.Streebog512(msg)` — a one-shot call that does a single `h.Write(msg)` internally (see `primitives_gost.go:182-186`). The oracle is NOT using a streaming `hash.Hash` interface; it is comparing clean-room-chunked against oracle-one-shot. The comparison is still meaningful and correct (clean-room streaming vs reference one-shot does catch internal state management bugs), but the comment falsely implies the oracle side is also streaming.

**3. Facade streaming oracles unused (confirmed)**
`exports_gost.go:35-38` exports `NewStreebog256Hash() hash.Hash` and `NewStreebog512Hash() hash.Hash`. Neither is imported or referenced anywhere in `parity/streebog/`. The parity tests always use the one-shot wrappers `gost.Streebog256()` / `gost.Streebog512()`.

**Why severity stays low, not raised**
The `Write`/`compress` machinery is genuinely shared between the two digest sizes — the only 256-specific code paths are (a) the `Reset()` IV initialization (`iv[i] = 0x01` for all 64 bytes) and (b) the `Sum()` truncation (`return append(in, out[32:64]...)` instead of the full 64 bytes). These are structurally simple, independent of the buffer management, and the correctness of the 256-bit IV + MSB_256 truncation is validated (against a one-shot oracle) for over 200 message lengths including 0, 1, 7, 31, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 1000, 4096 and 200 random values. The gap is real but the chance of a bug that only surfaces under 256-bit streaming-with-split and is missed by 200+ one-shot lengths is genuinely low.

**Suggested fix:** Three targeted changes to `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/streebog/streebog_parity_test.go`:

1. **Add a streaming 256-bit test** — mirror `TestDiffStreamingAgainstGost` for the 256-bit digest. Example:
```go
func TestDiffStreaming256AgainstGost(t *testing.T) {
    rng := rand.New(rand.NewSource(0xCAFE))
    for i := 0; i < 50; i++ {
        n := rng.Intn(3000)
        msg := make([]byte, n)
        rng.Read(msg)

        h := streebog.New256()
        for off := 0; off < n; {
            chunk := rng.Intn(70) + 1
            end := off + chunk
            if end > n { end = n }
            h.Write(msg[off:end])
            off = end
        }
        got := h.Sum(nil)
        ref := gost.Streebog256(msg)
        if !bytes.Equal(got, ref) {
            t.Fatalf("streaming 256 mismatch len=%d\n clean-room %x\n oracle     %x", n, got, ref)
        }
    }
}
```

2. **Add a streaming 256-bit fuzz path** — add a split-based section to `FuzzDiffAgainstGost`, parallel to the existing "Streaming 512" block at lines 66-78:
```go
// Streaming 256: same split logic, diff against one-shot.
h256 := streebog.New256()
if len(msg) > 0 {
    off := int(split % uint(len(msg)+1))
    h256.Write(msg[:off])
    h256.Write(msg[off:])
} else {
    h256.Write(msg)
}
gotStream256 := h256.Sum(nil)
if !bytes.Equal(gotStream256, ref256) {
    t.Fatalf("streaming 256 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), gotStream256, ref256)
}
```

3. **Fix the comment at lines 82-83** — change "exercises chunked Write against the oracle's hash.Hash streaming path" to "exercises chunked Write against the one-shot oracle (clean-room streaming vs reference one-shot)" to accurately reflect what the test does.

### [STB-03] Fuzz streams only the 512 variant with a single two-way split

- **Location:** `parity/streebog/streebog_parity_test.go:48-80`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** FuzzDiffAgainstGost varies the message and one split offset for New512 only. Not fuzzed: (a) a streaming New256 (256-bit truncation after fuzzer-chosen buffered state), (b) >2-chunk Write sequences — repeated partial-buffer fills that never reach a block boundary across more than two Writes are covered only by the fixed-seed TestDiffStreamingAgainstGost (rng seed 0xBEEF), not by active fuzzing, (c) Sum-then-Write-then-Sum reuse. There is also no committed testdata/fuzz corpus directory; only the three inline f.Add seeds replay under plain go test.

**Evidence:** f.Fuzz body (lines 53-79) builds exactly one streebog.New512() and performs at most two Writes (msg[:off], msg[off:]); ls parity/streebog/ shows no testdata directory. Empty-input seeding at line 49 is correct — Streebog has no empty-input divergence (that caveat is GOST R 34.11-94 per docs/engine-vectors.md), so this is explicitly NOT a finding.

**Verifier confirmation:** All three sub-claims in the finding are factually accurate, but the practical risk is lower than it might appear.

Sub-claim (a) — no streaming New256 in the fuzz target: Confirmed. Lines 67-74 construct only `streebog.New512()`. However, the clean-room `Write` implementation (streebog.go:407-440) does not branch on `d.size` at all — the streaming state machine is identical for 256 and 512. The size field only matters at `Sum` time (lines 476-481: a different output slice). A bug in buffered partial-block handling would be equally caught by 512 streaming. The gap is real but carries negligible incremental risk.

Sub-claim (b) — >2-chunk sequences only in fixed-seed deterministic test: Confirmed. The fuzz body (lines 67-74) performs at most two Writes. Multi-chunk (>2 Write) coverage lives entirely in `TestDiffStreamingAgainstGost` (lines 84-107), which uses a fixed RNG seed 0xBEEF with 50 random-length messages and random chunk sizes (1-70 bytes). That test does cover repeated partial-buffer fills and multi-block streaming, but it is not driven by the fuzzer and its 50-iteration fixed corpus is narrow. The fuzz target cannot discover multi-chunk edge cases (e.g. exactly at blockSize=64 boundary across 3+ Writes, or alternating empty+non-empty Writes).

Sub-claim (c) — no Sum-then-Write-then-Sum reuse: Confirmed absent from the fuzz target. Note: the CLAUDE.md documents that `gost28147.MAC.Sum` is destructive (via slice aliasing), but Streebog's Sum (streebog.go:443-481) snapshots `h`, `n`, `sum` into local copies before operating, leaving the receiver state (`d.buf`, `d.nbuf`, `d.h`, `d.n`, `d.sum`) untouched. So Sum is non-destructive and calling Sum mid-stream is valid behavior — but no test covers this pattern.

Testdata corpus absence: Confirmed. `ls parity/streebog/` returns only `streebog_parity_test.go`; there is no `testdata/fuzz/FuzzDiffAgainstGost/` directory. Only the three inline `f.Add` seeds (lines 49-51) replay under plain `go test`.

The empty-input note in the finding is also correct: the CLAUDE.md and docs/engine-vectors.md document that the empty-input divergence is a GOST R 34.11-94 (Streebog-94) issue, not Streebog-2012. The `f.Add([]byte{}, uint(0))` seed at line 49 is intentional and correct.

Severity stays low: the most impactful gap is the absence of a committed corpus and the restriction of the fuzz target to two-Write sequences. The streaming-256 gap carries near-zero risk given the shared code path.

**Suggested fix:** Three concrete improvements to `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/streebog/streebog_parity_test.go`:

1. Extend `FuzzDiffAgainstGost` to cover streaming `New256` with a split, mirroring lines 66-78. After the existing streaming-512 block, add:

```go
// Streaming 256: same split, diff against one-shot.
h256 := streebog.New256()
if len(msg) > 0 {
    off := int(split % uint(len(msg)+1))
    h256.Write(msg[:off])
    h256.Write(msg[off:])
} else {
    h256.Write(msg)
}
gotStream256 := h256.Sum(nil)
if !bytes.Equal(gotStream256, ref256[:]) {
    t.Fatalf("streaming 256 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), gotStream256, ref256)
}
```

2. Add a second fuzz split parameter to cover >2-chunk sequences, e.g.:

```go
func FuzzDiffAgainstGostMultiChunk(f *testing.F) {
    f.Add(bytes.Repeat([]byte{0xab}, 193), uint(64), uint(128))
    f.Fuzz(func(t *testing.T, msg []byte, split1, split2 uint) {
        h := streebog.New512()
        if len(msg) > 0 {
            off1 := int(split1 % uint(len(msg)+1))
            off2 := off1 + int(split2%uint(len(msg)-off1+1))
            h.Write(msg[:off1])
            h.Write(msg[off1:off2])
            h.Write(msg[off2:])
        } else {
            h.Write(msg)
        }
        ref := gost.Streebog512(msg)
        if got := h.Sum(nil); !bytes.Equal(got, ref) {
            t.Fatalf(...)
        }
    })
}
```

3. Create the corpus directory and commit one interesting seed that exercises a 3-chunk write crossing a block boundary:
```
mkdir -p parity/streebog/testdata/fuzz/FuzzDiffAgainstGost
```
Then run `go test -fuzz=FuzzDiffAgainstGost -fuzztime=60s ./parity/streebog/` once and commit any generated corpus entries.

The Sum-then-Write-then-Sum pattern is worth a deterministic unit test (not necessarily fuzz) to document that Sum is non-destructive and continued Write after Sum produces the correct result.

---

## tlstree

**Reviewer summary:** This is a genuinely solid parity test. The oracle (gostcryptocompat.TLSTree wrapping gogost's gost34112012256.DeriveCached) is fully independent of the clean-room implementation (own HMAC-Streebog256 KDF chain) — no tautology, no shared helpers. Comparisons are full 32-byte bytes.Equal diffs, never length/nil checks. The Derive(0) priming of the oracle is the correct, documented workaround for gogost's D2 zero-key startup trap, and leaving the clean-room side unprimed is precisely the divergence the clean-room must not carry — an intentional asymmetry, not a wiring bug. The pinned KAT (seq=63, K=32x0xFF) matches gogost's own committed test vector (third_party/gogost/gost34112012256/tlstree_test.go:115) and the gost-engine-derived vectors in the clean-room's own tests, so it is independently sourced. The table seqs cross all three mask levels (C1/C2/C3) for both Kuznyechik and Magma, and the fuzz target varies master key, full-range uint64 seq, and suite, plus a self-consistency window invariant whose near-max-uint64 wraparound is benign. All tests pass. Remaining gaps are minor: no multi-call/sequential-reuse parity (real TLS monotone seq replay exercising the oracle's cache transitions with seqNumPrev>0), constructor panic parity unexercised, the fuzz performs only one ref Derive after priming (never fuzzes a (seq1,seq2) pair on a shared tree), and the seed corpus anchors only level-3 boundaries. No correctness findings.

### [TLS-01] Constructor error-path parity (non-32-byte master panic) not exercised

- **Location:** `gostcrypto-compat/parity/tlstree/tlstree_parity_test.go:26-31`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** Both sides document and implement a panic on master keys != 32 bytes (clean-room gostcrypto/tlstree/tlstree.go:102-105; facade tlstree_gost.go:27-29 — note the facade checks before NewTLSTree while gogost itself would silently accept a short key). The parity test only ever feeds 32-byte masters, so the contract that both constructors reject bad lengths identically is asserted only in the clean-room's own unit test (tlstree_test.go:213-227), not in the parity package. Trivial behaviour, hence low.

**Evidence:** All four masters at tlstree_parity_test.go:26-31 are exactly 32 bytes; no recover-based negative case exists in the parity package.

**Verifier confirmation:** The factual claims in the finding are correct.

**What the code actually does:**

- Clean-room `newTree` (`gostcrypto/tlstree/tlstree.go:102-105`): panics if `len(master) != KeySize`.
- Facade `NewTLSTreeKuznyechikCTROMAC` / `NewTLSTreeMagmaCTROMAC` (`tlstree_gost.go:27-29`, `43-45`): explicitly check `len(masterKey) != 32` and panic *before* delegating to gogost.
- gogost `NewTLSTree` (`third_party/gogost/gost34112012256/tlstree.go:65-74`): no length check whatsoever — does `make([]byte, len(keyRoot))` / `copy` and proceeds silently with any length.

So at the *raw gogost* layer, a short key is silently accepted. The facade papers over this by adding its own guard. The public API surface of both the clean-room and the compat facade therefore panics identically on bad-length inputs.

**Why the parity gap is real but low-value:**

All four masters at `tlstree_parity_test.go:26-31` are exactly 32 bytes. No `recover`-based negative test exists in the parity package. The clean-room's own `TestMasterKeyLength` (`tlstree_test.go:212-227`) covers this contract with five bad lengths (0, 16, 31, 33, 64) against `NewTLSTreeKuznyechikCTROMAC` only, but that test is in `gostcrypto`, not in the parity package.

A parity test covering this would confirm that `gostcryptocompat.NewTLSTreeKuznyechikCTROMAC(make([]byte, 16))` panics identically to the clean-room. Since the facade's guard is a deliberate shim to compensate for gogost's missing validation, such a test could catch a future regression if the facade guard were accidentally removed. However, given that the behavioral contract is already uniform (both panic), the gap introduces no latent divergence risk. Nothing in `TODO.md` or `docs/engine-vectors.md` documents this as a known intentional divergence, so the finding is not refuted on those grounds either. The severity of `low` is appropriate.

**Suggested fix:** Add a recover-based subtest to `parity/tlstree/tlstree_parity_test.go` that asserts both constructors panic identically for non-32-byte masters. Example:

```go
func Test_TLSTree_BadMasterKeyLength(t *testing.T) {
    for _, n := range []int{0, 16, 31, 33, 64} {
        n := n
        t.Run(fmt.Sprintf("len=%d", n), func(t *testing.T) {
            bad := make([]byte, n)
            mustPanic := func(name string, fn func()) {
                t.Helper()
                defer func() {
                    if recover() == nil {
                        t.Fatalf("%s(len=%d) did not panic", name, n)
                    }
                }()
                fn()
            }
            mustPanic("cleanroom.NewTLSTreeKuznyechikCTROMAC", func() { cleanroom.NewTLSTreeKuznyechikCTROMAC(bad) })
            mustPanic("gostref.NewTLSTreeKuznyechikCTROMAC",   func() { gostref.NewTLSTreeKuznyechikCTROMAC(bad) })
            mustPanic("cleanroom.NewTLSTreeMagmaCTROMAC",      func() { cleanroom.NewTLSTreeMagmaCTROMAC(bad) })
            mustPanic("gostref.NewTLSTreeMagmaCTROMAC",        func() { gostref.NewTLSTreeMagmaCTROMAC(bad) })
        })
    }
}
```

This guards against a future regression where the facade guard in `tlstree_gost.go` is removed, inadvertently letting gogost silently accept bad-length keys while the clean-room still panics.

### [TLS-02] Fuzz target never varies the number/order of Derive calls — cache-path dimension hardcoded

- **Location:** `gostcrypto-compat/parity/tlstree/tlstree_parity_test.go:92-95`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The fuzzer varies master, seq, and suite, but the call pattern is fixed: prime(0) then one Derive(seq). Fuzzing a second sequence number (seq2) on the same shared oracle tree (ref.Derive(seq); ref.Derive(seq2) vs fresh clean-room Derives) would let the fuzzer explore gogost's DeriveCached state machine — cache hits, partial-mask matches across the three levels, and backward seq jumps — none of which are reachable from seqNumPrev=0 alone. The clean-room's statelessness limits the blast radius, so low severity.

**Evidence:** f.Fuzz signature at line 81 is `func(t *testing.T, raw []byte, seq uint64, magma bool)` — a single seq; lines 92-95 perform exactly prime(0)+Derive(seq) on the ref.

**Verifier confirmation:** The fuzz target at `parity/tlstree/tlstree_parity_test.go` lines 76-112 creates a **fresh** `ref` tree per fuzz iteration (line 92: `ref := newRef(master)`), primes it once (`ref.Derive(0)`, line 93), then calls `ref.Derive(seq)` exactly once (line 94). It never calls `Derive` twice on the same ref object.

This means the test never exercises gogost's `DeriveCached` cache-hit branch (gogost `gost34112012256/tlstree.go:77-82`): the `if seqNum > 0 && (seqNum&params[0]) == (seqNumPrev&params[0]) && ...` condition can only be `true` on the *second or later* call on a live tree. Because the fuzz always uses a fresh tree, `seqNumPrev` is always 0 and the cache branch is never taken.

This matters for the facade (`gostcryptocompat.TLSTree` in `tlstree_gost.go`): its `inner` field is a persistent gogost tree that accumulates `seqNumPrev` across multiple `Derive` calls. In production, sequential calls like `facade.Derive(63); facade.Derive(64)` will hit the cache path on the second call. A bug in gogost's cache condition (wrong mask, off-by-one window boundary) would cause the facade to return a stale key silently for seq 64 — and the current fuzz would never detect it, because it never calls two derives on the same ref object.

The clean-room `gostcrypto/tlstree/TLSTree.Derive()` is entirely stateless (always recomputes all three KDF levels from root, no mutable fields beyond the constant masks and root key). This limits blast radius: any cache mismatch between a fresh-tree call and a re-used-tree call on the *gogost side* would still show up as a divergence between the facade (which may return the cached-wrong value) and the clean-room (which always recomputes correctly). So the parity test structure does catch the failure — but only if the fuzz actually calls Derive twice on the same ref object. With a fresh tree each iteration it cannot.

The finding is NOT a documented intentional divergence in `gostcrypto/TODO.md` or `docs/engine-vectors.md`; those documents cover GOSTR341194 empty-input finalization, S-box row order, and CryptoPro key meshing — unrelated to TLSTree cache behavior. Severity is low (not medium/high) because: (a) gogost's cache is almost certainly correct given it is battle-tested, and (b) the window-boundary invariant is exercised by a separate inline check in the fuzz body (lines 101-110) using fresh clean-room trees, which would catch a wrong window size even without the cache path.

**Suggested fix:** Add a second sequence number `seq2` to the fuzz signature and run a two-derive sequence on the **same ref object**, then compare against a fresh clean-room derive for seq2:

```go
f.Add(bytes.Repeat([]byte{0xFF}, 32), uint64(63), uint64(64), false)  // cross-window
f.Add(bytes.Repeat([]byte{0x00}, 32), uint64(0), uint64(1), false)    // same window
f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(4096), uint64(4096), true)

f.Fuzz(func(t *testing.T, raw []byte, seq1, seq2 uint64, magma bool) {
    master := make([]byte, 32)
    copy(master, raw)

    newRef, newNew := gostref.NewTLSTreeKuznyechikCTROMAC, cleanroom.NewTLSTreeKuznyechikCTROMAC
    window := uint64(64)
    if magma {
        newRef, newNew = gostref.NewTLSTreeMagmaCTROMAC, cleanroom.NewTLSTreeMagmaCTROMAC
        window = 4096
    }

    // Existing single-derive check for seq1.
    ref := newRef(master)
    _ = ref.Derive(0)
    gotRef1 := ref.Derive(seq1)
    gotNew1 := newNew(master).Derive(seq1)
    if !bytes.Equal(gotRef1, gotNew1) {
        t.Fatalf("mismatch master=%x seq=%d magma=%v\n ref: %x\n new: %x",
            master, seq1, magma, gotRef1, gotNew1)
    }

    // Sequential call: reuse ref to exercise the DeriveCached cache path.
    // After Derive(seq1), seqNumPrev==seq1; Derive(seq2) may hit the cache
    // if seq2 falls in the same L1/L2/L3 window as seq1.
    gotRef2 := ref.Derive(seq2)
    gotNew2 := newNew(master).Derive(seq2)
    if !bytes.Equal(gotRef2, gotNew2) {
        t.Fatalf("sequential mismatch master=%x seq1=%d seq2=%d magma=%v\n ref: %x\n new: %x",
            master, seq1, seq2, magma, gotRef2, gotNew2)
    }

    // Window-boundary invariant (unchanged).
    base := seq1 - (seq1 % window)
    k0 := newNew(master).Derive(base)
    kIn := newNew(master).Derive(base + window - 1)
    kOut := newNew(master).Derive(base + window)
    if !bytes.Equal(k0, kIn) {
        t.Fatalf("intra-window key changed: master=%x base=%d window=%d", master, base, window)
    }
    if bytes.Equal(k0, kOut) {
        t.Fatalf("cross-window key unchanged: master=%x base=%d window=%d", master, base, window)
    }
})
```

The seeds should include cases where `seq1` and `seq2` are in the same window (cache hit expected) and across a window boundary (cache miss expected). Update the `f.Add` calls accordingly, e.g. `f.Add(..., uint64(63), uint64(64), false)` for a cross-boundary case in the Kuznyechik suite.

### [TLS-03] Seed corpus anchors only level-3 (C3) boundaries; no level-1/level-2 boundary seeds

- **Location:** `gostcrypto-compat/parity/tlstree/tlstree_parity_test.go:77-79`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The three seeds use seq = 63, 0, 4096 — all within or at the level-3 window. No seed sits at a level-2 boundary (2^19 for Kuznyechik, 2^25 for Magma) or level-1 boundary (2^32 / 2^38), so on a short fuzz run the level-1/level-2 KDF seed paths are reached only if the mutator happens to flip high bits of the uint64. Adding e.g. f.Add(master, uint64(1)<<32, false) and f.Add(master, uint64(1)<<38, true) would anchor those paths. Mitigated by the table test at line 33 which does cross all levels deterministically, hence low.

**Evidence:** Seeds: `f.Add(..., uint64(63), false)`, `f.Add(..., uint64(0), false)`, `f.Add(..., uint64(4096), true)` — max seeded seq is 4096, below every C2/C1 boundary. The fuzz invariant at lines 101-110 likewise checks only the C3 window.

**Verifier confirmation:** The finding is factually correct in all details. Verified against actual source:

1. **Seed corpus (lines 77-79)**: The three `f.Add` seeds use `seq = 63, 0, 4096`, which are all within or at the C3 window boundaries. For Kuznyechik the C3 window is 64 records, for Magma 4096. Max seed is 4096 — well below every C2 boundary (Kuznyechik: 2^19 = 524288, Magma: 2^25 = 33554432) and every C1 boundary (Kuznyechik: 2^32, Magma: 2^38). No testdata corpus directory exists for `parity/tlstree/`, so the three `f.Add` calls constitute the entire seed corpus.

2. **Fuzz invariant (lines 101-110)**: `window` is set to `64` (Kuznyechik) or `4096` (Magma) — exactly the C3 window. `kOut = Derive(base + window)` crosses only a C3 boundary. The invariant is incapable of detecting a regression specifically in the level-1 or level-2 KDF chain independently of the main conformance check.

3. **Mitigation is real**: `Test_TLSTree_Conformance` at line 33 uses `seqs := []uint64{..., 1 << 20, 1<<32 - 1, 1 << 32, 1 << 40}`. Verified: `1<<20` (1048576) is above Kuznyechik C2 (524288); `(1<<32)-1` and `1<<32` cross the Kuznyechik C1 boundary and also land above Magma C2 (33554432); `1<<40` is above Magma C1 (274877906944). All four level-1/level-2 boundary paths for both suites are exercised deterministically on every `go test` run. This is a genuine mitigation, not a nominal one.

4. **Severity**: Low is correct. The fuzz weakness matters only for active fuzzing (i.e. finding new bugs), not for correctness of `go test ./...`. Since the clean-room `Derive` recomputes all three KDF levels on every call without caching, the level-1/level-2 paths are structurally unavoidable once the table test supplies an appropriate seq. The fuzz corpus gap simply means a time-limited fuzz run (`make fuzz FUZZTIME=1m`) is unlikely to exercise those paths unless the mutator flips high bits.

**Suggested fix:** Add seeds that anchor the level-1 and level-2 boundary paths for both suites in `Fuzz_TLSTree_Conformance`. Insert after line 79:

```go
// Kuznyechik C2 boundary (seq = 2^19 = 524288, magma=false)
f.Add(bytes.Repeat([]byte{0xFF}, 32), uint64(1)<<19, false)
// Kuznyechik C1 boundary (seq = 2^32, magma=false)
f.Add(bytes.Repeat([]byte{0xFF}, 32), uint64(1)<<32, false)
// Magma C2 boundary (seq = 2^25, magma=true)
f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(1)<<25, true)
// Magma C1 boundary (seq = 2^38, magma=true)
f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(1)<<38, true)
```

Optionally, also extend the fuzz invariant to verify C2-level transitions by computing `kC2out := newNew(master).Derive(base + c2Window)` where `c2Window` is the C2-window size for the active suite (524288 for Kuznyechik, 33554432 for Magma) and asserting it differs from `k0` when the two are in different C2 windows. This is optional since the main conformance check (`bytes.Equal(gotRef, gotNew)`) already handles it once the seeds are seeded correctly.

### Dismissed for tlstree (do NOT act on these)

#### DISMISSED: No sequential-reuse parity: repeated Derive calls on the same tree pair never diffed

- **Location:** `gostcrypto-compat/parity/tlstree/tlstree_parity_test.go:35-48` · **Category:** test-gap · **Severity claimed:** low · **Verifier:** sonnet

**Original claim:** Every comparison builds a fresh oracle, primes it with Derive(0), and does exactly one Derive(seq). The real TLS usage pattern — many Derives on one long-lived tree with monotonically increasing seq — is never replayed against the clean-room. gogost's DeriveCached has stateful cache-hit/recompute transitions keyed on seqNumPrev (third_party/gogost/gost34112012256/tlstree.go:76-92); only the seqNumPrev=0 transition is ever exercised. A replay loop (e.g. seq 0..2*window+3 on a shared ref/cleanroom pair) would prove the clean-room is a drop-in replacement across cache transitions with nonzero seqNumPrev, and would also catch any aliasing regression in the facade's copy at tlstree_gost.go:61-64. Low because the clean-room Derive is stateless (tlstree.go:119-138), so per-seq equality already implies sequence equality for it.

**Why dismissed:** The finding rests on the assumption that testing a fresh oracle/clean-room pair per seq is weaker than testing a long-lived pair sequentially. That assumption fails for this specific primitive.

**Clean-room is stateless (tlstree.go:119-138).** The `TLSTree` struct holds only `root [32]byte`, `c1`, `c2`, `c3` — no `seqNumPrev`, no cached key. Every call to `Derive(seqNum)` runs the full three-level KDF chain from the root unconditionally. The output is a pure function of `(root, seqNum)`.

**Mathematical implication.** Because `cleanroom.Derive(seq)` produces the same bytes regardless of which calls preceded it, the property "for all (master, seq): fresh_cleanroom.Derive(seq) == fresh_oracle.Derive(seq)" implies "for any call sequence on a long-lived pair: shared_cleanroom.Derive(seq_i) == shared_oracle.Derive(seq_i)". The test's fresh-instance-per-seq pattern is therefore not weaker — it is equivalent.

**The gogost DeriveCached cache transitions (tlstree.go:76-92) are not observable from outside.** Cache-hit and cache-miss paths both return the same mathematical answer (that is the whole point of the cache). A sequential loop on the oracle cannot produce a value that differs from a per-seq fresh-oracle call, because if it did, the oracle itself would be buggy. Parity tests compare clean-room to reference; they do not audit the reference's internal consistency.

**Facade aliasing (tlstree_gost.go:61-64) is not a gap.** The wrapper does `out := make([]byte, 32); copy(out, key); return out` — a fresh allocation on every call. A subsequent `DeriveCached` call overwrites `t.inner.key` but cannot retroactively alter the already-returned `out`. There is no aliasing regression possible here, and no sequential test is needed to confirm it — the code is self-evidently safe.

**No documented divergence applies.** TODO.md and docs/engine-vectors.md list the D2 zero-key startup trap (when `seqNum > 0` lands in the same window as the unset `seqNumPrev=0`), which is precisely what the test's `ref.Derive(0)` prime is designed to avoid. Nothing in either document suggests a cache-transition divergence between clean-room and oracle.

The finding's own parenthetical ("Low because the clean-room Derive is stateless, so per-seq equality already implies sequence equality for it") correctly states the reason the claimed gap is not a gap. The test is correctly designed.

---

## vko

**Reviewer summary:** The vko parity test is genuinely differential and non-vacuous: the oracle path goes through the gostcryptocompat facade straight into gogost's gost3410 KEK/KEK2001/KEK2012256/KEK2012512 (independent EC math and hashing), comparisons are byte-exact on the KEK, the 2012 KAT inputs are copied from gogost's own upstream test vectors, both agreement directions are exercised for each variant, and the fuzz target adds a symmetry check plus oracle equality on random scalars. Tests pass. The real weaknesses are coverage gaps: the clean-room's cofactor-4 handling (its most delicate, gogost-divergent code path, including the VKO-62 mod-fullOrder reduction) is never run through live parity — the only cofactor-4 check is a frozen KAT inside gostcrypto whose expected value was itself generated from the gogost oracle; the fuzz pins UKM to 8 bytes and the curve/variant to VKO2012_256 on 512-paramSetA, leaving the UKM-reduction branch, the 2001 (GOSTR341194-hash, 256-bit curve) path, and VKO2012_512 un-fuzzed; and base-point derivation (DeriveQLE) feeds both sides in the fuzz and the 2001 KAT, so a self-consistent base-multiplication bug would pass parity. None of the documented divergences (S-box row order, R 34.11-94 empty input, key meshing) apply here — the 2001 hash input is always 64 non-empty bytes.

### [VKO-01] Cofactor-4 curves (tc26-256-A, tc26-512-C) never run through live parity

- **Location:** `gostcrypto-compat/parity/vko/vko_parity_test.go:36-115 (KAT) and :128-171 (fuzz)`
- **Category:** test-gap · **Severity:** medium · **Verifier:** opus

**Finding:** Every parity case uses a cofactor-1 curve: the 2001 test paramset and 512-paramSetA. The clean-room's cofactor machinery — cofactor() and the u = UKM*cofactor handling plus the VKO-62 reduction in agreementRaw (gostcrypto/vko/vko.go:137-203) — is the part of the implementation that structurally diverges from gogost (which multiplies by C.Co with no reduction, third_party/gogost/gost3410/vko.go KEK), yet it is never diffed against the oracle. The only cofactor-4 test anywhere is gostcrypto/vko/cofactor4_test.go, which pins a frozen expected value that, per its own comment, 'was computed via the gogost oracle' — a snapshot, not a live differential, and it lives outside the parity gate in the BSD module. The facade already exposes VKO2012_256OnCurve + CurveByOID (gostcrypto-compat/primitives_gost.go:387-401), so adding a tc26-256-A differential KAT and/or fuzz leg is trivial.

**Evidence:** Parity test: c := vko.Curve2012ParamSetA() (cofactor 1) is the only fuzz curve; KAT variants use curve2001Test (Cofactor: 1) and curve2012paramSetA. gostcrypto/vko/cofactor4_test.go:20-21: "The expected value below was computed via the gogost oracle and independently reproduced by this package's KEK2012256."

**Verifier confirmation:** The finding is accurate on every checkable point.

(1) All live parity cases use cofactor-1 curves. vko_parity_test.go:37 uses vko.Curve2001Test() whose def pins Cofactor: 1 (vko.go:275). The 2012_256/512 cases (lines 71-74, 95-98) and the fuzz target (line 136) all run on Curve2012ParamSetA() = OID 1.2.643.7.1.2.1.2.1 = id-tc26-gost-3410-12-512-paramSetA, which in the gogost oracle is built with co=nil -> c.Co=bigInt1 (params.go:446-448, curve.go:73-74). Cofactor 1 confirmed.

(2) The cofactor-4 path is the part that structurally diverges from the oracle. Clean-room agreementRaw computes u = UKM*cofactor and then reduces u mod (cofactor*q) (vko.go:171-189, the VKO-62 reduction). The gogost oracle does u = ukm.Mul(ukm, C.Co) with NO reduction (third_party/gogost/gost3410/vko.go:28-34). On every parity curve cofactor()==1, so u==UKM (an 8-byte value), the reduction is a no-op and the cofactor multiply is the identity — the divergent branch is never executed against the oracle.

(3) The only cofactor-4 coverage is gostcrypto/vko/cofactor4_test.go, which pins a frozen want value its own comment (lines 20-21) says 'was computed via the gogost oracle' — a static snapshot, in the BSD module, outside the parity gate. If either side's cofactor logic regressed, this snapshot would not catch a clean-room-vs-oracle drift; it would only fail if the clean-room stopped matching the frozen bytes.

(4) Adding a live differential is trivial as claimed: the facade exposes VKO2012_256OnCurve (primitives_gost.go:390) and CurveByOID; the clean-room exposes KEK2012256(c,...) and DeriveQLE(c,...). tc26-256-A is OID 1.2.643.7.1.2.1.1.1 (cofactor 4 in gogost, params.go:164 bigInt4).

(5) Not a documented intentional divergence. gostcrypto/TODO.md and docs/engine-vectors.md contain no exemption for cofactor-4 VKO from the parity gate; the only VKO mention in docs is unrelated (DER-encoded 'derive' subtest vectors skipped for format reasons, engine-vectors.md:57).

Severity adjusted down from high to medium: the reduction is mathematically KEK-preserving for an 8-byte UKM and the snapshot test does demonstrate clean-room==gogost on tc26-256-A for one vector, so a latent correctness bug is unlikely. But the finding is about test-absence, and that claim holds exactly: the live parity gate never diffs the cofactor-4 branch, and the sole cofactor-4 check sits outside the gate as a frozen snapshot that can rot independently.

**Suggested fix:** Add a cofactor-4 leg to gostcrypto-compat/parity/vko/vko_parity_test.go so the divergent branch is diffed live against the oracle:

1. KAT: add a v2012256onA variant that resolves c := gost3410curves.CurveByOID("1.2.643.7.1.2.1.1.1") (tc26-256-A, cofactor 4), derives peer Q via vko.DeriveQLE(c, ...), and compares vko.KEK2012256(c, prv, peer, ukm) against gostoracle.VKO2012_256OnCurve(curve, prv, peer, ukm). Add at least one A/B (symmetry) pair, reusing the same priv/ukm style as cofactor4_test.go (priv=0x11*32, ukm=01 00.. ) but computing want from the oracle at runtime rather than pinning bytes.

2. Fuzz: add a second fuzz target (or parametrize the existing one) that runs on the tc26-256-A curve so fuzzer-chosen scalars/UKMs exercise u = UKM*4 and the mod (4*q) reduction against the oracle. Crucially, seed at least one UKM large enough that UKM*4 exceeds 4*q so the reduction path is actually taken (the current 8-byte UKMs never trigger it).

3. Once the live differential exists, the frozen gostcrypto/vko/cofactor4_test.go snapshot can stay as a fast smoke check but is no longer load-bearing for parity.

### [VKO-02] Fuzz covers only VKO2012_256 on 512-paramSetA; VKO2001 (GOSTR341194 path, 256-bit curve) and VKO2012_512 get fixed KATs only

- **Location:** `gostcrypto-compat/parity/vko/vko_parity_test.go:136-169`
- **Category:** fuzz-gap · **Severity:** medium · **Verifier:** sonnet

**Finding:** FuzzDifferential hardcodes vko.Curve2012ParamSetA() and calls only VKO2012_256 on both sides. The 2001 variant — which exercises a different 256-bit curve's ScalarMult and the GOST R 34.11-94 CryptoPro hash of the agreement point — and the Streebog-512 variant are exercised by exactly two fixed KAT directions each in TestDifferential and never by fuzzing. A variant selector byte in the fuzz input (dispatching to the matching clean/oracle pair, as the KAT already does via the variant enum at lines 59-85) would close this cheaply. Note also there is no committed seed corpus under parity/vko/testdata/ — only the single inline f.Add seed — so 'go test' replay coverage is one input.

**Evidence:** vko_parity_test.go:136: c := vko.Curve2012ParamSetA(); lines 152-169 call only vko.VKO2012_256 / gostoracle.VKO2012_256. ls parity/vko/ shows no testdata directory.

**Verifier confirmation:** All three specific claims in the finding are confirmed by direct code inspection:

1. FuzzDifferential (lines 128-171 of parity/vko/vko_parity_test.go) hardcodes `c := vko.Curve2012ParamSetA()` at line 136 and exclusively calls `vko.VKO2012_256` / `gostoracle.VKO2012_256` at lines 152-168. The `v2001` and `v2012512` branches of the `clean`/`oracle` dispatch closures (lines 66-85) are never reached from FuzzDifferential.

2. `VKO2001TestCurve` and `VKO2012_512` appear only in `TestDifferential` (lines 93-94 and 97-98 respectively) — two fixed-input KAT directions each. These cover materially distinct code paths: VKO2001 exercises a 256-bit curve (`curve2001Test()`), 32-byte scalar/public-key encoding, and GOST R 34.11-94 CryptoPro hashing instead of Streebog. A bug specific to 32-byte `loadPrivateLE`/`loadPublicLE` sizing or the `gostr341194.New` hash path in `kek()` would not be caught by fuzzing.

3. `find /Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat/parity/vko -type f` returns only `vko_parity_test.go` — no `testdata/fuzz/FuzzDifferential/` seed corpus exists. The only seed is the single inline `f.Add` at lines 129-135.

Neither TODO.md nor docs/engine-vectors.md documents this fuzz gap as intentional. The only VKO note in engine-vectors.md explains why gost-engine VKO vectors were skipped (DER-encoded key format issue), which is unrelated to this parity-fuzz coverage gap.

The `variant` enum and `clean`/`oracle` closures at lines 59-85 already provide the dispatch machinery; adding a variant selector byte to the fuzz corpus requires minimal new code.

**Suggested fix:** Extend `FuzzDifferential` with a `variantByte byte` parameter in `f.Add` and `f.Fuzz`, dispatching on `variantByte % 3` to select v2001 / v2012_256 / v2012_512. For v2001, norm scalars to 32 bytes and use `vko.Curve2001Test()` for `DeriveQLE`; the `clean`/`oracle` closures already handle the rest. Also add at least one committed seed file under `parity/vko/testdata/fuzz/FuzzDifferential/` (the existing inline seed bytes are sufficient as the first corpus entry) so `go test` replay exercises more than a single input.

### [VKO-03] Fuzz swallows clean-room errors one-directionally — a false-reject regression silently zeroes coverage instead of failing

- **Location:** `gostcrypto-compat/parity/vko/vko_parity_test.go:143-154`
- **Category:** correctness · **Severity:** minor · **Verifier:** sonnet

**Finding:** On DeriveQLE or VKO2012_256 error from the clean-room side, the fuzz body does a bare 'return' without asserting that the gogost oracle rejects the same input. The reverse direction IS checked (lines 163-166: oracle error where clean succeeded is fatal), but a clean-room regression that starts rejecting valid inputs (e.g., an over-strict IsOnCurve or length check) would make every fuzz iteration return early and the target would pass vacuously. Mitigation is that norm() guarantees well-formed non-zero inputs, so errors are nearly impossible today — which is exactly why a silent early-return would go unnoticed if that changed. Mirroring the check (clean error => oracle must also error, else Fatalf) makes the diff symmetric.

**Evidence:** vko_parity_test.go:152-154: kAB, err := vko.VKO2012_256(dA, QB, ukm); if err != nil { return } — no oracle cross-check on this path; same pattern at 143-150 for both DeriveQLE calls.

**Verifier confirmation:** The asymmetry is real and verified by reading the source.

**Lines in question (vko_parity_test.go):**
- 143-150: `DeriveQLE(c, dA)` error → bare `return` (no oracle cross-check)
- 147-150: `DeriveQLE(c, dB)` error → bare `return` (no oracle cross-check)
- 152-155: `VKO2012_256(dA, QB, ukm)` error → bare `return` (no oracle cross-check)
- 156-159: `VKO2012_256(dB, QA, ukm)` error → `t.Fatalf` — CORRECT, this direction IS checked
- 163-166: oracle error when clean-room succeeded → `t.Fatalf` — CORRECT

So: oracle-errors-where-clean-succeeded is fatal (line 165), but clean-errors is always a silent skip. The reverse direction is only partially covered: line 157-159 checks the B→A direction only after A→B already succeeded.

**What errors can actually occur given `norm()`?**
`norm(b, n)` truncates/zero-extends to n bytes and sets `b[0] |= 0x01`. This guarantees:
- Scalars are exactly 64 bytes → `errBadPrivLen` impossible
- UKM is exactly 8 bytes with bit 0 set → `leBytes2big(ukm) != 0` → `errZeroUKM` impossible
- QB comes from a successful `DeriveQLE` → correct length and on-curve → `errBadPubLen` and `errPubNotOn` impossible in `VKO2012_256`

The only realistic error paths are:
1. `errZeroPrivate` from `loadPrivateLE` — when the 64-byte scalar reduces to 0 mod q (probability ~2^-512 for a uniformly random input)
2. `errDerivedID` from `DeriveQLE` — when d·G = identity (same probability class)
3. `errIdentity` from `agreementRaw` — when d·Q = identity (same class)

These are astronomically improbable with fuzzer-generated inputs, which is precisely why a silent early-return regression would go unnoticed. If the clean-room ever tightened its validation (e.g., adding a stricter IsOnCurve variant, or if the curve's scalar arithmetic changed), every fuzz iteration would return early and the corpus-replay run would report vacuous success with zero oracle comparisons.

**Not a documented intentional divergence:** `gostcrypto/TODO.md` and `docs/engine-vectors.md` contain no note about VKO error-handling asymmetry. This is a test-quality issue, not a documented design choice.

Severity remains **low** (not higher) because `norm()` makes the reachable error paths effectively impossible in practice, and the KAT tests in `TestDifferential` (`t.Fatalf` on any clean-room error, line 103-105) provide a complementary non-fuzz safety net for the nominal case. The risk is specifically of a future regression silently zeroing fuzz coverage.

**Suggested fix:** After each early-return guard, cross-check the oracle and fail if the oracle disagrees (succeeds when clean-room failed, or vice versa). Replace the three silent early-return blocks in `FuzzDifferential` with symmetric checks:

```go
QA, err := vko.DeriveQLE(c, dA)
if err != nil {
    if _, oErr := gostoracle.VKO2012_256(dA, make([]byte, 128), ukm); oErr == nil {
        t.Fatalf("clean-room DeriveQLE(A) failed but oracle accepts dA: %v", err)
    }
    return
}
QB, err := vko.DeriveQLE(c, dB)
if err != nil {
    if _, oErr := gostoracle.VKO2012_256(dB, make([]byte, 128), ukm); oErr == nil {
        t.Fatalf("clean-room DeriveQLE(B) failed but oracle accepts dB: %v", err)
    }
    return
}

kAB, err := vko.VKO2012_256(dA, QB, ukm)
if err != nil {
    if _, oErr := gostoracle.VKO2012_256(dA, QB, ukm); oErr == nil {
        t.Fatalf("clean-room VKO2012_256 failed but oracle succeeded: %v", err)
    }
    return
}
```

Note: `gostoracle` uses gogost under the hood; gogost's `DeriveSharedKey` does not expose a stand-alone point-derivation step, so the DeriveQLE cross-check must be done indirectly (attempt a full VKO with the scalar in question and a valid peer key to probe whether the oracle rejects the same scalar). Alternatively, expose a `DeriveQLE`-equivalent in `gostcryptocompat` and use that for a more direct check. The key invariant is: clean-room error ⟹ oracle must also error on the same (dA, QB, ukm) triple.

### [VKO-04] Base-point derivation (DeriveQLE) is never diffed against gogost; a self-consistent base-mult bug passes parity

- **Location:** `gostcrypto-compat/parity/vko/vko_parity_test.go:24-31, 42-43, 143-150`
- **Category:** test-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** In both the 2001 KAT (Q1/Q2 via deriveQ) and the entire fuzz target (QA/QB via vko.DeriveQLE), the peer public points fed to BOTH the clean-room and the gogost oracle are produced by the clean-room's own base-point ScalarMult. A self-consistent bug there (e.g., deriving f(d)·P instead of d·P for some multiplicative f) preserves agreement symmetry (kAB == kBA) and oracle equality (both sides hash the same dA·QB'), so it would pass undetected; the parity KEK value itself is checked only against the oracle, not a pinned constant. The 2012 KATs partially mitigate this by using independent gogost-vector points (constraining arbitrary-point ScalarMult parity), and gostcrypto's own vko_test.go pins the expected KEKs — but inside the parity gate, public-key derivation parity is unverified. One line fixes it: compare vko.DeriveQLE(c, dA) against gogost's NewPrivateKey(...).PublicKey().Raw() (RawLE is LE(X)||LE(Y)... note gogost RawLE emits Y||X reversed — use the matching encoding) inside the fuzz body.

**Evidence:** vko_parity_test.go:24-31 deriveQ uses vko.DeriveQLE (clean-room) and the comment admits it exists 'so the 2001 KAT ... can feed both impls the same peer point'; fuzz lines 143-150 derive both QA and QB the same way; no gostoracle public-key-derivation call exists anywhere in the package.

**Verifier confirmation:** The claim is structurally correct but the severity is overstated. Here is what the code actually shows:

**What the parity gate does (gostcrypto-compat/parity/vko/vko_parity_test.go)**

1. `TestDifferential` 2001 variants (lines 42-43): `Q1 = deriveQ(t, c2001, d1)` and `Q2 = deriveQ(t, c2001, d2)` both call `vko.DeriveQLE` (clean-room). Both the clean-room VKO and `gostoracle.VKO2001TestCurve` receive these same clean-room-derived bytes. The oracle's `gost3410.NewPublicKey` just decodes the bytes it is given — it does not independently re-derive the point from dB. A self-consistent bug in `DeriveQLE` (e.g., `c.ScalarMult(d, wrongBase)`) would produce a different-but-consistent Q, and both sides would compute the same wrong KEK.

2. `TestDifferential` 2012 variants (lines 47-56): `QA` and `QB` are hardcoded RFC 7836 hex literals (the same values gogost's own `TestVKO2012256` uses). These are independent external ground-truth points. This provides coverage of the KEK-computation path for 512-paramSetA, but does NOT exercise `DeriveQLE`.

3. `FuzzDifferential` (lines 143-150): both `QA` and `QB` are derived with `vko.DeriveQLE`. The oracle at line 163 receives the clean-room QB. Symmetry check (kAB == kBA) catches some bugs but not a scalar-independent one (e.g., always returns the correct-order point for zero scalar mod q cases). No gogost public-key derivation is called anywhere in this file.

`grep -n "PublicKeyRaw\|NewPrivateKey\|PublicKey()"` on `parity/vko/vko_parity_test.go` returns only two `vko.DeriveQLE` calls (lines 26 and 143/147) — confirmed no gogost-side public-key derivation exists.

**Why severity is low, not medium**

The clean-room module's own `TestKAT_Engine04PkeyDerive` (gostcrypto/vko/vko_test.go:170-437) calls `DeriveQLE` for 14 different (curve, private scalar) pairs and compares SHA-256(SPKI) against pinned gost-engine hashes. This validates the `DeriveQLE` base-point multiplication directly against a third-party reference binary — it is far stronger than a gogost parity check would be for this function, because gogost and the clean-room share the same ScalarMult logic path. The gap is purely architectural: the parity gate (`parity/vko/`) does not independently validate `DeriveQLE` against gogost, but the separate unit test does validate it against gost-engine. The risk of a silent ScalarMult bug is real in theory but well-mitigated in practice by `TestKAT_Engine04PkeyDerive`.

**The finding's claim about gogost `RawLE` encoding is incorrect** (a red herring): gogost `public.go:85` says `func (pub *PublicKey) Raw() []byte { return pub.RawLE() }` and `RawLE()` does emit `LE(X)||LE(Y)` — the same encoding as `vko.DeriveQLE`. So there is no encoding mismatch to worry about when wiring in a gogost-side derivation.

**Suggested fix:** Add a `FuzzDeriveQLE` or a table test in `parity/vko/vko_parity_test.go` that independently derives the public point from both sides and asserts equality:

```go
// In FuzzDifferential body, after deriving QA and QB:
oracleQA, err := gostoracle.PublicKeyRawFromPrivate(
    &gostoracle.Curve{/* 512-paramSetA via CurveByOID */}, dA)
if err != nil {
    t.Fatalf("oracle DeriveQA: %v", err)
}
if !bytes.Equal(QA, oracleQA) {
    t.Fatalf("DeriveQLE mismatch vs oracle:\n got=%x\n ref=%x", QA, oracleQA)
}
```

Because `gostoracle.CurveByOID` requires an `asn1.ObjectIdentifier`, the simplest approach is to expose a 512-paramSetA helper from `gostcryptocompat` (or use the existing `PublicKeyRawFromPrivate2001Test` as a model for a 2012 variant). For the 2001 KAT's `deriveQ`, replace `vko.DeriveQLE(c2001, d)` with a check that also calls `gostoracle.PublicKeyRawFromPrivate2001Test(d)` and asserts the bytes match before feeding the point to both VKO sides.

### [VKO-05] UKM pinned to 8 bytes — the VKO-62 mod-fullOrder reduction branch is never differentially exercised

- **Location:** `gostcrypto-compat/parity/vko/vko_parity_test.go:141 (ukm := norm(rawUKM, 8))`
- **Category:** fuzz-gap · **Severity:** minor · **Verifier:** sonnet

**Finding:** The clean-room reduces u = UKM*cofactor modulo cofactor*q before the second ScalarMult (gostcrypto/vko/vko.go:173-182), a deliberate deviation from gogost, which multiplies by the unreduced u (third_party/gogost/gost3410/vko.go). With an 8-byte UKM, u < 2^67 << q, so the Mod is always a no-op and the equivalence claim ('(u mod cofactor*q)*K1 == u*K1, including torsion components') is argued in a comment but never proven against the oracle. Both sides accept arbitrary-length UKM (gogost NewUKM takes any length; clean kek() passes ukmRaw through leBytes2big), so fuzzing the UKM length up to >= PointSize bytes would directly validate the reduction — especially important combined with a cofactor-4 curve, where the torsion argument actually bites. The u == 0 mod fullOrder error branch (vko.go:178-182) is likewise unreachable under the current fuzz shape.

**Evidence:** vko_parity_test.go:141 forces len(ukm)==8 via norm(rawUKM, 8); gostcrypto/vko/vko.go:174-176: u := new(big.Int).Mul(ukm, cof); fullOrder := new(big.Int).Mul(cof, c.Q); u.Mod(u, fullOrder) — a no-op for any 64-bit UKM on a 256/512-bit curve.

**Verifier confirmation:** The finding is structurally correct: `norm(rawUKM, 8)` at line 141 of `vko_parity_test.go` caps UKM at 8 bytes (64 bits). On `Curve2012ParamSetA()` (`tc26-512-A`, cofactor=1), `fullOrder = cofactor * Q = Q` is a 512-bit number. The maximum 64-bit `u = UKM * 1` is at least 2^448 smaller than `fullOrder`, so `u.Mod(u, fullOrder)` in `vko.go:176` is unconditionally a no-op for all fuzz inputs. The `u == 0` error branch at lines 178-182 is also unreachable because `norm` forces bit 0, making `u >= 1 << 2^500` impossible (UKM < Q << Q).

Additionally, the fuzz test uses `Curve2012ParamSetA()` exclusively — a cofactor-1 curve. No cofactor-4 curve (`tc26-256-A`, OID `1.2.643.7.1.2.1.1.1`, or `tc26-512-C`) is present anywhere in `parity/vko/vko_parity_test.go`. This means the `cof = cofactor(c)` → `big.NewInt(4)` path in `agreementRaw` is also never reached by any differential test.

The gogost oracle (`vko.go KEK()`, lines 28-29) does `u = ukm * Co` with no mod — it never reduces. For a large UKM (e.g., 64 bytes on a 512-bit curve), the clean-room computes `(UKM mod Q) * K1` while gogost computes `UKM * K1`; these are mathematically identical because `ord(K1) | Q`, so no wrong-answer bug can be latent. The mathematical soundness of the reduction is also confirmed by `gostcrypto/vko/cofactor4_test.go::TestVKO2012_256_Cofactor4`, which pins a vector against the gogost oracle independently — but that KAT lives in the clean-room module, not in the parity suite, and uses only UKM = `01 00 00 00 00 00 00 00` (still 8 bytes, still far below Q). Neither `gostcrypto/TODO.md` nor `docs/engine-vectors.md` documents any UKM-reduction divergence as intentional.

Severity is adjusted to **low** (not medium) because: (a) the modular reduction is provably KEK-preserving by group theory with no hidden bug visible in the source; (b) the production API only ever receives 8-byte UKM from TLS handshakes (RFC 7836 §4.3 mandates 64-bit UKM); (c) the only risk is a future maintainer introducing a bug in the Mod path that the parity test would fail to catch — a test-coverage gap, not an exploitable weakness today.

**Suggested fix:** Add two targeted expansions to `gostcrypto-compat/parity/vko/vko_parity_test.go`:

1. **Cofactor-4 differential table case** — add a `TestDifferential` sub-case using `tc26-256-A` (`CurveByOID("1.2.643.7.1.2.1.1.1")`) with UKM = `01 00 00 00 00 00 00 00`. This exercises the `cofactor(c) = 4` branch and the `u = UKM * 4` path (still below Q, but the cofactor multiply is exercised). Pair it with `gostoracle.VKO2012_256OnCurve(...)` using the matching gogost curve.

2. **Large-UKM fuzz variant (or table test)** — for the modular-reduction branch to be differentially tested, UKM must be >= Q. For `tc26-256-A` (Q ≈ 255 bits), any 32-byte or larger UKM reaches the Mod. Add a table test using a fixed 32-byte UKM on the cofactor-4 curve. Generate the expected value with `gostoracle.VKO2012_256OnCurve(...)` and cross-check with the clean-room `vko.KEK2012256(c, ...)`. Both should agree (the group-theoretic equality holds), but if either implementation had a Mod-path bug, this test would catch it.

   Example seed entry for `FuzzDifferential` variant or a new `TestDifferentialLargeUKM`:
   ```go
   // ukm = 32 bytes, exceeds Q for tc26-256-A (~255 bits), triggering Mod in clean-room
   ukm32 := make([]byte, 32)
   ukm32[0] = 0x01 // non-zero
   copy(ukm32[1:], bytes.Repeat([]byte{0xff}, 31))
   ```
   Run both `vko.KEK2012256(c256A, dA32, QB32, ukm32)` and `gostoracle.VKO2012_256OnCurve(c256AOracle, dA32, QB32, ukm32)` and assert equality.

No changes needed to `vko.go` itself — the implementation is correct.

---

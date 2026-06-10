# Parity-audit remediation plan

Execution plan for the 75 confirmed findings of the 2026-06-10 parity-test review.
Companion document: **`docs/parity-audit-findings.md`** — the full machine-generated
findings reference. Every lane cites finding IDs (e.g. `MGM-02`); the implementer MUST
read the cited appendix sections before coding — they contain exact `file:line`
locations, the reviewer's evidence, the verifier's confirmation, and (for most) a
concrete suggested fix with code.

Unlike the `gostcrypto` audit, **every finding here is in test code**: this module is
the parity gate, so all work is adding/strengthening differential tests, fuzz
dimensions, and pinned external anchors in `parity/<prim>/`. **No primitive behaviour
changes anywhere.** Nothing in `../gostcrypto` or `../gostls` is edited.

This plan is written to be executed by subagents. Each **lane** is one subagent task,
scoped to a single `parity/<pkg>/` directory. The default implementer model is
**Sonnet**; two lanes are **Opus** because they must produce an independent external
KAT for a primitive whose oracle is *not* gogost (so the parity gate itself cannot
catch a wrong vector). The orchestrator dispatches per the wave schedule in §2.

---

## 1. Global rules — every implementer reads this first

These rules are binding for every lane. Violating any of them is a hard failure.

1. **Read `CLAUDE.md` in this module root** (`gostcrypto-compat`) before starting,
   plus the workspace root `CLAUDE.md` for the parity-gate and license-boundary
   context.
2. **License boundary (it runs the *opposite* way here).** This module is **GPL-3.0**
   and **may** import `go.stargrave.org/gogost/v7` — that is its entire purpose. The
   rule is: never let GPL code flow *out* into the BSD modules. Do **not** add a gogost
   import to `../gostcrypto` or `../gostls` "to make a test easier", and do **not**
   move any code from this module into them. All new code stays in `gostcrypto-compat`.
3. **No primitive behaviour changes.** These are coverage additions only. **Never edit
   clean-room code in `../gostcrypto` to make a parity test pass.** If a strengthened
   parity test reveals a genuine clean-room ≠ gogost divergence, that is a *gostcrypto*
   finding: **STOP and report it** (do not patch it here, do not weaken the test to
   hide it). Re-read `../gostcrypto/TODO.md` and `docs/engine-vectors.md` first — it may
   be a documented intentional divergence (S-box row order, R 34.11-94 empty-input
   finalization, CryptoPro key meshing), in which case it is **not** a finding.
4. **Build/test commands** (the harness sandbox blocks the Go build cache — pass
   `dangerouslyDisableSandbox: true` on Bash calls running go build/test/vet/fuzz):
   ```sh
   go build ./...                         # must stay green module-wide
   go vet ./...
   go test ./parity/<your-pkg>/           # during the lane (replays fuzz seeds)
   go test ./...                          # before your final commit
   make fuzz PKG=./parity/<your-pkg>/ FUZZTIME=1m   # shake new fuzz dimensions
   ```
   `../gostcrypto` must be checked out as a sibling (it is, via `replace`); gogost is
   vendored at `./third_party/gogost`.
5. **The parity gate is the referee.** Because no behaviour changes, `go test ./...`
   must stay **green throughout** — a new test going red means either your wiring is
   wrong or you found a real clean-room divergence (rule 3). It never means "weaken the
   assertion".
6. **Vectors are extracted, never invented.** Every new KAT byte string carries a
   citation comment: `tmp/engine/<path>:<line>` (the gitignored gost-engine 3.0.3
   clone), `<pkg>/rfc/<file>` where a package bundles its RFC/standard, `testdata/...`,
   or the exact tool command line that produced it (for gost-engine CLI output). When
   the appendix already contains verified hex, cite the *original* source it names
   (e.g. "RFC 9189 A.1.3.2"), not the appendix.
7. **The "oracle independence" caveat (license-driven, correctness-critical).** For
   five primitives the vendored gogost ships no equivalent mode, so the parity
   "oracle" is the in-repo `gostcryptocompat` facade — a *sibling* implementation, not
   an independent one: **ctracpkm, kdftree, omac, kexp15, keywrap** (see the cross-
   cutting note in the findings doc). When a finding for one of these asks for an
   independent anchor (KXP-01, KWP-01/02, KDF-02), that anchor **must** come from
   gost-engine or a published RFC vector — **never** from the clean-room or facade
   output (that would be circular). This is exactly why lanes L10/L11 are Opus.
8. **Dismissed findings are off-limits.** `docs/parity-audit-findings.md` lists 5
   dismissed findings under their packages with full reasoning. Do not implement them.
   Two confirmed findings were downgraded to `informational` (G89C-04, MAG-02) — treat
   them as optional notes, not required work (each lane says so).
9. **Fuzz hygiene.** When you add a fuzz parameter: update every `f.Add(...)` seed to
   match the new signature, add seeds that actually reach the newly-covered path
   (verify with `go test ./parity/<pkg>/` — seed replay must execute them), then run
   `make fuzz PKG=./parity/<pkg>/ FUZZTIME=1m` and confirm no new failure. A fuzz
   change that doesn't widen replayed coverage is incomplete.
10. **Commits.** One lane = 1–3 logical commits. Subject `parity/<pkg>: <imperative
    summary>`. Body ends with the finding IDs line: `Findings: MGM-01, MGM-02, MGM-03`.
    Never add `Co-Authored-By` / `Generated by` trailers (per workspace + user rules).
11. **Scope discipline.** Fix only what the cited findings say, only inside your
    `parity/<pkg>/` directory. No drive-by refactors, no touching sibling parity
    packages, no edits to the module-root `gostcryptocompat` facade or to
    `../gostcrypto`.

### 1.1 Anti-footgun rules — read twice, this is where parity tests go wrong

- **A parity test that passes is worthless if it isn't actually comparing.** The whole
  finding class here is "vacuous / one-shot / self-round-trip / fixed-dimension".
  After writing a new differential, *prove it bites*: temporarily perturb one input on
  one side (flip a byte, swap a curve) and confirm the test FAILS, then revert. A new
  assertion you never saw fail is suspect.
- **Never invent or "fix up" expected bytes.** Sources: hex in this plan or the
  findings appendix (already verified), a cited repo file (`rfc/*`, `tmp/engine/...`,
  `testdata/...`), or a recorded tool command. No other source exists.
- **When a new KAT fails, the expected bytes are presumed right and your wiring
  wrong.** Debug order: (1) byte order — GOST wire format is little-endian, RFC tables
  big-endian; (2) S-box / curve choice; (3) parameter order; (4) `../gostcrypto/TODO.md`
  for a documented divergence. If still failing: STOP and report. Do NOT edit the
  expected bytes, and do NOT touch `../gostcrypto`.
- **Never weaken, skip, or delete an existing assertion to get green.** If an existing
  parity test conflicts with your change, your change is wrong or the lane spec is —
  stop and report which.
- **Don't fuzz a dimension you don't also seed.** Adding a `variant byte` parameter
  without a seed that selects each variant means active fuzzing might reach it but seed
  replay (what CI runs) won't. Seed every branch.
- **If this plan contradicts the code you read** (a cited line moved, a named symbol
  doesn't exist), the code wins — report the discrepancy; don't guess.
- **The fix for a lying comment is to make it tell the truth** (relevant to SIG-01,
  CTRA-03, KDF-01, OMAC-01, KXP-02), not to change code to match the lie.
- **gogost gotchas are real** (see this module's `CLAUDE.md`): `gost28147.CTR`
  over-increments and is only valid for zero-key/zero-IV/n<1024 (L3);
  `gost28147.MAC.Sum` is destructive (L4); `TLSTree.DeriveCached` returns zero on first
  call when `seqNum>0` — prime with `Derive(0)` (L17); `KDF.Derive` only ever produces
  32 bytes (L8). Work *around* these in the oracle wiring; do not "fix" them.

---

## 2. Wave schedule (orchestrator instructions)

**Precondition:** commit the two new docs (`docs/parity-audit-findings.md`,
`docs/parity-audit-remediation.md`) first so lane commits stay reviewable. The rest of
the tree is clean.

Every lane touches **only its own `parity/<pkg>/` directory** — all 18 are disjoint,
so they run **fully in parallel in one wave**. No lane edits the shared module-root
`gostcryptocompat` package or `../gostcrypto`. If, mid-implementation, a lane concludes
it genuinely needs a *new* facade oracle symbol in the root package (a risk flagged for
L9 keg only), it must **STOP and report** rather than racing siblings on root files —
the orchestrator will schedule that follow-up alone.

| Wave | Lanes | Notes |
|---|---|---|
| **1** | L1 ctracpkm, L2 gost28147, L3 gost28147cnt, L4 gost28147imit, L5 gost3410curves, L6 gost3410sign, L7 gostr341194, L8 kdftree, L9 keg, L10 kexp15, L11 keywrap, L12 kuznyechik, L13 magma, L14 mgm, L15 omac, L16 streebog, L17 tlstree, L18 vko | All disjoint `parity/<pkg>/` dirs; full parallel. |
| **F** | LF final gate | Serial, after everything. |

Model per lane: **Opus** for **L10 (kexp15)** and **L11 (keywrap)** — each must
hand-produce an independent external KAT for a sibling-oracle primitive (rule 7), the
one place a wrong vector passes silently. **Sonnet** for every other lane and LF.

Subagent prompt template (orchestrator fills in lane ID):

> Work in `/Users/blikh/data/workspace/go-tlsdialer-workspace/gostcrypto-compat`.
> Execute lane **<ID>** of `docs/parity-audit-remediation.md` exactly as specified.
> First read §1 (global rules) of that doc, this module's `CLAUDE.md`, your lane's
> section, and the cited finding sections in `docs/parity-audit-findings.md`. Stay
> inside your own `parity/<pkg>/` directory; never edit `../gostcrypto` or the module-
> root facade. Build/test only your own package until the final commit. Pass
> `dangerouslyDisableSandbox: true` on Bash calls running go build/test/vet/fuzz.
> Commit per §1 rule 10. Report: what you changed, test results, the
> "prove-it-bites" result for each new differential, fuzz-smoke result, and any
> deviation from spec (especially any suspected clean-room divergence per rule 3).

---

## L1 — ctracpkm (Sonnet, Wave 1)

Findings: **CTRA-01, CTRA-02, CTRA-03, CTRA-04, CTRA-05, CTRA-06**. Oracle is the
in-repo facade (gogost has no CTR-ACPKM) — see rule 7.

1. **CTRA-04 + CTRA-01 — streaming is the headline gap.** Every comparison (table,
   plain-CTR, fuzz) is one-shot `XORKeyStream`, so the split-call / partial-gamma path
   — the exact failure mode that motivated the clean-room reimplementation — is
   unexercised. (a) Add a chunked-feeding dimension to `TestDiff_CTRACPKM_vs_Oracle`
   with split offsets crossing block and section boundaries; (b) add a fuzzer-chosen
   chunk schedule to `FuzzDiff_CTRACPKM_vs_Oracle`, driving **both** streams through
   the same schedule (mirror `parity/gost28147cnt`'s `chunkSeed`). Seed it.
2. **CTRA-02 — stop discarding ~94% of fuzz inputs.** The fuzzer `t.Skipf`s when
   `section` isn't a block multiple. Normalize it: derive `bs` from the cipher
   selector, set `section = (sectionRaw % k) * bs`, so almost every input exercises the
   clean-room.
3. **CTRA-05.** Plain-CTR parity (`NewCTR`) covers Kuznyechik only — add the Magma
   8-byte-block `NewCTR` leg.
4. **CTRA-06.** Add an in-place (`dst==src`) case to both the table test and the fuzz
   body.
5. **CTRA-03 — doc note.** Add a comment at the top of the parity test stating the
   oracle is the engine-KAT-anchored in-repo facade (`ctr_gost.go`), not gogost,
   because gogost v7 has no CTR/CTR-ACPKM. No code change beyond the comment.

**Acceptance:** `go test ./parity/ctracpkm/` green; new differentials proven to bite;
`make fuzz PKG=./parity/ctracpkm/ FUZZTIME=1m` clean.

---

## L2 — gost28147 (Sonnet, Wave 1)

Findings: **G89-01, G89-02, G89-03, G89-04**.

1. **G89-01 (medium) — real Decrypt parity.** The table test's "decrypt" check is an
   oracle self-round-trip. Replace it with a true diff: clean-room `Decrypt` vs the
   gogost oracle `Decrypt` on the same ciphertext.
2. **G89-02.** `SboxTC26Z` is never directly parity-diffed and TC26-Z `Decrypt` has no
   parity anywhere. The facade oracle hardcodes CryptoPro-A, so drive **gogost
   directly** with the TC26-Z S-box and add an ECB encrypt+decrypt differential for it.
3. **G89-03.** Add an S-box selector to `FuzzDiffGost28147` (CryptoPro-A / TC26-Z),
   wiring both sides to the chosen box. Seed both.
4. **G89-04.** Expand the two-entry seed corpus (add a committed `testdata` corpus or
   more `f.Add` seeds covering both S-boxes).

**Acceptance:** `go test ./parity/gost28147/` green; fuzz smoke clean.

---

## L3 — gost28147cnt (Sonnet, Wave 1)

Findings: **G89C-01, G89C-02, G89C-03**, and **G89C-04 (informational — optional)**.
Read this module's `CLAUDE.md` gogost-gotcha on `gost28147.CTR`: the gogost oracle is
only valid for zero-key / zero-IV / n<1024 — do not widen the gogost diff past that.

1. **G89C-01.** The engine-CLI helper conflates a real mid-run CLI failure with
   binary-unavailable, turning failures into silent skips. Split the two: `t.Skip` only
   when the binary genuinely isn't resolvable; `t.Fatal` on an invocation that should
   have worked.
2. **G89C-02.** No test crosses the ≥2048-byte (second+) CryptoPro meshing boundary.
   The gogost oracle can't reach there (n<1024 limit), so extend the **engine-CLI**
   differential (`TestDiff_GostEngineCLI`) with inputs ≥2049 bytes; if the engine
   binary is absent the test already skips.
3. **G89C-03.** tc26-Z parity depends entirely on the optional engine binary. Add a
   gogost-based tc26-Z differential *within* the valid zero-key/zero-IV/n<1024 regime
   (gogost CTR is correct there for tc26-Z too), so tc26-Z has an always-on anchor.
4. **G89C-04 (optional).** Widening the fuzz chunk schedule (>256 shapes, chunks >13B)
   and fuzzing the S-box is a nice-to-have; the clean-room module's own oracle-free
   `FuzzSplitInvariance` already covers fuzzed key/IV/sbox. Do only if cheap.

**Acceptance:** `go test ./parity/gost28147cnt/` green (engine legs skip cleanly when
no binary); fuzz smoke clean.

---

## L4 — gost28147imit (Sonnet, Wave 1)

Findings: **G89I-01, G89I-02, G89I-03, G89I-04**. Read this module's `CLAUDE.md` on
`gost28147.MAC.Sum` destructiveness before wiring the oracle.

1. **G89I-01 (medium) — cover SeqMACBlock.** The TLS record-layer building block has
   zero differential coverage despite a gogost-backed facade mirror existing. Add a
   `SeqMACBlock` differential vs the facade `GOST28147Cipher.SeqMACBlock` over random
   keys and blocks, for **both** S-boxes (it has a fuzzable S-box that IMIT hardcodes
   to CryptoPro-A).
2. **G89I-02.** The fuzz target skips on oracle error, masking oracle-only failures.
   Make divergence visible: assert the clean-room side's accept/reject matches the
   oracle's instead of silently skipping (keep the documented empty-input skip — that's
   intentional, see imit.go).
3. **G89I-03 — doc note.** State that the mesh/finalization wrapper is same-author code
   whose independence rests on the root-package gost-engine vector tests; cross-
   reference them in a comment.
4. **G89I-04.** No fuzz seed reaches the 1024-byte CryptoPro meshing path — add a seed
   with a ≥1024-byte message.

**Acceptance:** `go test ./parity/gost28147imit/` green; fuzz smoke clean.

---

## L5 — gost3410curves (Sonnet, Wave 1)

Findings: **CRV-01, CRV-02, CRV-03, CRV-04, CRV-05, CRV-06**. The vendored gogost
exposes `P/Q/A/B/X/Y/Co` and `Curve.Equal`/`Contains` — use them as the oracle.

1. **CRV-01 (medium) — constants + IsOnCurve.** Coefficient **B**, **Cofactor**, and
   `IsOnCurve` have zero parity coverage. Add `TestCurveConstantsDifferential`: for
   each of the 10 OIDs, diff the clean-room `Curve` (P, A, B, Q, X, Y, Cofactor) against
   the gogost reference curve, and diff `IsOnCurve` against gogost `Contains` over both
   on-curve and off-curve points.
2. **CRV-02.** `TestCrossCheckInternalGost` compares only `PointSize` + name-non-empty
   — fold it into CRV-01's real constant diff (or strengthen it to assert the full
   constant set). Note the documented name alias divergence (`...3410-2012-512...` vs
   `...3410-12-512...`) so the name check stays correct.
3. **CRV-03.** `FuzzScalarMult` skips asymmetrically when gogost rejects a key — assert
   the clean-room side rejects too.
4. **CRV-04.** `helpers_test.go` declares an expected `pointSize` per OID but never
   asserts it — assert it.
5. **CRV-05.** Diff `Add`/`Double` on arbitrary (non-base) points and their edge
   branches (the k·G path alone never reads B).
6. **CRV-06.** Add boundary-scalar seeds (0, 1, q−1, q, q+1) and a committed corpus to
   `FuzzScalarMult`.

**Acceptance:** `go test ./parity/gost3410curves/` green; constant diff proven to bite;
fuzz smoke clean.

---

## L6 — gost3410sign (Sonnet, Wave 1)

Findings: **SIG-01, SIG-02, SIG-03, SIG-04**. gogost is the oracle for both 256- and
512-bit curves.

1. **SIG-01 (medium) — byte-compare the sign path.** Fixed-nonce signatures are
   provably byte-identical, yet the sign output is never byte-compared and the
   justifying comment is **false**. Add `bytes.Equal(refSig, newSig)` on the
   deterministic path and **fix the lying comment**.
2. **SIG-02 (medium) — 512-bit parity.** Only the 256-bit 2001 `TestParamSet` is
   exercised; add 512-bit (PointSize=64) parity: a pinned KAT (port the GOST R
   34.10-2012 512 example, cite source) plus cross-verify.
3. **SIG-03.** Add negative-path parity: malformed / out-of-range signatures, wrong
   lengths, off-curve public keys — assert clean-room and oracle agree on rejection.
4. **SIG-04.** `FuzzCrossVerify` clamps every input to exactly 32 bytes — vary digest
   length, key length, and curve (seed each).

**Acceptance:** `go test ./parity/gost3410sign/` green; sign-byte diff proven to bite;
fuzz smoke clean.

---

## L7 — gostr341194 (Sonnet, Wave 1)

Findings: **R94-01, R94-02, R94-03, R94-04**. Keep seeding non-empty inputs only — the
empty-input finalization divergence is documented (`docs/engine-vectors.md`).

1. **R94-01.** Add `Reset()` / instance-reuse parity vs the oracle.
2. **R94-02.** Add non-destructive `Sum` parity (guide D8): `Sum` twice, keep writing,
   diff against the oracle.
3. **R94-03.** `Sum(in)` is always called with `nil` — add a non-nil append-prefix case
   and diff.
4. **R94-04.** The fuzz streaming path uses exactly one split — make the number/offsets
   of `Write` calls fuzzer-chosen (mirror `parity/streebog`/`omac` `split` param).

**Acceptance:** `go test ./parity/gostr341194/` green; fuzz smoke clean.

---

## L8 — kdftree (Sonnet, Wave 1)

Findings: **KDF-01, KDF-02, KDF-03, KDF-04, KDF-05**. Oracle is the in-repo facade
(rule 7); the RFC 7836 vector is the only independent anchor. Note the `KDF.Derive`
32-byte gotcha (this module's `CLAUDE.md`).

1. **KDF-02 — independent anchor.** The 32-byte case omits the authoritative RFC 7836
   pin (`want=""`). Port the RFC 7836 Appendix B multi-block vector from the bundled
   `kdftree/rfc/rfc7836.txt` (example 9/10 — the 64-byte K1‖K2 case) and pin
   `KDFTree256(K_in, label, seed, 1, 64) == K1‖K2`. **TRAP:** `[L]_b` is in every HMAC
   message, so the 64-byte vector does NOT pin the 32-byte output — see the appendix.
2. **KDF-01 — doc note.** State the primary oracle is a same-project reimplementation;
   multi-block independence now rests on the KDF-02 RFC KAT.
3. **KDF-03.** Exercise counter width r=2..4, outLen>64 (counter ≥ 3), and truncation
   to non-multiples of 32 in the parity tests.
4. **KDF-04.** Committed fuzz seeds never replay the 64-byte multi-block path
   (`lenSel&1` maps seed 64→keyOutLen 32) — fix the seed so the multi-block path is
   actually replayed.
5. **KDF-05.** `FuzzKDFTree256Conformance` forces HMAC key length to 32 and output to
   {32,64} — vary both.

**Acceptance:** `go test ./parity/kdftree/` green; RFC KAT proven to bite; fuzz smoke
clean.

---

## L9 — keg (Sonnet, Wave 1)

Findings: **KEG-01, KEG-02, KEG-03, KEG-04, KEG-05, KEG-06**. **Risk flag:** if making
the curve real requires the *oracle* (`keg_gost.go`, module root) to accept a curve
param, that's a root-package edit — **STOP and report** (see §2) rather than racing
other lanes; prefer driving gogost directly from the parity test if possible.

1. **KEG-01 (medium) — multi-curve coverage.** Every clean-room call passes `nil`
   (TC26 256-A only). Add a differential that walks the non-default 256-bit OIDs,
   resolving the curve through each module's own registry (clean-room via
   `gost3410curves.CurveByOID`; oracle via gogost), and diffs each.
2. **KEG-02 (medium).** `FuzzKEG2012_256_DiffOracle` hardcodes the curve — add a
   `curveIdx byte` selecting among the supported 256-bit OIDs. Seed each.
3. **KEG-03.** The zero-UKM special-case branch has no independent anchor (both sides
   co-developed). Pin it with a reference-derived vector (see the appendix for how the
   reference computes it).
4. **KEG-04.** Fuzz skips on oracle KEG error before running the clean-room side — run
   the clean-room side too and assert symmetric accept/reject.
5. **KEG-05.** Add error-path parity (wrong-length / off-curve pub key, bad priv key).
6. **KEG-06.** Key material is always laundered through the oracle's generator; feed
   raw fuzzer bytes to the pub/priv inputs so the fuzzer actually drives them.

**Acceptance:** `go test ./parity/keg/` green; multi-curve diff proven to bite; fuzz
smoke clean.

---

## L10 — kexp15 (**Opus**, Wave 1)

Findings: **KXP-01, KXP-02, KXP-03, KXP-04**. Oracle's OMAC/CTR/composition layers are
*not* gogost (only the block ciphers are) — rule 7. **Opus because KXP-01 is the only
independent anchor and a wrong vector passes silently.**

1. **KXP-01 (medium) — independent Kuznyechik vector.** There is no independent pinned
   vector for the Kuznyechik variant. Add a deterministic KAT from **RFC 9189 A.1.3.2**
   (the bundled RFC already supplies the value the Magma path uses) — extract with a
   line citation, wire it, and confirm it matches. This is the external anchor the
   sibling oracle can't provide.
2. **KXP-02 — doc note.** State that only the block ciphers are independently sourced;
   the OMAC/CTR composition is facade-side.
3. **KXP-03.** Add error-path parity: invalid key/IV lengths, empty shared key, unknown
   variant — clean-room vs oracle agree on rejection.
4. **KXP-04.** Single Magma-only fuzz seed — add a Kuznyechik-variant seed and an OMAC
   complete-final-block (K1) seed.

**Acceptance:** `go test ./parity/kexp15/` green; RFC KAT proven to bite; fuzz smoke
clean.

---

## L11 — keywrap (**Opus**, Wave 1)

Findings: **KWP-01, KWP-02, KWP-03, KWP-04, KWP-05**. KEK diversification and wrap
assembly are project-written on *both* sides — rule 7. **Opus because KWP-01/02 require
hand-producing a gost-engine CryptoPro-A KAT, the only independent anchor.**

1. **KWP-01 (medium) + KWP-02 — independent anchor + use the real oracle.** Pin a
   CryptoPro-A KAT generated from gost-engine 3.0.3 (`keyWrapCryptoPro`, `sbox=
   CryptoPro-A`) on the same KAT inputs already in `helpers_test.go` (`katKEK`,
   `katUKM`, `katSession`) — record the exact command line. Separately, wire the
   **genuinely-gogost** `UnwrapCryptoPro` round-trip oracle (currently unused) as a
   real differential check.
2. **KWP-03.** Exported `Diversify` is never parity-tested though its intermediate KAT
   constants sit unused in `helpers_test.go` — add the differential and consume them.
3. **KWP-04.** Add error-path parity (wrong kek/ukm/cek lengths).
4. **KWP-05.** Fuzz seed corpus is two identical-input seeds and only covers wrap — add
   varied seeds and cover the unwrap entry point.

**Acceptance:** `go test ./parity/keywrap/` green; engine KAT proven to bite; fuzz smoke
clean.

---

## L12 — kuznyechik (Sonnet, Wave 1)

Findings: **KUZ-01, KUZ-02**.

1. **KUZ-01.** `TestDiffKAT` doesn't diff `Decrypt` on the pinned RFC 7801 vector nor
   anchor the literal expected ciphertext — add the Decrypt diff and cite the RFC 7801
   ciphertext explicitly.
2. **KUZ-02.** `FuzzDiffKuznyechik` never exercises in-place (`dst==src`) — add it.

**Acceptance:** `go test ./parity/kuznyechik/` green; fuzz smoke clean.

---

## L13 — magma (Sonnet, Wave 1)

Findings: **MAG-01**, and **MAG-02 (informational — do not implement as parity)**.

1. **MAG-01.** The cipher object API (instance reuse, `dst==src` aliasing) is never
   exercised by parity — add it.
2. **MAG-02 (informational).** Invalid-length rejection shapes differ between clean-
   room and oracle **by design**; do **not** add a parity assertion for it. Optionally
   leave a one-line comment noting the intentional shape difference.

**Acceptance:** `go test ./parity/magma/` green.

---

## L14 — mgm (Sonnet, Wave 1)

Findings: **MGM-01, MGM-02, MGM-03**.

1. **MGM-01 (medium) — truncated-tag parity.** Tag size is hardcoded to the full block;
   truncated tags (4..blockSize−1) are never differentially tested. Derive a per-variant
   `tagSize` from the fuzz selector (`minTagSize=4`; blockSizes 8 and 16) and add table
   cases.
2. **MGM-02 (medium) — dead Kuznyechik fuzz arm.** Both fuzz seeds select Magma, so the
   Kuznyechik arm is dead under seed replay and the RFC Kuznyechik seed is mangled. Make
   the first `f.Add` use an odd `sel` (Kuznyechik) and fix the seed bytes.
3. **MGM-03.** `Open` is never run against the gogost oracle and there's no forgery-
   rejection case — add Open parity and a flipped-tag rejection diff.

**Acceptance:** `go test ./parity/mgm/` green; Kuznyechik arm proven live; fuzz smoke
clean.

---

## L15 — omac (Sonnet, Wave 1)

Findings: **OMAC-01, OMAC-02, OMAC-03, OMAC-04, OMAC-05**. Oracle is a sibling CMAC
reimplementation (rule 7).

1. **OMAC-01 — doc note.** State the oracle is a sibling reimplementation; CMAC mode
   logic is effectively self-compared; independence rests on engine KATs.
2. **OMAC-02.** Tag truncation parity exists only at two fixed widths — sweep widths and
   pin tagSize-out-of-range semantics.
3. **OMAC-03.** Add `Sum` non-destructiveness and Write-after-`Sum` continuation
   differentials.
4. **OMAC-04.** `FuzzDiffAgainstGost` hardcodes tagSize to full block — fuzz it.
5. **OMAC-05.** Streaming coverage is a single 2-way split on the clean-room side — make
   splits fuzzer-chosen and add a partial-final-block seed.

**Acceptance:** `go test ./parity/omac/` green; fuzz smoke clean.

---

## L16 — streebog (Sonnet, Wave 1)

Findings: **STB-01, STB-02, STB-03**.

1. **STB-01.** Add `Reset`/reuse and `Sum`-non-destructiveness parity.
2. **STB-02.** The New256 streaming path is never diffed and the oracle streaming hashes
   are unused — add a New256 streaming differential.
3. **STB-03.** Fuzz streams only the 512 variant with a single split — add the 256
   variant and a fuzzer-chosen multi-split.

**Acceptance:** `go test ./parity/streebog/` green; fuzz smoke clean.

---

## L17 — tlstree (Sonnet, Wave 1)

Findings: **TLS-01, TLS-02, TLS-03**. Note the `TLSTree.DeriveCached` gotcha (this
module's `CLAUDE.md`): prime with `Derive(0)` before a `seqNum>0` cached call.

1. **TLS-01.** Constructor error-path parity (non-32-byte master panic) is not
   exercised — add it.
2. **TLS-02.** `Fuzz_TLSTree_Conformance` never varies the number/order of `Derive`
   calls — make the call sequence fuzzer-chosen so the cache path is exercised.
3. **TLS-03.** Seed corpus anchors only level-3 (C3) boundaries — add level-1 and
   level-2 boundary seeds.

**Acceptance:** `go test ./parity/tlstree/` green; fuzz smoke clean.

---

## L18 — vko (Sonnet, Wave 1)

Findings: **VKO-01, VKO-02, VKO-03, VKO-04, VKO-05**.

1. **VKO-01 (medium) — cofactor-4 live parity.** Cofactor-4 curves (tc26-256-A,
   tc26-512-C) never run through live parity — add a cofactor-4 leg diffing against the
   oracle (resolve via `gost3410curves.CurveByOID`).
2. **VKO-02 (medium) — fuzz all variants.** Fuzz covers only VKO2012_256 on
   512-paramSetA; VKO2001 (GOSTR341194 path, 256-bit curve) and VKO2012_512 get fixed
   KATs only. Add a `variant byte` dispatching `variant%3` across v2001 / v2012_256 /
   v2012_512. Seed each.
3. **VKO-03.** Fuzz swallows clean-room errors one-directionally — assert symmetric
   accept/reject so a false-reject regression fails instead of silently zeroing
   coverage.
4. **VKO-04.** Base-point derivation (`DeriveQLE`) is never diffed against gogost — add
   it (a self-consistent base-mult bug currently passes parity).
5. **VKO-05.** UKM is pinned to 8 bytes — vary it to exercise the mod-fullOrder
   reduction branch.

**Acceptance:** `go test ./parity/vko/` green; cofactor-4 + variant fuzz proven to bite;
fuzz smoke clean.

---

## LF — Final gate (Sonnet, after everything)

1. Full module: `go build ./... && go vet ./... && go test -count=1 ./...` (green).
2. Fuzz smoke on every package that gained a dimension:
   `make fuzz PKG=./parity/<pkg>/ FUZZTIME=30s` for L1, L2, L4, L5, L6, L7, L8, L9,
   L10, L12, L14, L15, L16, L17, L18 (each must end clean — no new crashers).
3. Lint: `make lint` (golangci-lint).
4. **License-boundary check:** `git -C ../gostcrypto status --short` and
   `git -C ../gostls status --short` must be **clean** — no parity-lane edit may have
   leaked into the BSD modules (rule 2/3). Report if not.
5. **Independent-anchor audit:** confirm every new KAT (KXP-01, KWP-01/02, KDF-02,
   SIG-02, KEG-03) cites gost-engine / RFC / testdata provenance, not clean-room or
   facade output (rule 7). Update `docs/engine-vectors.md` with each newly-ported
   vector (which file it landed in, source line).
6. Report: per-lane commit list, test/lint results, the "prove-it-bites" outcome per
   new differential, any finding *not* fully addressed with the reason, and any
   suspected clean-room divergence surfaced (rule 3) routed to a `gostcrypto` issue.

---

## Quick reference — finding → lane map

| Lane | Model | Wave | Findings |
|---|---|---|---|
| L1 ctracpkm | Sonnet | 1 | CTRA-01..06 |
| L2 gost28147 | Sonnet | 1 | G89-01..04 |
| L3 gost28147cnt | Sonnet | 1 | G89C-01..03 (G89C-04 optional) |
| L4 gost28147imit | Sonnet | 1 | G89I-01..04 |
| L5 gost3410curves | Sonnet | 1 | CRV-01..06 |
| L6 gost3410sign | Sonnet | 1 | SIG-01..04 |
| L7 gostr341194 | Sonnet | 1 | R94-01..04 |
| L8 kdftree | Sonnet | 1 | KDF-01..05 |
| L9 keg | Sonnet | 1 | KEG-01..06 |
| L10 kexp15 | **Opus** | 1 | KXP-01..04 |
| L11 keywrap | **Opus** | 1 | KWP-01..05 |
| L12 kuznyechik | Sonnet | 1 | KUZ-01..02 |
| L13 magma | Sonnet | 1 | MAG-01 (MAG-02 informational) |
| L14 mgm | Sonnet | 1 | MGM-01..03 |
| L15 omac | Sonnet | 1 | OMAC-01..05 |
| L16 streebog | Sonnet | 1 | STB-01..03 |
| L17 tlstree | Sonnet | 1 | TLS-01..03 |
| L18 vko | Sonnet | 1 | VKO-01..05 |
| LF final gate | Sonnet | F | — |

Dismissed (do NOT act): SIG fuzz-skip masking claim, R94 "no committed corpus",
KUZ malformed-input parity, MGM AEAD-reuse, TLS sequential-reuse parity — see the
findings doc per-package "Dismissed" sections.

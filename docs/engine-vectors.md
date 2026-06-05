# gost-engine v3.0.3 vector port

Source: `tmp/engine/` (tag v3.0.3, commit e0a500a). Not committed to this repo.

## test/01-digest.t + tcl_tests/dgst.try

Ported: 7 Streebog-256, 7 Streebog-512, 5 GOST R 34.11-94 vectors.
Also ported from tcl_tests/mac.try: 1 HMAC-Streebog-512, 1 HMAC-GOST R 34.11-94.
All live in `engine_hash_vectors_test.go`.

Skipped: GOSTR341194 empty-input vector (see Disagreements below).

Surprises / fixes:
- The carry-propagation test vector (dgst_CF.dat / `etalon/carry`) was originally
  hardcoded as 130 bytes in the test file instead of the correct 128 bytes. The
  error was 64×0xEE + 0x16 + **64**×0x11 + 0x16 (wrong) vs
  64×0xEE + 0x16 + **62**×0x11 + 0x16 (correct per `etalon/carry`).
  Corrected and all carry vectors now pass.

## test/02-mac.t + tcl_tests/mac.try

Ported to `primitives_engine_vectors_test.go`:
- gost-mac (SboxDefault = CryptoPro-A): 9 vectors — sizes 1–8 bytes (testdata.dat).
- gost-mac-12 (tc26-Z): 8 vectors — sizes 1–8 bytes (testdata.dat).

Skipped: `mac.try` gost-mac vectors (key `12345678901234567890123456789012`): expected
`37f646d2` for dgst.dat does not match any S-box in our library. Key encoding or
S-box selection differs from the `02-mac.t` key (`0123456789abcdef0123456789abcdef`).
Skipped: magma-mac and kuznyechik-mac (OMAC/CMAC) — out of scope.

Previously a disagreement on testbig.dat (266240 bytes, `5efab81f` vs `383059e8`) —
resolved 2026-04-20 by reimplementing `GOST28147_IMIT` with CryptoPro key meshing
(RFC 4357 §2.3.2, engine ref: `gost_crypt.c:1510-1524`). Validated by
`TestGost_GOST28147_IMIT_Wrapper_KeyMeshing`. gogost's raw `gost28147.MAC` still
lacks meshing, so that vector remains skipped in the raw-MAC loop.

## test/03-encrypt.t

Ported to `primitives_engine_vectors_test.go`:
- gost89-cnt (CryptoPro-A S-box): 2 vectors (paramset argument confirmed to have no effect).
- gost89-cnt-12 (tc26-Z S-box): 2 vectors.

Skipped: CFB mode (gost89 with paramset A/B/C/D) — not used in our TLS suites.
Skipped: CBC mode (gost89-cbc with paramset A/B/C/D) — not used in our TLS suites.
Skipped: magma-ctr (from tcl_tests/enc.try) — no Magma CTR wrapper in our primitives layer.

## test/04-pkey.t

Ported to `primitives_pkey_vectors_test.go`:
- R 34.10-2001 verify KAT using RFC 7091 §A.1 TestParamSet vector (1 PASS).
- R 34.10-2001 sign+verify round-trip via R341012Sign wrapper (1 PASS).
- Tamper-rejection check (1 PASS).

Skipped: all pkey 'keys' subtest vectors — text-output matching of PEM/DER key fields;
no raw cryptographic KAT extractable.

Skipped: all VKO 'derive' subtest vectors — expected values are sha256(DER-encoded
derived key), not raw shared-key bytes. Private keys are PEM-encoded; extracting the
LE raw bytes requires ASN.1 DER parsing outside the scope of this porting task.

Skipped: R 34.10-2012-512 sign/verify — our Phase-1 wrapper exposes only 256-bit sign.

## Problems / disagreements

1. **GOSTR341194 empty-input** (`tcl_tests/dgst.try:87`): engine `3f25bc1f...`,
   gogost `981e5f3c...`. Root cause (2026-04-20): empty-input finalization differs.
   Engine's `finish_hash` at `gosthash.c:257-258` runs an extra
   `hash_step(H, zero_block)` when `fin_len == 0`; gogost's `Sum` does not.
   S-box bytes are equivalent; all 5 non-empty vectors pass. TLS PRF uses
   HMAC (never empty input), so this mismatch is benign for the TLS use case.
   Fix would require reimplementing GOST R 34.11-94 locally — deferred.

2. ~~**IMIT on large data**~~ — resolved. See `test/02-mac.t` section above.

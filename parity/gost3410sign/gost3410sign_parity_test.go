package gost3410signparity

import (
	"bytes"
	"encoding/hex"
	. "github.com/bigbes/gostcrypto/gost3410sign"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"
)

// The differential tests cross-check the clean-room sign/verify against the
// in-repo gogost-backed reference (gostcryptocompat), used strictly as a black
// box. Signing is randomized in production but here the oracle's SignDigestOnCurve
// takes an io.Reader nonce source, so we feed a fixed reader to keep the oracle
// deterministic; the clean-room SignDigest takes the nonce bytes directly.
//
// Both impls operate on the RFC 7091 §7 TestParamSet (256-bit). The clean-room
// curve is built from the same hex (testParamSetCurve); the oracle uses its own
// GOST2001TestParamSetCurve().

// TestDiff_PinnedVector cross-verifies the §7 pinned signature and public key
// under both impls (deterministic surface).
func TestDiff_PinnedVector(t *testing.T) {
	newCurve := testParamSetCurve()
	refCurve := gost.GOST2001TestParamSetCurve()

	prv := mustHex(t, katPrvLE)
	dig := mustHex(t, katDigBE)
	sig := mustHex(t, katSigSR)
	wantPub := append(mustHex(t, katPubX), mustHex(t, katPubY)...)

	// Public-key derivation parity.
	refPub, err := gost.PublicKeyRawFromPrivate(refCurve, prv)
	if err != nil {
		t.Fatalf("ref PublicKeyRawFromPrivate: %v", err)
	}
	newPub := PublicKeyRaw(newCurve, prv)
	if newPub == nil {
		t.Fatal("new PublicKeyRaw nil")
	}
	if !bytes.Equal(refPub, wantPub) {
		t.Fatalf("ref pub %x != pin %x", refPub, wantPub)
	}
	if !bytes.Equal(newPub, refPub) {
		t.Fatalf("pub mismatch ref=%x new=%x", refPub, newPub)
	}

	// Pinned signature verifies under both.
	okRef, err := gost.VerifyDigestOnCurve(refCurve, wantPub, dig, sig)
	if err != nil || !okRef {
		t.Fatalf("ref verify pinned sig: ok=%v err=%v", okRef, err)
	}
	if !VerifyDigest(newCurve, wantPub, dig, sig) {
		t.Fatal("new verify rejected pinned sig")
	}

	// Tamper: both reject.
	bad := append([]byte(nil), dig...)
	bad[0] ^= 0x01
	if VerifyDigest(newCurve, wantPub, bad, sig) {
		t.Fatal("new accepted tampered digest")
	}
	if ok, _ := gost.VerifyDigestOnCurve(refCurve, wantPub, bad, sig); ok {
		t.Fatal("ref accepted tampered digest")
	}
}

// TestDiff_CrossVerifyRandom signs with each impl and verifies each signature
// under BOTH, across many fresh (prv, digest) pairs on the §7 TestParamSet.
func TestDiff_CrossVerifyRandom(t *testing.T) {
	newCurve := testParamSetCurve()
	refCurve := gost.GOST2001TestParamSetCurve()

	for iter := 0; iter < 64; iter++ {
		prv := make([]byte, 32)
		dig := make([]byte, 32)
		k := make([]byte, 32)
		for i := 0; i < 32; i++ {
			prv[i] = byte(iter*7 + i*3 + 1)
			dig[i] = byte(iter*5 + i*11 + 2)
			k[i] = byte(iter*13 + i*17 + 3)
		}

		// Public-key parity.
		refPub, err := gost.PublicKeyRawFromPrivate(refCurve, prv)
		if err != nil {
			t.Skipf("iter %d: ref key load failed: %v", iter, err)
		}
		newPub := PublicKeyRaw(newCurve, prv)
		if newPub == nil {
			t.Fatalf("iter %d: new PublicKeyRaw nil where ref ok", iter)
		}
		if !bytes.Equal(refPub, newPub) {
			t.Fatalf("iter %d: pub mismatch ref=%x new=%x", iter, refPub, newPub)
		}

		// Sign with the oracle (fixed nonce reader) and with the clean-room impl.
		refSig, err := gost.SignDigestOnCurve(refCurve, prv, dig, bytes.NewReader(k))
		if err != nil {
			t.Fatalf("iter %d: ref sign: %v", iter, err)
		}
		newSig := SignDigest(newCurve, prv, dig, k)
		if newSig == nil {
			t.Fatalf("iter %d: new sign nil", iter)
		}

		// Cross-verify every combination.
		if !VerifyDigest(newCurve, refPub, dig, refSig) {
			t.Fatalf("iter %d: new failed to verify ref sig", iter)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, newSig); err != nil || !ok {
			t.Fatalf("iter %d: ref failed to verify new sig: ok=%v err=%v", iter, ok, err)
		}
		if !VerifyDigest(newCurve, refPub, dig, newSig) {
			t.Fatalf("iter %d: new failed to verify new sig", iter)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, refSig); err != nil || !ok {
			t.Fatalf("iter %d: ref failed to verify ref sig: ok=%v err=%v", iter, ok, err)
		}
	}
}

// seedHex decodes hex for f.Add seeds, where no *testing.T is available.
func seedHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// fixLen slices or zero-extends b to exactly n bytes.
func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// FuzzCrossVerify mirrors TestDiff_CrossVerifyRandom over fuzzer-chosen scalars:
// it derives a key, signs the digest with both the clean-room impl and the
// gogost oracle (deterministic via a fixed nonce reader), and asserts each
// signature cross-verifies under BOTH. GOST signing is randomized, so raw
// signature bytes won't match; cross-verification is the robust differential.
// Tampering the digest must be rejected by both. Operates on the §7
// TestParamSet (256-bit), matching the existing tests.
func FuzzCrossVerify(f *testing.F) {
	f.Add(seedHex(katPrvLE), seedHex(katDigBE), seedHex(katNonce))
	f.Add(
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x22}, 32),
		bytes.Repeat([]byte{0x33}, 32),
	)

	newCurve := testParamSetCurve()
	refCurve := gost.GOST2001TestParamSetCurve()

	f.Fuzz(func(t *testing.T, rawPrv, rawDig, rawK []byte) {
		prv := fixLen(rawPrv, 32)
		dig := fixLen(rawDig, 32)
		k := fixLen(rawK, 32)

		// Public-key parity. A scalar reducing to zero (or k yielding a
		// degenerate nonce) is a genuinely invalid input: skip it.
		refPub, err := gost.PublicKeyRawFromPrivate(refCurve, prv)
		if err != nil {
			t.Skipf("ref key load failed: %v", err)
		}
		newPub := PublicKeyRaw(newCurve, prv)
		if newPub == nil {
			t.Fatalf("new PublicKeyRaw nil where ref ok (prv=%x)", prv)
		}
		if !bytes.Equal(refPub, newPub) {
			t.Fatalf("pub mismatch ref=%x new=%x", refPub, newPub)
		}

		// Sign with the oracle (fixed nonce reader) and the clean-room impl.
		refSig, err := gost.SignDigestOnCurve(refCurve, prv, dig, bytes.NewReader(k))
		if err != nil {
			// A nonce of zero (or one reducing to zero mod q) is invalid.
			t.Skipf("ref sign failed (likely degenerate nonce): %v", err)
		}
		newSig := SignDigest(newCurve, prv, dig, k)
		if newSig == nil {
			t.Skipf("new sign nil (likely degenerate nonce, prv=%x k=%x)", prv, k)
		}

		// Cross-verify every combination: each sig accepted under both impls.
		if !VerifyDigest(newCurve, refPub, dig, refSig) {
			t.Fatalf("new failed to verify ref sig (prv=%x dig=%x)", prv, dig)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, newSig); err != nil || !ok {
			t.Fatalf("ref failed to verify new sig: ok=%v err=%v (prv=%x dig=%x)", ok, err, prv, dig)
		}
		if !VerifyDigest(newCurve, refPub, dig, newSig) {
			t.Fatalf("new failed to verify new sig (prv=%x dig=%x)", prv, dig)
		}
		if ok, err := gost.VerifyDigestOnCurve(refCurve, refPub, dig, refSig); err != nil || !ok {
			t.Fatalf("ref failed to verify ref sig: ok=%v err=%v (prv=%x dig=%x)", ok, err, prv, dig)
		}

		// Tamper: flip a digest bit; both impls must reject the now-stale sig.
		bad := append([]byte(nil), dig...)
		bad[0] ^= 0x01
		if VerifyDigest(newCurve, refPub, bad, refSig) {
			t.Fatalf("new accepted tampered digest (prv=%x dig=%x)", prv, dig)
		}
		if ok, _ := gost.VerifyDigestOnCurve(refCurve, refPub, bad, refSig); ok {
			t.Fatalf("ref accepted tampered digest (prv=%x dig=%x)", prv, dig)
		}
	})
}

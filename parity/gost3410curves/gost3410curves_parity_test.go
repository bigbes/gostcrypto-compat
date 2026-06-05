package gost3410curvesparity

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"
	"github.com/bigbes/gostcrypto/gost3410sign"
)

// oidToASN1 parses a dotted-decimal OID string into an asn1.ObjectIdentifier.
func oidToASN1(t *testing.T, s string) asn1.ObjectIdentifier {
	t.Helper()
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n := 0
		for _, ch := range p {
			n = n*10 + int(ch-'0')
		}
		oid[i] = n
	}
	return oid
}

// Cross-check OID->PointSize against the gogost-backed gostcryptocompat as a
// black box (it does not expose raw integers). We compare PointSize and assert
// both resolutions succeed and agree on the family size.
func TestCrossCheckInternalGost(t *testing.T) {
	for _, tc := range allOIDs {
		t.Run(tc.name, func(t *testing.T) {
			mine := mustCurve(t, tc.oid)

			ref, err := gost.CurveByOID(oidToASN1(t, tc.oid))
			if err != nil {
				t.Fatalf("gostcryptocompat.CurveByOID(%s): %v", tc.oid, err)
			}
			if mine.PointSize() != ref.PointSize() {
				t.Fatalf("%s: PointSize mine=%d gogost=%d",
					tc.name, mine.PointSize(), ref.PointSize())
			}
			if ref.Name() == "" {
				t.Fatalf("%s: gogost returned empty name", tc.name)
			}
			t.Logf("%s: gogost name=%q PointSize=%d", tc.name, ref.Name(), ref.PointSize())
		})
	}
}

// fixLen slices or zero-extends b to exactly n bytes.
func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// FuzzScalarMult exercises the clean-room curve point arithmetic (ScalarMult of
// the base point, via PublicKeyRaw) against the gogost oracle byte-for-byte over
// a fuzzer-chosen scalar and a fuzzer-selected standard OID curve. Public-key
// derivation is scalar·Base, so a match proves the point-operation outputs agree
// across all standard param-set curves. The scalar is raw LE, sized to the
// curve's PointSize; a scalar reducing to zero is a genuinely invalid input
// (no public key) and is skipped.
func FuzzScalarMult(f *testing.F) {
	f.Add(0, []byte{
		0x28, 0x3b, 0xec, 0x91, 0x98, 0xce, 0x19, 0x1d, 0xee, 0x7e, 0x39, 0x49,
		0x1f, 0x96, 0x60, 0x1b, 0xc1, 0x72, 0x9a, 0xd3, 0x9d, 0x35, 0xed, 0x10,
		0xbe, 0xb9, 0x9b, 0x78, 0xde, 0x9a, 0x92, 0x7a,
	})
	f.Add(3, bytes.Repeat([]byte{0x42}, 32))
	f.Add(7, bytes.Repeat([]byte{0x11}, 64))

	f.Fuzz(func(t *testing.T, sel int, rawPrv []byte) {
		// Pick a standard OID curve deterministically from sel.
		idx := sel % len(allOIDs)
		if idx < 0 {
			idx += len(allOIDs)
		}
		oid := allOIDs[idx].oid

		mine := mustCurve(t, oid)
		ref, err := gost.CurveByOID(oidToASN1(t, oid))
		if err != nil {
			t.Fatalf("gogost CurveByOID(%s): %v", oid, err)
		}

		prv := fixLen(rawPrv, mine.PointSize())

		refPub, err := gost.PublicKeyRawFromPrivate(ref, prv)
		if err != nil {
			// Scalar reduced to zero / invalid private key: genuinely no key.
			t.Skipf("ref key load failed on %s: %v", oid, err)
		}
		newPub := gost3410sign.PublicKeyRaw(mine, prv)
		if newPub == nil {
			t.Fatalf("%s: clean-room PublicKeyRaw nil where gogost ok (prv=%x)", oid, prv)
		}
		if !bytes.Equal(refPub, newPub) {
			t.Fatalf("%s: public point mismatch (prv=%x):\n ref  %x\n mine %x",
				oid, prv, refPub, newPub)
		}
	})
}

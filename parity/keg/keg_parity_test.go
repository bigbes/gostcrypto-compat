package kegparity

import (
	"bytes"
	"encoding/asn1"
	. "github.com/bigbes/gostcrypto/keg"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"
)

// fixLen returns b padded with zeros or truncated to exactly n bytes.
func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// tc26256AOID is GOST R 34.10-2012 256-bit TC26 ParamSet A.
var tc26256AOID = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}

func oracleCurve(t testing.TB) *gost.Curve {
	t.Helper()
	c, err := gost.CurveByOID(tc26256AOID)
	if err != nil {
		t.Fatalf("oracle CurveByOID: %v", err)
	}
	return c
}

// TestKEG2012_256_DiffOracle pins the clean-room output to the in-repo
// gogost-backed reference (gostcryptocompat.KEG2012_256), the de-facto spec this
// repo matches, on the doc's KAT inputs.
func TestKEG2012_256_DiffOracle(t *testing.T) {
	curve := oracleCurve(t)
	ukm := mustHex(t, ukmHex)
	want := mustHex(t, wantHex)

	cases := []struct {
		name      string
		pub, priv string
	}{
		{"privA_pubB", pubBHex, privAHex},
		{"privB_pubA", pubAHex, privBHex},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub := mustHex(t, tc.pub)
			priv := mustHex(t, tc.priv)

			ref, err := gost.KEG2012_256(curve, pub, priv, ukm)
			if err != nil {
				t.Fatalf("oracle KEG: %v", err)
			}
			if !bytes.Equal(ref[:], want) {
				t.Fatalf("oracle != pinned vector:\n ref %x\nwant %x", ref[:], want)
			}

			got, err := KEG2012_256(curve, pub, priv, ukm)
			if err != nil {
				t.Fatalf("clean-room KEG: %v", err)
			}
			if got != ref {
				t.Fatalf("clean-room != oracle:\n got %x\n ref %x", got[:], ref[:])
			}
		})
	}
}

// TestKEG2012_256_DiffEphemeral draws fresh key material from the oracle's
// ephemeral-key generator and checks clean-room == oracle plus pair symmetry.
func TestKEG2012_256_DiffEphemeral(t *testing.T) {
	curve := oracleCurve(t)

	seeds := [][2][]byte{
		{bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)},
		{bytes.Repeat([]byte{0xa5}, 32), bytes.Repeat([]byte{0x5a}, 32)},
		{mustHex(t, privAHex), mustHex(t, privBHex)},
	}
	ukms := [][]byte{
		mustHex(t, ukmHex),
		make([]byte, 32), // all-zero first 16 bytes → real_ukm special case
		bytes.Repeat([]byte{0xff}, 32),
	}

	for si, sp := range seeds {
		privA, pubA, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(sp[0]))
		if err != nil {
			t.Fatalf("seed %d: gen A: %v", si, err)
		}
		privB, pubB, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(sp[1]))
		if err != nil {
			t.Fatalf("seed %d: gen B: %v", si, err)
		}

		for ui, ukm := range ukms {
			ref, err := gost.KEG2012_256(curve, pubB, privA, ukm)
			if err != nil {
				t.Fatalf("seed %d ukm %d: oracle: %v", si, ui, err)
			}
			got, err := KEG2012_256(curve, pubB, privA, ukm)
			if err != nil {
				t.Fatalf("seed %d ukm %d: clean-room: %v", si, ui, err)
			}
			if got != ref {
				t.Fatalf("seed %d ukm %d: clean-room != oracle\n got %x\n ref %x",
					si, ui, got[:], ref[:])
			}

			// Free pair-symmetry oracle.
			sym, err := KEG2012_256(curve, pubA, privB, ukm)
			if err != nil {
				t.Fatalf("seed %d ukm %d: clean-room sym: %v", si, ui, err)
			}
			if sym != got {
				t.Fatalf("seed %d ukm %d: not pair-symmetric\n A→B %x\n B→A %x",
					si, ui, got[:], sym[:])
			}
		}
	}
}

// FuzzKEG2012_256_DiffOracle mirrors TestKEG2012_256_DiffEphemeral: from two
// fuzzer-supplied 32-byte seeds it derives valid ephemeral key pairs via the
// oracle's generator, then for a fuzzer-supplied UKM asserts that the
// clean-room KEG equals the oracle KEG and that the result is pair-symmetric
// (A→B == B→A). Seeds and UKM are normalized to 32 bytes; invalid generator
// inputs are skipped (never used to hide a KEG mismatch).
func FuzzKEG2012_256_DiffOracle(f *testing.F) {
	f.Add(seedHex(privAHex), seedHex(privBHex), seedHex(ukmHex))
	f.Add(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), make([]byte, 32))
	f.Add(bytes.Repeat([]byte{0xa5}, 32), bytes.Repeat([]byte{0x5a}, 32), bytes.Repeat([]byte{0xff}, 32))

	f.Fuzz(func(t *testing.T, seedA, seedB, rndUKM []byte) {
		curve := oracleCurve(t)
		sa := fixLen(seedA, 32)
		sb := fixLen(seedB, 32)
		ukm := fixLen(rndUKM, 32)

		privA, pubA, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(sa))
		if err != nil {
			t.Skipf("gen A: %v", err)
		}
		privB, pubB, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(sb))
		if err != nil {
			t.Skipf("gen B: %v", err)
		}

		ref, err := gost.KEG2012_256(curve, pubB, privA, ukm)
		if err != nil {
			t.Skipf("oracle KEG: %v", err)
		}
		got, err := KEG2012_256(curve, pubB, privA, ukm)
		if err != nil {
			t.Fatalf("clean-room KEG: %v", err)
		}
		if got != ref {
			t.Fatalf("clean-room != oracle\n got %x\n ref %x", got[:], ref[:])
		}

		// Pair symmetry: A→B must equal B→A.
		sym, err := KEG2012_256(curve, pubA, privB, ukm)
		if err != nil {
			t.Fatalf("clean-room sym: %v", err)
		}
		if sym != got {
			t.Fatalf("not pair-symmetric\n A→B %x\n B→A %x", got[:], sym[:])
		}
	})
}

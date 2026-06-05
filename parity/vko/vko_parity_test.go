package vkoparity

import (
	"bytes"
	"encoding/hex"
	"testing"

	gostoracle "github.com/bigbes/gostcrypto-compat"
	"github.com/bigbes/gostcrypto/gost3410curves"
	"github.com/bigbes/gostcrypto/vko"
)

func mustHexF(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// deriveQ derives the LE public point d·P via the clean-room curve math so the
// 2001 KAT (scalars only) can feed both impls the same peer point.
func deriveQ(t *testing.T, c *gost3410curves.Curve, dLE []byte) []byte {
	t.Helper()
	q, err := vko.DeriveQLE(c, dLE)
	if err != nil {
		t.Fatalf("DeriveQLE: %v", err)
	}
	return q
}

// TestDifferential asserts the clean-room VKO matches the gostcryptocompat oracle
// across all three variants and both agreement directions (D2 symmetry, D4
// X/Y order, D1 LE UKM).
func TestDifferential(t *testing.T) {
	c2001 := vko.Curve2001Test()

	d1 := mustHexF(t, "1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
	d2 := mustHexF(t, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
	ukm2001 := mustHexF(t, "5172be25f852a233")
	Q1 := deriveQ(t, c2001, d1)
	Q2 := deriveQ(t, c2001, d2)

	dA := mustHexF(t, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
		"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	QA := mustHexF(t, "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5"+
		"d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7"+
		"914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38"+
		"461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	dB := mustHexF(t, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
		"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	QB := mustHexF(t, "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"+
		"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"+
		"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"+
		"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	ukm2012 := mustHexF(t, "1d80603c8544c727")

	type variant int
	const (
		v2001 variant = iota
		v2012256
		v2012512
	)

	clean := func(v variant, prv, peer, ukm []byte) ([]byte, error) {
		switch v {
		case v2001:
			return vko.VKO2001TestCurve(prv, peer, ukm)
		case v2012256:
			return vko.VKO2012_256(prv, peer, ukm)
		default:
			return vko.VKO2012_512(prv, peer, ukm)
		}
	}
	oracle := func(v variant, prv, peer, ukm []byte) ([]byte, error) {
		switch v {
		case v2001:
			return gostoracle.VKO2001TestCurve(prv, peer, ukm)
		case v2012256:
			return gostoracle.VKO2012_256(prv, peer, ukm)
		default:
			return gostoracle.VKO2012_512(prv, peer, ukm)
		}
	}

	cases := []struct {
		name      string
		v         variant
		prv, peer []byte
		ukm       []byte
	}{
		{"2001/A", v2001, d1, Q2, ukm2001},
		{"2001/B", v2001, d2, Q1, ukm2001},
		{"2012_256/A", v2012256, dA, QB, ukm2012},
		{"2012_256/B", v2012256, dB, QA, ukm2012},
		{"2012_512/A", v2012512, dA, QB, ukm2012},
		{"2012_512/B", v2012512, dB, QA, ukm2012},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := clean(tc.v, tc.prv, tc.peer, tc.ukm)
			if err != nil {
				t.Fatalf("clean-room: %v", err)
			}
			ref, err := oracle(tc.v, tc.prv, tc.peer, tc.ukm)
			if err != nil {
				t.Fatalf("oracle: %v", err)
			}
			if !bytes.Equal(got, ref) {
				t.Fatalf("KEK mismatch vs oracle:\n got = %x\n ref = %x", got, ref)
			}
		})
	}
}

// norm slices or zero-extends b to n bytes (LE) and forces a non-zero low byte
// so a scalar/UKM is never all-zero (guide D7/D1).
func norm(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	out[0] |= 0x01
	return out
}

// FuzzDifferential: random scalar pair + 8-byte UKM on paramSetA. Asserts
// agreement symmetry plus equality against the gostcryptocompat oracle.
func FuzzDifferential(f *testing.F) {
	f.Add(
		mustHexFz(f, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
			"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"),
		mustHexFz(f, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
			"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"),
		mustHexFz(f, "1d80603c8544c727"),
	)
	c := vko.Curve2012ParamSetA()

	f.Fuzz(func(t *testing.T, rawA, rawB, rawUKM []byte) {
		dA := norm(rawA, 64)
		dB := norm(rawB, 64)
		ukm := norm(rawUKM, 8)

		QA, err := vko.DeriveQLE(c, dA)
		if err != nil {
			return
		}
		QB, err := vko.DeriveQLE(c, dB)
		if err != nil {
			return
		}

		kAB, err := vko.VKO2012_256(dA, QB, ukm)
		if err != nil {
			return
		}
		kBA, err := vko.VKO2012_256(dB, QA, ukm)
		if err != nil {
			t.Fatalf("asymmetric error: B->A failed but A->B did not: %v", err)
		}
		if !bytes.Equal(kAB, kBA) {
			t.Fatalf("symmetry broken: A->B=%x B->A=%x", kAB, kBA)
		}
		ref, err := gostoracle.VKO2012_256(dA, QB, ukm)
		if err != nil {
			t.Fatalf("oracle error where clean-room succeeded: %v", err)
		}
		if !bytes.Equal(kAB, ref) {
			t.Fatalf("KEK != oracle:\n got=%x\n ref=%x", kAB, ref)
		}
	})
}

func mustHexFz(f *testing.F, s string) []byte {
	f.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		f.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

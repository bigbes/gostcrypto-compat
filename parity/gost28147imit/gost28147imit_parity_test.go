package gost28147imitparity

import (
	"bytes"
	"encoding/hex"
	. "github.com/bigbes/gostcrypto/gost28147imit"
	"math/rand"
	"testing"

	refgost "github.com/bigbes/gostcrypto-compat"
)

// seedHex decodes a hex string for f.Add seeds (which take no *testing.T).
func seedHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestDiff_InternalGostOracle treats gostcryptocompat.GOST28147_IMIT as a
// black-box oracle (signature from the guide §"Conformance & fuzz testing":
// returns the 4-byte TLS-truncated tag with CryptoPro key meshing) and diffs
// it against the clean-room IMIT over random keys and messages. Lengths are
// chosen to exercise the short-message finalization (1..8 and 9..16) and the
// key-meshing path (> 1024 bytes).
func TestDiff_InternalGostOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1234_5678))

	// Deterministic length set: every short length 1..16 (short-message
	// trailing-zero-block window plus the first whole-block boundary), plus a
	// spread that straddles the 1024-byte meshing boundary several times.
	var lengths []int
	for n := 1; n <= 16; n++ {
		lengths = append(lengths, n)
	}
	lengths = append(lengths,
		17, 31, 32, 100, 255, 256, 1016, 1017, 1023, 1024, 1025, 1031,
		1032, 2048, 2049, 3072, 4097, 8192, 12345,
	)

	for iter := 0; iter < 200; iter++ {
		key := make([]byte, keySize)
		rng.Read(key)

		for _, n := range lengths {
			msg := make([]byte, n)
			rng.Read(msg)

			got := IMIT(key, msg)
			ref, err := refgost.GOST28147_IMIT(key, msg)
			if err != nil {
				t.Fatalf("oracle GOST28147_IMIT(len=%d): %v", n, err)
			}
			if !bytes.Equal(got, ref) {
				t.Fatalf("mismatch key=%x len=%d: clean-room %x != oracle %x",
					key, n, got, ref)
			}
		}
	}
}

// FuzzDiff_InternalGostOracle is the fuzzing companion to
// TestDiff_InternalGostOracle: it diffs the clean-room IMIT against the
// gostcryptocompat.GOST28147_IMIT black-box oracle (4-byte TLS-truncated tag with
// CryptoPro key meshing) over a fuzzer-chosen key and arbitrary-length message.
// Both sides are one-shot (the oracle exposes no streaming surface), so there
// is no MAC.Sum partial-block destructiveness to guard against here.
func FuzzDiff_InternalGostOracle(f *testing.F) {
	f.Add(
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1122334455667700ffeeddccbbaa9988"))
	f.Add(
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("92def06b3c130a59"))
	f.Add(
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		[]byte{0x01})

	f.Fuzz(func(t *testing.T, rndKey, msg []byte) {
		if len(msg) == 0 {
			// IMIT is undefined on the empty message: the clean-room primitive
			// panics and the oracle errors. The Test func only uses lengths >= 1.
			t.Skip("empty message is undefined for GOST 28147-89 IMIT")
		}
		key := fixLen(rndKey, keySize)

		ref, err := refgost.GOST28147_IMIT(key, msg)
		if err != nil {
			// Invalid constructor / input for the oracle.
			t.Skipf("oracle GOST28147_IMIT(len=%d): %v", len(msg), err)
		}
		got := IMIT(key, msg)
		if !bytes.Equal(got, ref) {
			t.Fatalf("mismatch key=%x len=%d: clean-room %x != oracle %x",
				key, len(msg), got, ref)
		}
	})
}

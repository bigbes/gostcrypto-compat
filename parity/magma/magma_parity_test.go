package magmaparity

import (
	"bytes"
	"encoding/hex"
	. "github.com/bigbes/gostcrypto/magma"
	"math/rand"
	"testing"

	gostref "github.com/bigbes/gostcrypto-compat"
)

// TestMagmaDifferential cross-checks the clean-room impl against the repo's
// gostcryptocompat.MagmaEncrypt/MagmaDecrypt black-box oracle over random blocks.
func TestMagmaDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	key := make([]byte, KeySize)
	pt := make([]byte, BlockSize)

	for i := 0; i < 50000; i++ {
		rng.Read(key)
		rng.Read(pt)

		ours := MagmaEncrypt(key, pt)

		theirs, err := gostref.MagmaEncrypt(key, pt)
		if err != nil {
			t.Fatalf("gostref.MagmaEncrypt i=%d: %v", i, err)
		}

		if !bytes.Equal(ours, theirs) {
			t.Fatalf("encrypt mismatch: key=%x pt=%x ours=%x ref=%x", key, pt, ours, theirs)
		}

		oursD := MagmaDecrypt(key, ours)

		theirsD, err := gostref.MagmaDecrypt(key, theirs)
		if err != nil {
			t.Fatalf("gostref.MagmaDecrypt i=%d: %v", i, err)
		}

		if !bytes.Equal(oursD, theirsD) {
			t.Fatalf("decrypt mismatch: key=%x ct=%x ours=%x ref=%x", key, ours, oursD, theirsD)
		}

		if !bytes.Equal(oursD, pt) {
			t.Fatalf("round-trip failed: key=%x pt=%x back=%x", key, pt, oursD)
		}
	}
}

// FuzzMagmaDifferential mirrors TestMagmaDifferential: it pads the fuzzer's raw
// bytes to a valid KeySize key and BlockSize block, then asserts byte-exact
// agreement between the clean-room impl and the gost oracle on both Encrypt and
// Decrypt, plus clean-room round-trip identity.
func FuzzMagmaDifferential(f *testing.F) {
	f.Add(
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("fedcba9876543210"))
	f.Add(
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		seedHex("0000000000000000"))

	f.Fuzz(func(t *testing.T, rndKey, rndBlk []byte) {
		key := fixLen(rndKey, KeySize)
		pt := fixLen(rndBlk, BlockSize)

		ours := MagmaEncrypt(key, pt)

		theirs, err := gostref.MagmaEncrypt(key, pt)
		if err != nil {
			t.Fatalf("gostref.MagmaEncrypt: %v", err)
		}

		if !bytes.Equal(ours, theirs) {
			t.Fatalf("encrypt mismatch: key=%x pt=%x ours=%x ref=%x", key, pt, ours, theirs)
		}

		// Decrypt diff on an arbitrary block (fuzzer-supplied ciphertext).
		oursD := MagmaDecrypt(key, pt)

		theirsD, err := gostref.MagmaDecrypt(key, pt)
		if err != nil {
			t.Fatalf("gostref.MagmaDecrypt: %v", err)
		}

		if !bytes.Equal(oursD, theirsD) {
			t.Fatalf("decrypt mismatch: key=%x ct=%x ours=%x ref=%x", key, pt, oursD, theirsD)
		}

		// Round-trip on the clean-room side.
		back := MagmaDecrypt(key, ours)
		if !bytes.Equal(back, pt) {
			t.Fatalf("round-trip failed: key=%x pt=%x back=%x", key, pt, back)
		}
	})
}

func seedHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func fixLen(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

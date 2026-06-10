package gost28147parity

import (
	"bytes"
	. "github.com/bigbes/gostcrypto/gost28147"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"
)

// TestDiff_InternalGostOracle treats gostcryptocompat as a black-box oracle
// (signatures taken from the guide, not the implementation source) and diffs
// its CryptoPro-A ECB output against the clean-room impl over the pinned
// vector and a spread of deterministic key/block pairs.
func TestDiff_InternalGostOracle(t *testing.T) {
	keys := [][]byte{
		mustHex(t, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1"),
	}
	for seed := 0; seed < 64; seed++ {
		var k [KeySize]byte
		x := uint64(seed)*0x9E3779B97F4A7C15 + 0xABCDEF
		for i := range k {
			k[i] = byte(x>>(8*(i%8))) ^ byte(i*31)
		}
		keys = append(keys, k[:])
	}

	for ki, key := range keys {
		c := NewCipher(key, SboxCryptoProA)
		for seed := 0; seed < 64; seed++ {
			var p [BlockSize]byte
			x := uint64(seed)*0x100000001B3 + uint64(ki)*0x9E3779B1
			for i := 0; i < BlockSize; i++ {
				p[i] = byte(x >> (8 * i))
			}
			want, err := gost.GOST2814789Encrypt(key, p[:])
			if err != nil {
				t.Fatalf("GOST2814789Encrypt key#%d: %v", ki, err)
			}

			got := make([]byte, BlockSize)
			c.Encrypt(got, p[:])
			if !bytes.Equal(got, want) {
				t.Fatalf("key#%d in=%x: clean-room %x != oracle %x", ki, p, got, want)
			}

			back, err := gost.GOST2814789Decrypt(key, want)
			if err != nil {
				t.Fatalf("GOST2814789Decrypt key#%d: %v", ki, err)
			}

			if !bytes.Equal(back, p[:]) {
				t.Fatalf("oracle decrypt mismatch key#%d", ki)
			}
		}
	}
}

// FuzzDiffGost28147 mirrors TestDiff_InternalGostOracle: it pads the fuzzer's
// raw bytes to a valid KeySize key and BlockSize block, then asserts byte-exact
// agreement between the clean-room CryptoPro-A ECB cipher and the gost oracle
// on both Encrypt and Decrypt, plus clean-room round-trip identity.
func FuzzDiffGost28147(f *testing.F) {
	f.Add(
		seedHex("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1"),
		seedHex("0011223344556677"))
	f.Add(
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		seedHex("0000000000000000"))

	f.Fuzz(func(t *testing.T, rndKey, rndBlk []byte) {
		key := fixLen(rndKey, KeySize)
		p := fixLen(rndBlk, BlockSize)

		c := NewCipher(key, SboxCryptoProA)

		got := make([]byte, BlockSize)
		c.Encrypt(got, p)

		want, err := gost.GOST2814789Encrypt(key, p)
		if err != nil {
			t.Fatalf("GOST2814789Encrypt: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf("Encrypt mismatch: key=%x in=%x clean-room %x != oracle %x", key, p, got, want)
		}

		// Decrypt diff on an arbitrary block (fuzzer-supplied ciphertext).
		minePT := make([]byte, BlockSize)
		c.Decrypt(minePT, p)

		refPT, err := gost.GOST2814789Decrypt(key, p)
		if err != nil {
			t.Fatalf("GOST2814789Decrypt: %v", err)
		}

		if !bytes.Equal(minePT, refPT) {
			t.Fatalf("Decrypt mismatch: key=%x in=%x clean-room %x != oracle %x", key, p, minePT, refPT)
		}

		// Round-trip on the clean-room side.
		back := make([]byte, BlockSize)
		c.Decrypt(back, got)
		if !bytes.Equal(back, p) {
			t.Fatalf("round-trip Decrypt(Encrypt) != p: key=%x p=%x got=%x", key, p, back)
		}
	})
}

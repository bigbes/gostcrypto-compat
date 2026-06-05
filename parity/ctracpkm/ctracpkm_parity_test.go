package ctracpkmparity

import (
	"bytes"
	"crypto/cipher"
	"testing"

	ref "github.com/bigbes/gostcrypto-compat"
	"github.com/bigbes/gostcrypto/ctracpkm"
	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
)

// TestDiff_CTRACPKM_vs_Oracle drives the in-repo gost oracle and the clean-room
// impl with identical inputs and asserts byte-equal keystream. The oracle
// constructors are NewCTR(block, iv) and NewCTRACPKM(newBlock, key, iv,
// section) — ctr-acpkm.md §"Conformance" pins these signatures.
func TestDiff_CTRACPKM_vs_Oracle(t *testing.T) {
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

	type tc struct {
		name     string
		newBlock func([]byte) cipher.Block
		ivLen    int
		sections []int
		lengths  []int
	}
	cases := []tc{
		{
			name:     "kuznyechik",
			newBlock: func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) },
			ivLen:    16,
			sections: []int{0, 16, 32, 64, 4096},
			lengths:  []int{1, 15, 16, 17, 31, 32, 33, 112, 257, 4096, 4097, 9000},
		},
		{
			name:     "magma",
			newBlock: func(k []byte) cipher.Block { return magma.NewCipher(k) },
			ivLen:    8,
			sections: []int{0, 8, 16, 1024},
			lengths:  []int{1, 7, 8, 9, 31, 32, 1024, 1025, 5000},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			iv := make([]byte, c.ivLen)
			copy(iv, []byte{0x12, 0x34, 0x56, 0x78})
			for _, section := range c.sections {
				for _, n := range c.lengths {
					plain := make([]byte, n)
					for i := range plain {
						plain[i] = byte(i*7 + 3)
					}

					oracle, err := ref.NewCTRACPKM(c.newBlock, key, iv, section)
					if err != nil {
						t.Fatalf("oracle NewCTRACPKM(section=%d): %v", section, err)
					}
					refOut := make([]byte, n)
					oracle.XORKeyStream(refOut, plain)

					mine := ctracpkm.NewCTRACPKM(c.newBlock, key, iv, section)
					myOut := make([]byte, n)
					mine.XORKeyStream(myOut, plain)

					if !bytes.Equal(refOut, myOut) {
						t.Fatalf("%s section=%d len=%d divergence:\n ref %x\n new %x",
							c.name, section, n, refOut, myOut)
					}
				}
			}
		})
	}
}

// FuzzDiff_CTRACPKM_vs_Oracle mirrors TestDiff_CTRACPKM_vs_Oracle: it feeds the
// same key/iv/section/plaintext to the in-repo gost oracle and the clean-room
// CTR-ACPKM impl and asserts byte-equal keystream. The block-cipher choice is
// fuzzer-selected; key is normalized to 32 bytes and the IV to the cipher's
// block size, while the plaintext length stays variable so section boundaries
// (re-keying) are explored.
func FuzzDiff_CTRACPKM_vs_Oracle(f *testing.F) {
	f.Add(byte(0),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("12345678000000000000000000000000"),
		uint16(32), []byte("hello ctr-acpkm world, this is a longer plaintext"))
	f.Add(byte(1),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1234567800000000"),
		uint16(8), make([]byte, 100))

	f.Fuzz(func(t *testing.T, sel byte, rndKey, rndIV []byte, sectionRaw uint16, plain []byte) {
		var newBlock func([]byte) cipher.Block
		var ivLen int
		if sel&1 == 0 {
			newBlock = func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) }
			ivLen = 16
		} else {
			newBlock = func(k []byte) cipher.Block { return magma.NewCipher(k) }
			ivLen = 8
		}
		key := fixLen(rndKey, 32)
		iv := fixLen(rndIV, ivLen)
		// section: keep variable (incl. 0 = plain CTR / no re-key), cap for speed.
		section := int(sectionRaw % 4097)
		// Cap absurd plaintext lengths so the fuzzer stays fast.
		if len(plain) > 16384 {
			plain = plain[:16384]
		}

		oracle, err := ref.NewCTRACPKM(newBlock, key, iv, section)
		if err != nil {
			t.Skipf("oracle NewCTRACPKM(section=%d): %v", section, err)
		}
		refOut := make([]byte, len(plain))
		oracle.XORKeyStream(refOut, plain)

		mine := ctracpkm.NewCTRACPKM(newBlock, key, iv, section)
		myOut := make([]byte, len(plain))
		mine.XORKeyStream(myOut, plain)

		if !bytes.Equal(refOut, myOut) {
			t.Fatalf("sel=%d section=%d len=%d divergence:\n ref %x\n new %x",
				sel, section, len(plain), refOut, myOut)
		}
	})
}

// TestDiff_PlainCTR_vs_Oracle checks NewCTR (plain CTR) against the oracle.
func TestDiff_PlainCTR_vs_Oracle(t *testing.T) {
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := mustHex(t, "1234567890abcef00000000000000000")

	for _, n := range []int{1, 16, 33, 200, 4097} {
		plain := make([]byte, n)
		for i := range plain {
			plain[i] = byte(i)
		}
		oracle, err := ref.NewCTR(kuznyechik.NewCipher(key), iv)
		if err != nil {
			t.Fatalf("oracle NewCTR: %v", err)
		}
		refOut := make([]byte, n)
		oracle.XORKeyStream(refOut, plain)

		myOut := make([]byte, n)
		ctracpkm.NewCTR(kuznyechik.NewCipher(key), iv).XORKeyStream(myOut, plain)

		if !bytes.Equal(refOut, myOut) {
			t.Fatalf("plain CTR len=%d divergence:\n ref %x\n new %x", n, refOut, myOut)
		}
	}
}

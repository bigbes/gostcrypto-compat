// Differential test of the clean-room MGM against the gogost oracle.
// gogost is used strictly as a BLACK BOX (imported and called; its source is
// not read). The diff covers both layers:
//   - clean-room MGM over clean-room block ciphers (kuznyechik/magma), vs
//   - gogost MGM over gogost block ciphers,
//
// fed identical key/nonce/aad/plaintext, asserting byte-identical output.
package mgmparity

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	. "github.com/bigbes/gostcrypto/mgm"
	"math/rand"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
	gogostmgm "go.stargrave.org/gogost/v7/mgm"

	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
)

type variant struct {
	name      string
	blockSize int
	tagSize   int
	newRef    func(key []byte) cipher.Block
	newMine   func(key []byte) cipher.Block
}

var variants = []variant{
	{
		name:      "Kuznyechik",
		blockSize: 16,
		tagSize:   16,
		newRef:    func(k []byte) cipher.Block { return gost3412128.NewCipher(k) },
		newMine:   func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) },
	},
	{
		name:      "Magma",
		blockSize: 8,
		tagSize:   8,
		newRef:    func(k []byte) cipher.Block { return gost341264.NewCipher(k) },
		newMine:   func(k []byte) cipher.Block { return magma.NewCipher(k) },
	},
}

func TestMGM_Differential(t *testing.T) {
	for _, v := range variants {
		v := v
		t.Run(v.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(0x9058))
			for iter := 0; iter < 500; iter++ {
				key := make([]byte, 32)
				rng.Read(key)
				nonce := make([]byte, v.blockSize)
				rng.Read(nonce)
				nonce[0] &= 0x7f // MSB-must-be-0

				adLen := rng.Intn(70)
				ptLen := rng.Intn(70)
				if adLen == 0 && ptLen == 0 {
					ptLen = 1 // MGM rejects empty text+aad
				}
				aad := make([]byte, adLen)
				rng.Read(aad)
				plain := make([]byte, ptLen)
				rng.Read(plain)

				// Reference: gogost MGM over gogost block cipher.
				ref, err := gogostmgm.NewMGM(v.newRef(key), v.tagSize)
				if err != nil {
					t.Fatalf("ref NewMGM: %v", err)
				}
				gotRef := ref.Seal(nil, nonce, plain, aad)

				// Clean-room: my MGM over my block cipher.
				mine, err := NewMGM(v.newMine(key), v.tagSize)
				if err != nil {
					t.Fatalf("mine NewMGM: %v", err)
				}
				gotMine := mine.Seal(nil, nonce, plain, aad)

				if !bytes.Equal(gotRef, gotMine) {
					t.Fatalf("iter %d Seal mismatch (ad=%d pt=%d):\n ref  %x\n mine %x",
						iter, adLen, ptLen, gotRef, gotMine)
				}

				// Round-trip on the clean-room side.
				back, err := mine.Open(nil, nonce, gotMine, aad)
				if err != nil {
					t.Fatalf("iter %d mine Open rejected own Seal: %v", iter, err)
				}
				if !bytes.Equal(back, plain) {
					t.Fatalf("iter %d round-trip mismatch:\n got  %x\n want %x", iter, back, plain)
				}
			}
		})
	}
}

func FuzzMGM_Differential(f *testing.F) {
	f.Add(byte(16),
		mustHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		mustHex("1122334455667700ffeeddccbbaa9988"),
		mustHex("0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505"),
		mustHex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0aaabbcc"))
	f.Add(byte(8),
		mustHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		mustHex("12def06b3c130a59"),
		mustHex("0101010101010101020202020202020203030303030303030404040404040404"),
		mustHex("ffeeddccbbaa998811223344556677008899aabbcceeff0aaabbcc"))

	f.Fuzz(func(t *testing.T, sel byte, rndKey, rndNonce, aad, plain []byte) {
		v := variants[0] // Kuznyechik
		if sel&1 == 0 {
			v = variants[1] // Magma
		}
		key := fixLen(rndKey, 32)
		nonce := fixLen(rndNonce, v.blockSize)
		nonce[0] &= 0x7f
		if len(plain) == 0 && len(aad) == 0 {
			plain = []byte{0}
		}

		ref, err := gogostmgm.NewMGM(v.newRef(key), v.tagSize)
		if err != nil {
			t.Skipf("ref NewMGM: %v", err)
		}
		mine, err := NewMGM(v.newMine(key), v.tagSize)
		if err != nil {
			t.Skipf("mine NewMGM: %v", err)
		}

		gotRef := ref.Seal(nil, nonce, plain, aad)
		gotMine := mine.Seal(nil, nonce, plain, aad)
		if !bytes.Equal(gotRef, gotMine) {
			t.Fatalf("Seal mismatch (bs=%d):\n ref  %x\n mine %x", v.blockSize, gotRef, gotMine)
		}
		back, err := mine.Open(nil, nonce, gotMine, aad)
		if err != nil {
			t.Fatalf("mine Open rejected own Seal: %v", err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatalf("round-trip mismatch:\n got  %x\n want %x", back, plain)
		}
	})
}

func mustHex(s string) []byte {
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

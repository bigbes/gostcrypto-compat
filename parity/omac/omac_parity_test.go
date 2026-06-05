package omacparity

import (
	"bytes"
	"math/rand"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"

	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
	mynew "github.com/bigbes/gostcrypto/omac"
)

// TestDiffAgainstGost runs the clean-room OMAC against the
// gostcryptocompat.NewOMAC black-box oracle (which wraps a gost block cipher
// from NewKuznyechikCipher/NewMagmaCipher) over random keys and
// arbitrary-length messages, for both block sizes, requiring byte-exact
// agreement.
func TestDiffAgainstGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0x6f6d6163))

	for iter := 0; iter < 2048; iter++ {
		key := make([]byte, 32)
		rng.Read(key)
		msg := make([]byte, rng.Intn(70)) // spans 0..>4 blocks for both sizes
		rng.Read(msg)

		// Kuznyechik, full 16-byte tag.
		{
			mine := mynew.New(kuznyechik.NewCipher(key), 16)
			mine.Write(msg)
			got := mine.Sum(nil)

			ref, err := gost.NewOMAC(gost.NewKuznyechikCipher(key), 16)
			if err != nil {
				t.Fatalf("gost.NewOMAC kuz: %v", err)
			}
			ref.Write(msg)
			want := ref.Sum(nil)

			if !bytes.Equal(got, want) {
				t.Fatalf("kuz mismatch iter=%d len=%d\n key=%x msg=%x\n mine=%x ref=%x",
					iter, len(msg), key, msg, got, want)
			}
		}

		// Magma, full 8-byte tag.
		{
			mine := mynew.New(magma.NewCipher(key), 8)
			mine.Write(msg)
			got := mine.Sum(nil)

			ref, err := gost.NewOMAC(gost.NewMagmaCipher(key), 8)
			if err != nil {
				t.Fatalf("gost.NewOMAC magma: %v", err)
			}
			ref.Write(msg)
			want := ref.Sum(nil)

			if !bytes.Equal(got, want) {
				t.Fatalf("magma mismatch iter=%d len=%d\n key=%x msg=%x\n mine=%x ref=%x",
					iter, len(msg), key, msg, got, want)
			}
		}
	}
}

// FuzzDiffAgainstGost is the fuzzing companion to TestDiffAgainstGost: it diffs
// the clean-room OMAC against the gostcryptocompat.NewOMAC black-box oracle over
// fuzzer-chosen keys and arbitrary-length messages, for both block sizes, and
// exercises a streaming (split) Write against a one-shot Write. The clean-room
// MAC is only Sum-ed once after all Writes complete.
func FuzzDiffAgainstGost(f *testing.F) {
	f.Add(byte(0),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"),
		uint(13))
	f.Add(byte(1),
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41"),
		uint(7))
	f.Add(byte(0),
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		[]byte{}, uint(0))

	f.Fuzz(func(t *testing.T, sel byte, rndKey, msg []byte, split uint) {
		key := fixLen(rndKey, 32)

		var mine *mynew.OMAC
		var ref *gost.OMAC
		var err error
		if sel&1 == 0 {
			// Kuznyechik, full 16-byte tag.
			mine = mynew.New(kuznyechik.NewCipher(key), 16)
			ref, err = gost.NewOMAC(gost.NewKuznyechikCipher(key), 16)
		} else {
			// Magma, full 8-byte tag.
			mine = mynew.New(magma.NewCipher(key), 8)
			ref, err = gost.NewOMAC(gost.NewMagmaCipher(key), 8)
		}
		if err != nil {
			t.Skipf("gost.NewOMAC: %v", err)
		}

		// Clean-room side: streaming split at a fuzzer-chosen offset.
		if len(msg) > 0 {
			off := int(split % uint(len(msg)+1))
			mine.Write(msg[:off])
			mine.Write(msg[off:])
		} else {
			mine.Write(msg)
		}
		got := mine.Sum(nil)

		// Oracle side: one-shot.
		ref.Write(msg)
		want := ref.Sum(nil)

		if !bytes.Equal(got, want) {
			t.Fatalf("mismatch sel=%d len=%d\n key=%x msg=%x\n mine=%x ref=%x",
				sel&1, len(msg), key, msg, got, want)
		}
	})
}

// TestDiffTruncatedKATs cross-checks the pinned standard KATs against the
// oracle at the truncated tag widths used by the published vectors.
func TestDiffTruncatedKATs(t *testing.T) {
	cases := []struct {
		name    string
		newMine func(key []byte, tag int) *mynew.OMAC
		newRef  func(key []byte, tag int) (*gost.OMAC, error)
		key     string
		msg     string
		tagSize int
		want    string
	}{
		{
			name:    "kuz/A.1.6/trunc8",
			newMine: func(k []byte, t int) *mynew.OMAC { return mynew.New(kuznyechik.NewCipher(k), t) },
			newRef:  func(k []byte, t int) (*gost.OMAC, error) { return gost.NewOMAC(gost.NewKuznyechikCipher(k), t) },
			key:     "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
			msg: "1122334455667700ffeeddccbbaa9988" +
				"00112233445566778899aabbcceeff0a" +
				"112233445566778899aabbcceeff0a00" +
				"2233445566778899aabbcceeff0a0011",
			tagSize: 8,
			want:    "336f4d296059fbe3",
		},
		{
			name:    "magma/A.2.6/trunc4",
			newMine: func(k []byte, t int) *mynew.OMAC { return mynew.New(magma.NewCipher(k), t) },
			newRef:  func(k []byte, t int) (*gost.OMAC, error) { return gost.NewOMAC(gost.NewMagmaCipher(k), t) },
			key:     "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			msg:     "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
			tagSize: 4,
			want:    "154e7210",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHex(t, tc.key)
			msg := mustHex(t, tc.msg)
			want := mustHex(t, tc.want)

			mine := tc.newMine(key, tc.tagSize)
			mine.Write(msg)
			got := mine.Sum(nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("clean-room: got %x want %x", got, want)
			}

			ref, err := tc.newRef(key, tc.tagSize)
			if err != nil {
				t.Fatalf("oracle ctor: %v", err)
			}
			ref.Write(msg)
			r := ref.Sum(nil)
			if !bytes.Equal(r, want) {
				t.Fatalf("oracle: got %x want %x", r, want)
			}
		})
	}
}

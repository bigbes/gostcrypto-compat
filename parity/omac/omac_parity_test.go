// OMAC parity tests: clean-room gostcrypto/omac vs gostcryptocompat.NewOMAC.
//
// Oracle independence note (OMAC-01): gogost v7 ships no CMAC/OMAC
// implementation (third_party/gogost/gost3413/ contains only padding.go). The
// oracle used here — gostcryptocompat.NewOMAC — is therefore a sibling
// reimplementation written in this same repo, not an independent one. Only the
// underlying block ciphers (gost3412128 / gost341264) are genuinely gogost,
// and their parity is proven independently by parity/kuznyechik and
// parity/magma. As a result, the differential tests here do NOT independently
// verify CMAC mode logic (subkey derivation, Write buffering, K1/K2 Sum
// finalization) — a shared mode bug that is replicated identically in both
// twins would pass every iteration. Independence of the CMAC mode logic rests
// on the engine-sourced KATs in the root package (omac_engine_test.go: the
// gost-engine "hello" Kuznyechik vector pins the K2/partial-block path for
// 16-byte blocks, and the A.2.6 / A.1.6 vectors pin the K1 path for both
// ciphers).
//
// API contract divergence (OMAC-02): omac.New (clean-room) panics on an
// out-of-range tagSize (programmer-error contract; the function returns no
// error). gostcryptocompat.NewOMAC returns (nil, error) for the same input.
// This divergence is intentional by API design (different constructor
// signatures) and is not a correctness difference.
package omacparity

import (
	"bytes"
	"math/rand"
	"sort"
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

// TestDiffSumNonDestructive verifies that Sum is non-destructive on both the
// clean-room and oracle sides: calling Sum twice returns identical bytes
// (idempotency), and writing more data after Sum produces the same result as a
// fresh instance over the full concatenated message (Write-after-Sum
// continuation). Covers OMAC-03.
func TestDiffSumNonDestructive(t *testing.T) {
	rng := rand.New(rand.NewSource(0x6f6d6163_dead))

	type cipherPair struct {
		name    string
		newMine func(key []byte, tagSize int) *mynew.OMAC
		newRef  func(key []byte, tagSize int) (*gost.OMAC, error)
		bs      int
	}

	pairs := []cipherPair{
		{
			name:    "kuznyechik",
			newMine: func(k []byte, ts int) *mynew.OMAC { return mynew.New(kuznyechik.NewCipher(k), ts) },
			newRef:  func(k []byte, ts int) (*gost.OMAC, error) { return gost.NewOMAC(gost.NewKuznyechikCipher(k), ts) },
			bs:      16,
		},
		{
			name:    "magma",
			newMine: func(k []byte, ts int) *mynew.OMAC { return mynew.New(magma.NewCipher(k), ts) },
			newRef:  func(k []byte, ts int) (*gost.OMAC, error) { return gost.NewOMAC(gost.NewMagmaCipher(k), ts) },
			bs:      8,
		},
	}

	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			for iter := 0; iter < 200; iter++ {
				key := make([]byte, 32)
				rng.Read(key)
				half1 := make([]byte, rng.Intn(35))
				rng.Read(half1)
				half2 := make([]byte, rng.Intn(35))
				rng.Read(half2)
				tagSize := 1 + rng.Intn(pair.bs)

				mine := pair.newMine(key, tagSize)
				ref, err := pair.newRef(key, tagSize)
				if err != nil {
					t.Fatalf("oracle ctor: %v", err)
				}

				// Write first half.
				mine.Write(half1)
				ref.Write(half1)

				// Sum mid-stream (non-destructive check) — both sides must agree.
				mid1 := mine.Sum(nil)
				midR1 := ref.Sum(nil)
				if !bytes.Equal(mid1, midR1) {
					t.Fatalf("iter=%d mid-Sum mismatch:\n mine=%x ref=%x", iter, mid1, midR1)
				}

				// Sum again (idempotency): must return identical bytes.
				mid2 := mine.Sum(nil)
				midR2 := ref.Sum(nil)
				if !bytes.Equal(mid1, mid2) {
					t.Fatalf("iter=%d clean-room Sum not idempotent: first=%x second=%x", iter, mid1, mid2)
				}
				if !bytes.Equal(midR1, midR2) {
					t.Fatalf("iter=%d oracle Sum not idempotent: first=%x second=%x", iter, midR1, midR2)
				}

				// Write second half after Sum (Write-after-Sum continuation).
				mine.Write(half2)
				ref.Write(half2)

				// Final Sum on both sides must agree.
				got := mine.Sum(nil)
				want := ref.Sum(nil)
				if !bytes.Equal(got, want) {
					t.Fatalf("iter=%d continuation mismatch:\n mine=%x ref=%x", iter, got, want)
				}

				// Cross-check: result must equal a fresh instance over the full message.
				full := append(append([]byte{}, half1...), half2...)
				fresh := pair.newMine(key, tagSize)
				fresh.Write(full)
				expected := fresh.Sum(nil)
				if !bytes.Equal(got, expected) {
					t.Fatalf("iter=%d continuation != fresh: got=%x expected=%x", iter, got, expected)
				}
			}
		})
	}
}

// FuzzDiffAgainstGost is the fuzzing companion to TestDiffAgainstGost: it diffs
// the clean-room OMAC against the gostcryptocompat.NewOMAC black-box oracle over
// fuzzer-chosen keys, messages, tag sizes (OMAC-02, OMAC-04), and multi-split
// streaming schedules (OMAC-05).
//
// sel&1 selects the cipher (0=Kuznyechik, 1=Magma). tagSizeHint is clamped to
// [1, blockSize]. The clean-room side is written via a multi-split schedule
// derived from split; the oracle side uses a one-shot Write.
func FuzzDiffAgainstGost(f *testing.F) {
	// Seed#0: Kuznyechik, 32 bytes (2 blocks, K1 path), full-width tag=16.
	f.Add(byte(0),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"),
		uint(13), byte(16))
	// Seed#1: Magma, 32 bytes (4 blocks, K1 path), full-width tag=8.
	f.Add(byte(1),
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41"),
		uint(7), byte(8))
	// Seed#2: Kuznyechik, empty message.
	f.Add(byte(0),
		seedHex("0000000000000000000000000000000000000000000000000000000000000000"),
		[]byte{}, uint(0), byte(16))
	// Seed#3: Kuznyechik, 17 bytes (partial final block, K2 path), truncated tag=7.
	// 17 % 16 = 1 → the final block has 1 data byte + 0x80-padding → K2 path.
	f.Add(byte(0),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a11"),
		uint(9), byte(7))
	// Seed#4: Magma, 7 bytes (partial final block, K2 path), truncated tag=3.
	// 7 < 8 → the single block is partially filled → K2 path.
	f.Add(byte(1),
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("92def06b3c130a"),
		uint(3), byte(3))
	// Seed#5: Kuznyechik, 64 bytes (4 blocks, K1 path), truncated tag=8 (A.1.6 width).
	f.Add(byte(0),
		seedHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		seedHex("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"),
		uint(5), byte(8))
	// Seed#6: Magma, 32 bytes (K1 path), truncated tag=4 (A.2.6 width).
	f.Add(byte(1),
		seedHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		seedHex("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41"),
		uint(4), byte(4))

	f.Fuzz(func(t *testing.T, sel byte, rndKey, msg []byte, split uint, tagSizeHint byte) {
		key := fixLen(rndKey, 32)

		var mine *mynew.OMAC
		var ref *gost.OMAC
		var err error
		if sel&1 == 0 {
			tagSize := 1 + int(tagSizeHint)%16 // [1, 16]
			mine = mynew.New(kuznyechik.NewCipher(key), tagSize)
			ref, err = gost.NewOMAC(gost.NewKuznyechikCipher(key), tagSize)
		} else {
			tagSize := 1 + int(tagSizeHint)%8 // [1, 8]
			mine = mynew.New(magma.NewCipher(key), tagSize)
			ref, err = gost.NewOMAC(gost.NewMagmaCipher(key), tagSize)
		}
		if err != nil {
			t.Fatalf("gost.NewOMAC: %v", err)
		}

		// Clean-room side: multi-split streaming derived from split.
		// Two cut-points are extracted; the message is written in up to 3 segments.
		if len(msg) > 0 {
			n := len(msg)
			off0 := int(split % uint(n+1))
			off1 := int((split / uint(n+1)) % uint(n+1))
			cuts := []int{off0, off1}
			sort.Ints(cuts)
			prev := 0
			for _, c := range cuts {
				if c > prev {
					mine.Write(msg[prev:c])
					prev = c
				}
			}
			mine.Write(msg[prev:])
		} else {
			mine.Write(msg)
		}
		got := mine.Sum(nil)

		// Oracle side: one-shot.
		ref.Write(msg)
		want := ref.Sum(nil)

		if !bytes.Equal(got, want) {
			t.Fatalf("mismatch sel=%d len=%d split=%d tagHint=%d\n key=%x msg=%x\n mine=%x ref=%x",
				sel&1, len(msg), split, tagSizeHint, key, msg, got, want)
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

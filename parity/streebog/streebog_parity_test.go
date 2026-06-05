package streebogparity

import (
	"bytes"
	"math/rand"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"
	streebog "github.com/bigbes/gostcrypto/streebog"
)

// TestDiffAgainstGost compares the clean-room implementation against the
// gostcryptocompat black-box oracle over random-length messages, for both 256
// and 512 output sizes.
func TestDiffAgainstGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))

	// Include boundary lengths explicitly plus randomized ones.
	lengths := []int{0, 1, 7, 31, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 1000, 4096}
	for i := 0; i < 200; i++ {
		lengths = append(lengths, rng.Intn(2050))
	}

	for _, n := range lengths {
		msg := make([]byte, n)
		rng.Read(msg)

		got256 := streebog.Sum256(msg)
		ref256 := gost.Streebog256(msg)
		if !bytes.Equal(got256[:], ref256) {
			t.Fatalf("256 mismatch len=%d\n clean-room %x\n oracle     %x", n, got256, ref256)
		}

		got512 := streebog.Sum512(msg)
		ref512 := gost.Streebog512(msg)
		if !bytes.Equal(got512[:], ref512) {
			t.Fatalf("512 mismatch len=%d\n clean-room %x\n oracle     %x", n, got512, ref512)
		}
	}
}

// FuzzDiffAgainstGost is the fuzzing companion to TestDiffAgainstGost /
// TestDiffStreamingAgainstGost: it diffs the clean-room Streebog against the
// gostcryptocompat black-box oracle over a fuzzer-chosen arbitrary-length message,
// for both 256 and 512 output sizes, and additionally exercises a streaming
// (split) 512-bit Write against the one-shot oracle. Empty input is permitted
// (Streebog has no empty-input divergence).
func FuzzDiffAgainstGost(f *testing.F) {
	f.Add([]byte{}, uint(0))
	f.Add([]byte("012345678901234567890123456789012345678901234567890123456789012"), uint(7))
	f.Add(bytes.Repeat([]byte{0xfb}, 128), uint(64))

	f.Fuzz(func(t *testing.T, msg []byte, split uint) {
		got256 := streebog.Sum256(msg)
		ref256 := gost.Streebog256(msg)
		if !bytes.Equal(got256[:], ref256) {
			t.Fatalf("256 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), got256, ref256)
		}

		got512 := streebog.Sum512(msg)
		ref512 := gost.Streebog512(msg)
		if !bytes.Equal(got512[:], ref512) {
			t.Fatalf("512 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), got512, ref512)
		}

		// Streaming 512: split at a fuzzer-chosen offset, diff against one-shot.
		h := streebog.New512()
		if len(msg) > 0 {
			off := int(split % uint(len(msg)+1))
			h.Write(msg[:off])
			h.Write(msg[off:])
		} else {
			h.Write(msg)
		}
		gotStream := h.Sum(nil)
		if !bytes.Equal(gotStream, ref512) {
			t.Fatalf("streaming 512 mismatch len=%d\n clean-room %x\n oracle     %x", len(msg), gotStream, ref512)
		}
	})
}

// TestDiffStreamingAgainstGost exercises chunked Write against the oracle's
// hash.Hash streaming path.
func TestDiffStreamingAgainstGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBEEF))
	for i := 0; i < 50; i++ {
		n := rng.Intn(3000)
		msg := make([]byte, n)
		rng.Read(msg)

		h := streebog.New512()
		for off := 0; off < n; {
			chunk := rng.Intn(70) + 1
			end := off + chunk
			if end > n {
				end = n
			}
			h.Write(msg[off:end])
			off = end
		}
		got := h.Sum(nil)
		ref := gost.Streebog512(msg)
		if !bytes.Equal(got, ref) {
			t.Fatalf("streaming 512 mismatch len=%d\n clean-room %x\n oracle     %x", n, got, ref)
		}
	}
}

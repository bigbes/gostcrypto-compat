// Differential test: cross-check the clean-room GOST R 34.11-94 implementation
// against the in-repo gogost-backed oracle gostcryptocompat.GOSTR341194 (used here
// strictly as a BLACK BOX — its source is not read).
//
// EMPTY INPUT IS EXCLUDED on purpose. gogost and gost-engine disagree on the
// degenerate empty-message finalization (guide D1): gogost yields 981e5f3c…,
// gost-engine/Tarantool yields 3f25bc1f…. The clean-room implementation matches
// the ENGINE value (pinned in the KAT in gostr341194_test.go), so diffing it
// against the gogost oracle on empty input would (correctly) disagree. We
// therefore compare only NON-empty messages here, where gogost and the engine
// agree bit-for-bit.
package gostr341194parity

import (
	"bytes"
	. "github.com/bigbes/gostcrypto/gostr341194"
	"math/rand"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"
)

func TestDiffAgainstInternalGost(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC0FFEE))

	// Deterministic spread of lengths around block boundaries plus random
	// lengths, all strictly > 0 (empty is the documented D1 divergence).
	lengths := []int{1, 2, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 100, 255, 256, 257, 1023, 1024, 2100}
	for i := 0; i < 200; i++ {
		lengths = append(lengths, 1+rng.Intn(4096))
	}

	for _, n := range lengths {
		msg := make([]byte, n)
		rng.Read(msg)

		want := gost.GOSTR341194(msg) // black-box oracle
		got := Sum(msg)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", n, got[:], want)
		}
	}
}

// FuzzDiffAgainstInternalGost is the fuzzing companion to
// TestDiffAgainstInternalGost / TestDiffStreaming: it diffs the clean-room
// GOST R 34.11-94 against the gostcryptocompat black-box oracle over a
// fuzzer-chosen message, both one-shot and streaming (split at a fuzzer-chosen
// offset).
//
// EMPTY INPUT IS EXCLUDED (skipped) here for the same reason the Test func only
// uses lengths > 0: gogost and gost-engine disagree on the degenerate
// empty-message finalization (guide D1), and the clean-room implementation
// matches the ENGINE value, not the gogost oracle. That divergence is the known
// documented one, so we structure the fuzz to avoid it rather than asserting on
// it.
func FuzzDiffAgainstInternalGost(f *testing.F) {
	f.Add([]byte{0x00}, uint(0))
	f.Add([]byte("This is message, length=32 bytes"), uint(13))
	f.Add(bytes.Repeat([]byte{0xa5}, 257), uint(64))

	f.Fuzz(func(t *testing.T, msg []byte, split uint) {
		if len(msg) == 0 {
			t.Skip("empty input is the documented D1 gogost/engine divergence")
		}

		want := gost.GOSTR341194(msg) // black-box oracle (one-shot)

		// One-shot clean-room.
		got := Sum(msg)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("one-shot len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", len(msg), got[:], want)
		}

		// Streaming clean-room: split at a fuzzer-chosen offset.
		off := int(split % uint(len(msg)+1))
		h := New()
		h.Write(msg[:off])
		h.Write(msg[off:])
		gotStream := h.Sum(nil)
		if !bytes.Equal(gotStream, want) {
			t.Fatalf("streaming len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", len(msg), gotStream, want)
		}
	})
}

// TestDiffStreaming feeds the same random messages through the streaming
// hash.Hash interface in odd chunk sizes and diffs against the oracle.
func TestDiffStreaming(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1234))
	for i := 0; i < 100; i++ {
		n := 1 + rng.Intn(2048)
		msg := make([]byte, n)
		rng.Read(msg)

		h := New()
		for off := 0; off < len(msg); {
			chunk := 1 + rng.Intn(40)
			end := off + chunk
			if end > len(msg) {
				end = len(msg)
			}
			h.Write(msg[off:end])
			off = end
		}
		got := h.Sum(nil)
		want := gost.GOSTR341194(msg)
		if !bytes.Equal(got, want) {
			t.Fatalf("streaming len=%d mismatch:\n clean-room %x\n gostcryptocompat %x", n, got, want)
		}
	}
}

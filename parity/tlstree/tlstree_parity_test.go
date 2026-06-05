package tlstreeparity

import (
	"bytes"
	"testing"

	gostref "github.com/bigbes/gostcrypto-compat"
	cleanroom "github.com/bigbes/gostcrypto/tlstree"
)

// Test_TLSTree_Conformance diffs the clean-room impl against the in-repo
// gostcryptocompat.TLSTree oracle, across both suites and a spread of sequence
// numbers. The reference is primed with Derive(0) first to dodge the documented
// D2 zero-key startup trap; the clean-room impl is never primed because it must
// not carry that bug.
func Test_TLSTree_Conformance(t *testing.T) {
	suites := []struct {
		name   string
		newRef func([]byte) *gostref.TLSTree
		newNew func([]byte) *cleanroom.TLSTree
	}{
		{"kuznyechik", gostref.NewTLSTreeKuznyechikCTROMAC, cleanroom.NewTLSTreeKuznyechikCTROMAC},
		{"magma", gostref.NewTLSTreeMagmaCTROMAC, cleanroom.NewTLSTreeMagmaCTROMAC},
	}

	masters := [][]byte{
		bytes.Repeat([]byte{0xFF}, 32),
		bytes.Repeat([]byte{0x00}, 32),
		bytes.Repeat([]byte{0x11}, 32),
		[]byte("0123456789abcdef0123456789abcdef"),
	}

	seqs := []uint64{0, 1, 63, 64, 65, 4095, 4096, 4097, 1 << 20, 1<<32 - 1, 1 << 32, 1 << 40}

	for _, su := range suites {
		for _, master := range masters {
			for _, seq := range seqs {
				ref := su.newRef(master)
				_ = ref.Derive(0) // prime (D2)
				want := ref.Derive(seq)

				got := su.newNew(master).Derive(seq) // first call, unprimed
				if !bytes.Equal(got, want) {
					t.Fatalf("%s master=%x seq=%d:\n ref %x\n new %x", su.name, master, seq, want, got)
				}
			}
		}
	}
}

// Test_TLSTree_KAT_vs_Oracle re-pins the guide's exact Kuznyechik seq=63 hex
// vector against both the oracle (primed) and the clean-room impl (unprimed).
func Test_TLSTree_KAT_vs_Oracle(t *testing.T) {
	kFF := bytes.Repeat([]byte{0xFF}, 32)
	want := []byte{
		0x50, 0x76, 0x42, 0xd9, 0x58, 0xc5, 0x20, 0xc6,
		0xd7, 0xee, 0xf5, 0xca, 0x8a, 0x53, 0x16, 0xd4,
		0xf3, 0x4b, 0x85, 0x5d, 0x2d, 0xd4, 0xbc, 0xbf,
		0x4e, 0x5b, 0xf0, 0xff, 0x64, 0x1a, 0x19, 0xff,
	}

	ref := gostref.NewTLSTreeKuznyechikCTROMAC(kFF)
	_ = ref.Derive(0)
	if got := ref.Derive(63); !bytes.Equal(got, want) {
		t.Fatalf("oracle mismatch: got %x want %x", got, want)
	}

	if got := cleanroom.NewTLSTreeKuznyechikCTROMAC(kFF).Derive(63); !bytes.Equal(got, want) {
		t.Fatalf("clean-room mismatch: got %x want %x", got, want)
	}
}

// Fuzz_TLSTree_Conformance fuzzes the clean-room impl against the oracle over a
// random 32-byte master key and a uint64 seq, and asserts the window-boundary
// invariant.
func Fuzz_TLSTree_Conformance(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0xFF}, 32), uint64(63), false)
	f.Add(bytes.Repeat([]byte{0x00}, 32), uint64(0), false)
	f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(4096), true)

	f.Fuzz(func(t *testing.T, raw []byte, seq uint64, magma bool) {
		master := make([]byte, 32)
		copy(master, raw)

		newRef, newNew := gostref.NewTLSTreeKuznyechikCTROMAC, cleanroom.NewTLSTreeKuznyechikCTROMAC
		window := uint64(64)
		if magma {
			newRef, newNew = gostref.NewTLSTreeMagmaCTROMAC, cleanroom.NewTLSTreeMagmaCTROMAC
			window = 4096
		}

		ref := newRef(master)
		_ = ref.Derive(0)
		gotRef := ref.Derive(seq)
		gotNew := newNew(master).Derive(seq)
		if !bytes.Equal(gotRef, gotNew) {
			t.Fatalf("mismatch master=%x seq=%d magma=%v\n ref: %x\n new: %x",
				master, seq, magma, gotRef, gotNew)
		}

		base := seq - (seq % window)
		k0 := newNew(master).Derive(base)
		kIn := newNew(master).Derive(base + window - 1)
		kOut := newNew(master).Derive(base + window)
		if !bytes.Equal(k0, kIn) {
			t.Fatalf("intra-window key changed: master=%x base=%d window=%d", master, base, window)
		}
		if bytes.Equal(k0, kOut) {
			t.Fatalf("cross-window key unchanged: master=%x base=%d window=%d", master, base, window)
		}
	})
}

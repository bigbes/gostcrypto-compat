package kexp15parity

import (
	"bytes"
	"encoding/hex"
	. "github.com/bigbes/gostcrypto/kexp15"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"
)

func mustHexF(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestKexp15Conformance asserts both the in-repo oracle and the clean-room
// impl reproduce the pinned Magma etalon.
func TestKexp15Conformance(t *testing.T) {
	shared := mustHexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	cipherKey := mustHexF("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637")
	macKey := mustHexF("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f")
	iv := mustHexF("67bed654")
	want := mustHexF("cfd5a12d5b81b6e1e99c916d07900c6ac12703fb3abded55567bf3742c899c755dafe7b42e3a8bd9")

	ref, err := gost.Kexp15(gost.KexpMagma, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("gost.Kexp15: %v", err)
	}
	if !bytes.Equal(ref, want) {
		t.Fatalf("oracle disagrees with pinned vector:\n got  %x\n want %x", ref, want)
	}

	got, err := Kexp15(KexpMagma, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("Kexp15: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("clean-room mismatch:\n got  %x\n want %x", got, want)
	}
}

// fixKey clamps b to exactly n bytes (zero-padded / truncated).
func fixKey(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

func FuzzKexp15Conformance(f *testing.F) {
	f.Add(
		mustHexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		mustHexF("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637"),
		mustHexF("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f"),
		mustHexF("67bed654"),
		false,
	)

	f.Fuzz(func(t *testing.T, shared, cipherRaw, macRaw, ivRaw []byte, kuz bool) {
		if len(shared) == 0 {
			shared = []byte{0x01}
		}
		refVariant := gost.KexpMagma
		myVariant := KexpMagma
		ivLen := 4
		if kuz {
			refVariant = gost.KexpKuznyechik
			myVariant = KexpKuznyechik
			ivLen = 8
		}
		cipherKey := fixKey(cipherRaw, 32)
		macKey := fixKey(macRaw, 32)
		iv := fixKey(ivRaw, ivLen)

		ref, errRef := gost.Kexp15(refVariant, shared, cipherKey, macKey, iv)
		got, errGot := Kexp15(myVariant, shared, cipherKey, macKey, iv)

		if (errRef == nil) != (errGot == nil) {
			t.Fatalf("error mismatch: ref=%v mynew=%v", errRef, errGot)
		}
		if errRef != nil {
			return
		}
		if !bytes.Equal(ref, got) {
			t.Fatalf("differential mismatch (kuz=%v):\n ref   %x\n mynew %x", kuz, ref, got)
		}
	})
}

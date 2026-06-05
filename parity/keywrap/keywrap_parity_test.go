package keywrapparity

import (
	"bytes"
	"encoding/hex"
	. "github.com/bigbes/gostcrypto/keywrap"
	"testing"

	gost "github.com/bigbes/gostcrypto-compat"
)

// pick maps an S-box name to both the clean-room and in-repo selectors.
func pick(name string) (Sbox, *gost.Sbox) {
	switch name {
	case "tc26-z":
		return SboxTC26Z, gost.SboxTC26Z
	case "cryptopro-a":
		return SboxCryptoProA, gost.SboxCryptoProA
	}
	panic("unknown sbox " + name)
}

// TestKeyWrapCryptoPro_Differential drives the clean-room impl and the in-repo
// gostcryptocompat oracle through identical inputs and asserts byte-for-byte
// equality of the 44-byte blob, on BOTH S-boxes. The tc26-Z leg additionally
// pins the guide's KAT.
func TestKeyWrapCryptoPro_Differential(t *testing.T) {
	mh := func(s string) []byte { return mustHex(t, s) }

	cases := []struct {
		name, sbox    string
		kek, ukm, cek []byte
		wantPinned    []byte // nil when no KAT pinned for this S-box
	}{
		{
			name:       "tc26z-kat",
			sbox:       "tc26-z",
			kek:        mh(katKEK),
			ukm:        mh(katUKM),
			cek:        mh(katSession),
			wantPinned: mh(katWrapped),
		},
		{
			name: "tc26z-other",
			sbox: "tc26-z",
			kek:  mh("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
			ukm:  mh("a1b2c3d4e5f60718"),
			cek:  mh("0011223344556677889900aabbccddeeff102030405060708090a0b0c0d0e0f0"),
		},
		{
			name: "cryptopro-a",
			sbox: "cryptopro-a",
			kek:  mh(katKEK),
			ukm:  mh(katUKM),
			cek:  mh(katSession),
		},
		{
			name: "cryptopro-a-other",
			sbox: "cryptopro-a",
			kek:  mh("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
			ukm:  mh("00ff00ff00ff00ff"),
			cek:  mh("deadbeefcafebabe0123456789abcdeffedcba98765432100f1e2d3c4b5a6978"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newSbox, repoSbox := pick(tc.sbox)

			gotNew, err := KeyWrapCryptoPro(newSbox, tc.kek, tc.ukm, tc.cek)
			if err != nil {
				t.Fatalf("clean-room KeyWrapCryptoPro: %v", err)
			}
			gotRepo, err := gost.KeyWrapCryptoPro(repoSbox, tc.kek, tc.ukm, tc.cek)
			if err != nil {
				t.Fatalf("oracle KeyWrapCryptoPro: %v", err)
			}
			if !bytes.Equal(gotNew, gotRepo) {
				t.Fatalf("clean-room vs oracle mismatch (sbox=%s)\n new: %x\nrepo: %x",
					tc.sbox, gotNew, gotRepo)
			}
			if tc.wantPinned != nil && !bytes.Equal(gotNew, tc.wantPinned) {
				t.Fatalf("KAT mismatch (sbox=%s)\n got: %x\nwant: %x",
					tc.sbox, gotNew, tc.wantPinned)
			}
		})
	}
}

// FuzzKeyWrapCryptoPro_Differential expands coverage across both S-boxes,
// asserting the clean-room impl always agrees with the in-repo oracle.
func FuzzKeyWrapCryptoPro_Differential(f *testing.F) {
	seed := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	kek := seed(katKEK)
	ukm := seed(katUKM)
	cek := seed(katSession)
	for _, name := range []string{"tc26-z", "cryptopro-a"} {
		f.Add(name, append(append(append([]byte{}, kek...), ukm...), cek...))
	}

	f.Fuzz(func(t *testing.T, sbox string, raw []byte) {
		if sbox != "tc26-z" && sbox != "cryptopro-a" {
			return
		}
		buf := make([]byte, 72)
		copy(buf, raw)
		k, u, c := buf[0:32], buf[32:40], buf[40:72]

		newSbox, repoSbox := pick(sbox)

		gotNew, err := KeyWrapCryptoPro(newSbox, k, u, c)
		if err != nil {
			t.Fatalf("clean-room KeyWrapCryptoPro: %v", err)
		}
		gotRepo, err := gost.KeyWrapCryptoPro(repoSbox, k, u, c)
		if err != nil {
			t.Fatalf("oracle KeyWrapCryptoPro: %v", err)
		}
		if !bytes.Equal(gotNew, gotRepo) {
			t.Fatalf("mismatch (sbox=%s)\n kek=%x ukm=%x cek=%x\n new=%x\nrepo=%x",
				sbox, k, u, c, gotNew, gotRepo)
		}
	})
}

package kdftreeparity

import (
	"bytes"
	"encoding/hex"
	. "github.com/bigbes/gostcrypto/kdftree"
	"testing"

	gostref "github.com/bigbes/gostcrypto-compat"
	"go.stargrave.org/gogost/v7/gost34112012256"
)

func mustHexG(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// Differential conformance against the in-repo oracle (gostcryptocompat), the
// pinned authoritative KAT-1 vector, and raw gogost KDF.Derive (32B only, D1).
func TestKDFTree256Conformance(t *testing.T) {
	key := mustHexG(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	cases := []struct {
		name      string
		label     []byte
		seed      []byte
		keyOutLen int
		want      string // "" => no pinned etalon, cross-check refs only
	}{
		{
			name:      "KAT-1/64B",
			label:     mustHexG(t, "26BDB878"),
			seed:      mustHexG(t, "AF21434145656378"),
			keyOutLen: 64,
			want: "22B6837845C6BEF65EA71672B265831086D3C76AEBE6DAE91CAD51D83F79D16B" +
				"074C9330599D7F8D712FCA54392F4DDDE93751206B3584C8F43F9E6DC51531F9",
		},
		{
			name:      "KAT-2/32B",
			label:     mustHexG(t, "26BDB878"),
			seed:      mustHexG(t, "AF21434145656378"),
			keyOutLen: 32,
			want:      "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := KDFTree256(key, tc.label, tc.seed, 1, tc.keyOutLen)
			if len(got) != tc.keyOutLen {
				t.Fatalf("len = %d, want %d", len(got), tc.keyOutLen)
			}
			// Reference 1: in-repo corrected iterator.
			if ref := gostref.KDFTree2012_256(key, tc.label, tc.seed, tc.keyOutLen); !bytes.Equal(got, ref) {
				t.Fatalf("mismatch vs gostcryptocompat:\n got %x\n ref %x", got, ref)
			}
			// Reference 2: pinned authoritative etalon, when present.
			if tc.want != "" {
				if want := mustHexG(t, tc.want); !bytes.Equal(got, want) {
					t.Fatalf("mismatch vs pinned vector:\n got  %x\n want %x", got, want)
				}
			}
			// Reference 3: raw gogost — ONLY valid for the 32-byte single-block case (D1).
			if tc.keyOutLen == 32 {
				ref := gost34112012256.NewKDF(key).Derive(nil, tc.label, tc.seed)
				if !bytes.Equal(got, ref) {
					t.Fatalf("mismatch vs gogost KDF.Derive:\n got %x\n ref %x", got, ref)
				}
			}
		})
	}
}

func FuzzKDFTree256Conformance(f *testing.F) {
	f.Add([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"+
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
		[]byte("\x26\xbd\xb8\x78"), []byte("\xaf\x21\x43\x41\x45\x65\x63\x78"), uint8(64))
	f.Add([]byte("short-key"), []byte("level1"), []byte("\x00\x00\x00\x00\x00\x00\x00\x01"), uint8(32))

	f.Fuzz(func(t *testing.T, rawKey, label, seed []byte, lenSel uint8) {
		key := make([]byte, 32)
		copy(key, rawKey)
		keyOutLen := 32
		if lenSel&1 == 1 {
			keyOutLen = 64
		}

		got := KDFTree256(key, label, seed, 1, keyOutLen)
		if len(got) != keyOutLen {
			t.Fatalf("len = %d, want %d", len(got), keyOutLen)
		}

		if ref := gostref.KDFTree2012_256(key, label, seed, keyOutLen); !bytes.Equal(got, ref) {
			t.Fatalf("mismatch vs gostcryptocompat (len=%d):\n got %x\n ref %x", keyOutLen, got, ref)
		}

		if keyOutLen == 32 {
			ref := gost34112012256.NewKDF(key).Derive(nil, label, seed)
			if !bytes.Equal(got, ref) {
				t.Fatalf("mismatch vs gogost KDF.Derive:\n got %x\n ref %x", got, ref)
			}
		}
	})
}

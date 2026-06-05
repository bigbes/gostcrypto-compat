package keywrapparity

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

const (
	katKEK     = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	katUKM     = "0102030405060708"
	katSession = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	katKEKUKM  = "c8ffc6b8d22ea16fdecbed3c770eb2406537e24300dd10349f57f4c647016c18"
	katCEKENC  = "940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1"
	katCEKMAC  = "e77d8bc3"
	katWrapped = "0102030405060708940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1e77d8bc3"
)

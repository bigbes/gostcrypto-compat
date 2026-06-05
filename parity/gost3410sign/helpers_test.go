package gost3410signparity

import (
	"encoding/hex"
	"math/big"
	"testing"

	curves "github.com/bigbes/gostcrypto/gost3410curves"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// testParamSetCurve builds the RFC 7091 §7.1 id-GostR3410-2001-TestParamSet
// curve from the guide's big-endian hex constants. This parameter set is not
// in the OID table (it is a test-only curve), so it is constructed here.
func testParamSetCurve() *curves.Curve {
	mustInt := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			panic("bad hex: " + s)
		}
		return n
	}
	return &curves.Curve{
		P:    mustInt("8000000000000000000000000000000000000000000000000000000000000431"),
		A:    mustInt("0000000000000000000000000000000000000000000000000000000000000007"),
		B:    mustInt("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
		Q:    mustInt("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
		X:    mustInt("0000000000000000000000000000000000000000000000000000000000000002"),
		Y:    mustInt("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
		Name: "id-GostR3410-2001-TestParamSet",
	}
}

const (
	katPrvLE = "283bec9198ce191dee7e39491f96601bc1729ad39d35ed10beb99b78de9a927a"
	katDigBE = "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5"
	katPubX  = "0bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7f"
	katPubY  = "da77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126"
	katNonce = "77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3"
	katR     = "41AA28D2F1AB148280CD9ED56FEDA41974053554A42767B83AD043FD39DC0493"
	katS     = "01456C64BA4642A1653C235A98A60249BCD6D3F746B631DF928014F6C5BF9C40"
	// raw form s||r, big-endian within each half.
	katSigSR = "01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40" +
		"41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"
)

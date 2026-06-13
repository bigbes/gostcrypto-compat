module github.com/bigbes/gostcrypto-compat

go 1.24

require (
	github.com/aead/cmac v0.0.0
	github.com/bigbes/gostcrypto v0.0.0
	go.stargrave.org/gogost/v7 v7.0.0
)

// gostcrypto is co-developed and not yet published; gogost is not resolvable
// through the stock Go proxy (custom CA + SHA-256 git upstream) and is vendored.
// aead/cmac predates Go modules (no go.mod, unmaintained) and is vendored as an
// independent test-only OMAC/CMAC oracle (see third_party/cmac/VENDORING.md).
// All three are wired in by replace until real versions are pinned at release.
replace github.com/bigbes/gostcrypto => ../gostcrypto

replace go.stargrave.org/gogost/v7 => ./third_party/gogost

replace github.com/aead/cmac => ./third_party/cmac

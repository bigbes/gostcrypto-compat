module github.com/bigbes/gostcrypto-compat

go 1.24

require (
	github.com/bigbes/gostcrypto v0.0.0
	go.stargrave.org/gogost/v7 v7.0.0
)

// gostcrypto is co-developed and not yet published; gogost is not resolvable
// through the stock Go proxy (custom CA + SHA-256 git upstream) and is vendored.
// Both are wired in by replace until real versions are pinned at release.
replace github.com/bigbes/gostcrypto => ../gostcrypto

replace go.stargrave.org/gogost/v7 => ./third_party/gogost

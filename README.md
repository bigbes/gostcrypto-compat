# gostcrypto-compat

GPL-3.0 companion to [`gostcrypto`](https://github.com/bigbes/gostcrypto). It
holds everything that touches the GPL-licensed `go.stargrave.org/gogost/v7`
reference implementation, kept in a **separate module** so `gostcrypto` itself
stays pure-Go BSD-2-Clause with zero GPL in its dependency graph.

Two things live here:

1. **Compatibility mode** — package `gostcryptocompat` (module root): a
   gogost-backed implementation of the `gostcrypto` facade API. Import this if
   you want the reference backend rather than the clean-room one. Same
   `[]byte`-in/`[]byte`-out surface as `gostcrypto`.
2. **Parity tests** — `parity/<primitive>/`: the clean-room ↔ gogost
   differential tests. Each imports the BSD clean-room primitive from
   `gostcrypto` and compares it against gogost byte-for-byte. This is the gate
   that proves `gostcrypto`'s BSD code matches the reference.

```
gostcrypto-compat/
  <facade>.go            package gostcryptocompat — gogost-backed facade + KAT/vector tests
  parity/<prim>/         clean-room (gostcrypto) ↔ gogost differential tests
  third_party/gogost/    vendored gogost (GPL-3.0)
```

## Building

`gostcrypto` is co-developed and not yet published, and gogost is not
resolvable through the stock Go proxy, so both are wired in by `replace`
directives in `go.mod`:

```
replace github.com/bigbes/gostcrypto => ../gostcrypto
replace go.stargrave.org/gogost/v7  => ./third_party/gogost
```

Check `gostcrypto` out as a sibling directory (`../gostcrypto`), then:

```sh
go build ./...
go test  ./...      # facade KAT/vector tests + all parity tests
```

### Known parity failures (in-progress refactor)

Two parity packages are currently **red**, both in the CTR/ACPKM family:

- `parity/kexp15` — `TestKexp15Conformance` / `FuzzKexp15Conformance`
- `parity/ctracpkm` — `TestDiff_PlainCTR_vs_Oracle`,
  `TestDiff_CTRACPKM_vs_Oracle`, `FuzzDiff_CTRACPKM_vs_Oracle`

These surfaced during the `gostcrypto` layout refactor that moved the clean-room
primitives from `gostcrypto/cleanroom/<prim>` to `gostcrypto/<prim>`. The
clean-room CTR keystream diverges from the gogost reference **after the first
block** (the first block matches, later blocks differ), and kexp15/ctracpkm both
build on that CTR — so this is a counter-increment / gamma-carry bug in
`../gostcrypto`'s clean-room CTR, not in this module. The remaining 15 parity
packages are green. Fixing the CTR port in `gostcrypto` is the open item; rerun
`go test ./parity/ctracpkm/ ./parity/kexp15/` to confirm once it lands.

## Licensing

GPL-3.0. This module is a **combined work**: it links and vendors
`go.stargrave.org/gogost/v7`, which is GPL-3.0, so the whole module — the
`gostcryptocompat` facade and the parity tests alike — is GPL-3.0. It is kept as
a deliberately **separate module** from `gostcrypto` so this GPL surface never
enters `gostcrypto`'s dependency graph; `gostcrypto` itself stays BSD-2-Clause
and links none of this. See [COPYING](COPYING) for the full license text.

gogost is Sergey Matveev's reference implementation, distributed only through his
own infrastructure (a GOPROXY behind a custom CA, and a SHA-256 git repository) —
neither resolves through the stock Go toolchain, so the v7.0.0 source is vendored
under `third_party/gogost` and wired in by the `replace` above. See
[third_party/gogost/UPSTREAM.md](third_party/gogost/UPSTREAM.md) for the exact
tag/commit and the update procedure.

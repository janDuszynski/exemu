<!-- GENERATED FILE — do not edit by hand.
     Regenerate with: .github/scripts/sbom.py --format markdown \
                        > docs/sbom/DEPENDENCIES.md
     CI regenerates and diffs this file; a stale copy fails the build. -->

# exemu dependency licence audit

Resolved from the committed `Cargo.lock` for `exemu-cli` v0.0.4 on `aarch64-apple-darwin`.

Scopes:

- **ship** — compiled into the distributable binary (default features, normal dependency edges).
- **build** — runs at build time only (build scripts); its code is not linked into the artifact.
- **dev** — developer tooling and tests only. Never distributed. Reached only with non-default features or dev-dependencies.

The `Verdict` column is a reading aid, not the gate. The gate is `cargo deny check licenses` against `deny.toml` (ship/build) and `deny.dev.toml` (dev); see `.github/workflows/licenses.yml`.

**Wine is not in this table and cannot be.** Wine's PE builtin DLLs are LGPL-2.1-or-later and are loaded at runtime as separate guest image files, not as cargo dependencies. Their obligations are tracked in [`docs/COMPLIANCE.md`](../COMPLIANCE.md).

## Shipping closure (38 dependencies)

| Crate | Version | Licence (SPDX) | Scope | Verdict |
| ----- | ------- | -------------- | ----- | ------- |
| `adler2` | 2.0.1 | 0BSD OR MIT OR Apache-2.0 | ship | permissive |
| `bitflags` | 1.3.2 | MIT OR Apache-2.0 | ship | permissive |
| `bitflags` | 2.13.0 | MIT OR Apache-2.0 | ship | permissive |
| `block2` | 0.6.2 | MIT | ship | permissive |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | ship | permissive |
| `crc32fast` | 1.5.0 | MIT OR Apache-2.0 | ship | permissive |
| `dispatch2` | 0.3.1 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `exemu-app` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `exemu-cli` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `exemu-core` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `exemu-cpu` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `exemu-gui` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `exemu-jit` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `exemu-loader` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `exemu-memory` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `exemu-os` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | ship | exemu's own code |
| `fdeflate` | 0.3.7 | MIT OR Apache-2.0 | ship | permissive |
| `flate2` | 1.1.9 | MIT OR Apache-2.0 | ship | permissive |
| `font8x8` | 0.3.1 | MIT | ship | permissive |
| `libc` | 0.2.186 | MIT OR Apache-2.0 | ship | permissive |
| `minifb` | 0.27.0 | MIT OR Apache-2.0 | ship | permissive |
| `miniz_oxide` | 0.8.9 | MIT OR Zlib OR Apache-2.0 | ship | permissive |
| `objc2` | 0.6.4 | MIT | ship | permissive |
| `objc2-app-kit` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-cloud-kit` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-core-data` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-core-foundation` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-core-graphics` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-core-image` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-core-text` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-core-video` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-encode` | 4.1.0 | MIT | ship | permissive |
| `objc2-foundation` | 0.3.2 | MIT | ship | permissive |
| `objc2-io-surface` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-metal` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `objc2-quartz-core` | 0.3.2 | Zlib OR Apache-2.0 OR MIT | ship | permissive |
| `png` | 0.17.16 | MIT OR Apache-2.0 | ship | permissive |
| `raw-window-handle` | 0.6.2 | MIT OR Apache-2.0 OR Zlib | ship | permissive |
| `simd-adler32` | 0.3.9 | MIT | ship | permissive |

## Build-time only (3)

| Crate | Version | Licence (SPDX) | Scope | Verdict |
| ----- | ------- | -------------- | ----- | ------- |
| `cc` | 1.2.65 | MIT OR Apache-2.0 | build | permissive |
| `find-msvc-tools` | 0.1.9 | MIT OR Apache-2.0 | build | permissive |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 | build | permissive |

## Developer tooling only — never distributed (28)

Reached only through dev-dependencies or the off-by-default `unicorn` feature of `exemu-oracle` (`publish = false`). See `deny.dev.toml` for the one recorded copyleft exception and why it is admissible.

| Crate | Version | Licence (SPDX) | Scope | Verdict |
| ----- | ------- | -------------- | ----- | ------- |
| `aho-corasick` | 1.1.4 | Unlicense OR MIT | dev | permissive |
| `bindgen` | 0.71.1 | BSD-3-Clause | dev | permissive |
| `cexpr` | 0.6.0 | Apache-2.0 OR MIT | dev | permissive |
| `clang-sys` | 1.8.1 | Apache-2.0 | dev | permissive |
| `cmake` | 0.1.58 | MIT OR Apache-2.0 | dev | permissive |
| `either` | 1.16.0 | MIT OR Apache-2.0 | dev | permissive |
| `exemu-oracle` | 0.0.4 | PolyForm-Noncommercial-1.0.0 | dev | exemu's own code |
| `glob` | 0.3.3 | MIT OR Apache-2.0 | dev | permissive |
| `heck` | 0.5.0 | MIT OR Apache-2.0 | dev | permissive |
| `itertools` | 0.13.0 | MIT OR Apache-2.0 | dev | permissive |
| `libloading` | 0.8.9 | ISC | dev | permissive |
| `log` | 0.4.33 | MIT OR Apache-2.0 | dev | permissive |
| `memchr` | 2.8.2 | Unlicense OR MIT | dev | permissive |
| `minimal-lexical` | 0.2.1 | MIT OR Apache-2.0 | dev | permissive |
| `nom` | 7.1.3 | MIT | dev | permissive |
| `pkg-config` | 0.3.33 | MIT OR Apache-2.0 | dev | permissive |
| `prettyplease` | 0.2.37 | MIT OR Apache-2.0 | dev | permissive |
| `proc-macro2` | 1.0.106 | MIT OR Apache-2.0 | dev | permissive |
| `quote` | 1.0.46 | MIT OR Apache-2.0 | dev | permissive |
| `regex` | 1.12.4 | MIT OR Apache-2.0 | dev | permissive |
| `regex-automata` | 0.4.14 | MIT OR Apache-2.0 | dev | permissive |
| `regex-syntax` | 0.8.11 | MIT OR Apache-2.0 | dev | permissive |
| `rustc-hash` | 2.1.3 | Apache-2.0 OR MIT | dev | permissive |
| `shlex` | 1.3.0 | MIT OR Apache-2.0 | dev | permissive |
| `syn` | 2.0.118 | MIT OR Apache-2.0 | dev | permissive |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 | dev | permissive |
| `unicorn-engine` | 2.1.5 | GPL-2.0 | dev | **copyleft** |
| `unicorn-engine-sys` | 2.1.5 | GPL-2.0 | dev | **copyleft** |


# Contributing to exemu

Thanks for your interest in exemu! Contributions of code, tests, docs, and bug
reports are welcome.

## Contributor License Agreement (required)

Before your first pull request can be merged, you must sign the project's
[Contributor License Agreement](CLA.md). This keeps the project owner as the
sole rights-holder, free to license, relicense, and commercialize exemu as a
whole (including under proprietary terms), while you keep the right to use your
own contributions elsewhere.

Signing is automatic and takes one comment:

1. Open your pull request as usual.
2. The **CLA Assistant** bot will comment if a signature is needed.
3. Reply on the PR with exactly:

   > I have read the CLA Document and I hereby sign the CLA

That's it — the bot records your signature and future PRs are covered until the
CLA version changes.

## Development workflow

exemu is a Rust workspace (stable toolchain). The CI gate — which every change
must pass — is:

```sh
cargo build --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

A second required gate covers licensing — see "Adding a dependency" below.

Please keep changes small and focused: one logical change (or roadmap item) per
commit, each independently green. Match the existing commit-message style:

```
<area>: <short summary>
```

where `<area>` is one of `cpu`, `os`, `loader`, `gui`, `oracle`, `docs`, etc.

Update `README.md` when a change is user-visible (a new instruction class, new
Win32 coverage, a new capability, or a change to what real binaries do). Keep
the "what works" tables honest — advertise only what is actually implemented.

## Adding a dependency

exemu has a **licence gate**, and it will fail your PR rather than let an
unvetted crate through. Before adding one:

1. Check its licence is on the allow-list in `deny.toml`. The list is
   permissive-only. **Copyleft licences — GPL, LGPL, MPL, CDDL, EPL and
   friends — are denied**, because exemu must stay licensable on the owner's
   terms. Notably `dynasmrt` is MPL-2.0 and is banned by name; the W8 JIT
   emitter is hand-rolled in-repo.
2. Prefer no dependency at all. exemu's inner layers (`core`, `memory`, `cpu`,
   `loader`) have zero third-party dependencies and that is a feature, not an
   accident.
3. Regenerate the SBOM in the same commit, or CI will tell you it is stale:

   ```sh
   .github/scripts/sbom.py --format cyclonedx \
     > docs/sbom/exemu-cli-aarch64-apple-darwin.cdx.json
   .github/scripts/sbom.py --format markdown > docs/sbom/DEPENDENCIES.md
   ```

4. Run the gate locally (needs [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny),
   itself MIT OR Apache-2.0):

   ```sh
   cargo deny --workspace --exclude-dev --exclude-unpublished \
     --locked check licenses bans sources
   cargo deny --workspace --all-features --config deny.dev.toml \
     --locked check licenses bans sources
   ```

There is exactly one recorded copyleft exception in the whole project:
`unicorn-engine` (GPL-2.0), the differential oracle's reference CPU. It is
admissible only because it is dev-only, behind an off-by-default feature, in a
`publish = false` crate, and compared against *behaviourally* with no source
read. `deny.dev.toml` explains this at length. Do not add a second exception
without reading it first.

## Wine, and what must never happen to it

exemu runs Wine's PE builtin DLLs (LGPL-2.1-or-later) as **guest image files**
loaded at runtime. They are not a dependency and never become one. The
invariant, which CI checks:

- No Wine source is ever vendored, compiled, or transcribed into any exemu
  crate. The repository tracks no C/C++/assembly source at all.
- Wine binaries are never committed — `example_exe/` is git-ignored and stays
  that way.
- Nothing embeds Wine bytes into an exemu binary (`include_bytes!` must not
  escape its crate).

```sh
cargo build --release -p exemu-cli
.github/scripts/separability.sh target/release/exemu
```

Read [`docs/CLEANROOM.md`](docs/CLEANROOM.md) **before** opening anything Wine
publishes: it defines which crates may look at Wine's public interface
headers and which must never see them at all. Redistribution obligations for
the Wine DLLs are in [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md).

## CPU correctness: the differential oracle

exemu's software CPU is validated against a reference x86 (Unicorn / QEMU TCG)
by the dev-only `exemu-oracle` crate. If you touch the interpreter
(`crates/cpu`), run it before sending your PR:

```sh
cargo run -p exemu-oracle --features unicorn --release -- fuzz --bits both --count 2M
```

It must report `ZERO DIVERGENCE`. The `unicorn` feature builds a bundled C
library (needs `cmake`), so it is **off by default** — the normal
`cargo build/test --workspace` never requires it, and neither does CI.

## Reporting bugs

Please include the exact binary/command, the emulator's fault report (the
register dump + rip trail it prints), and what you expected to happen.

## License

By contributing, you agree that your contributions are provided under the terms
of the [CLA](CLA.md) and may be distributed as part of exemu under the project's
license — the [PolyForm Noncommercial License 1.0.0](LICENSE.md) today, and any
other terms at the owner's discretion going forward.

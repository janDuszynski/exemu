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

Please keep changes small and focused: one logical change (or roadmap item) per
commit, each independently green. Match the existing commit-message style:

```
<area>: <short summary>
```

where `<area>` is one of `cpu`, `os`, `loader`, `gui`, `oracle`, `docs`, etc.

Update `README.md` when a change is user-visible (a new instruction class, new
Win32 coverage, a new capability, or a change to what real binaries do). Keep
the "what works" tables honest — advertise only what is actually implemented.

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

# exemu redistribution compliance checklist

**Status: nothing in Part B has been executed, because no exemu release has
bundled Wine yet.** This document exists so that the first one cannot skip it.
Part A is live and enforced in CI today.

> **This is not legal advice, and it is not a substitute for counsel.** It is a
> release engineer's punch-list written from the licence texts. The
> architecture it describes — executing an LGPL library's machine code as guest
> instructions rather than calling it through a host ABI — is legally novel;
> no case law, FSF opinion or SFLC guidance covers it. **A qualified IP lawyer
> must review this document and the shipped bundle before any artifact
> containing Wine leaves the building.** Where a judgement call exists, this
> file records the conservative option and flags the question rather than
> resolving it.

---

## The two obligations, which are not the same thing

Conflating these is the failure mode this document exists to prevent.

| | **1. exemu's own dependency licences** | **2. The Wine PE DLL set** |
|---|---|---|
| What | Rust crates compiled into exemu's binaries | LGPL-2.1-or-later PE builtin DLLs |
| Relationship | linked into the artifact | loaded at runtime as separate guest image *files* |
| Appears in `cargo tree`? | yes | **no** — not a cargo dependency |
| Enforced by | `cargo deny` (`deny.toml`, `deny.dev.toml`) | this document, Part B |
| Current state | permissive-only, green in CI | not yet shipped |

A green `cargo deny check licenses` means *no copyleft **crate** in the Rust
dependency closure*. It does **not** mean *no LGPL anywhere in the product*.
Anyone reading the CI badge as the latter has been misled; both `deny.toml` and
the SBOM say so in-file.

---

## Part A — exemu's own artifacts (enforced today)

Every item is checked by `.github/workflows/licenses.yml` on every push and PR.
Run them locally with the commands given.

- [ ] **A1. Every crate compiled into a shipped binary is under a permitted
      licence.** Allow-list is `deny.toml`; there are **no exceptions in it**.

      cargo deny --workspace --exclude-dev --exclude-unpublished \
        --locked check licenses bans sources

- [ ] **A2. The only copyleft anywhere in the workspace is the dev-only GPL
      differential oracle**, and it is named as an exception rather than
      permitted by a blanket rule.

      cargo deny --workspace --all-features --config deny.dev.toml \
        --locked check licenses bans sources

- [ ] **A3. The GPL oracle is provably absent from the shipping graph.**
      `unicorn-engine` (GPL-2.0) is an optional dependency of `exemu-oracle`
      alone, behind the `unicorn` feature, which is off by default;
      `exemu-oracle` is `publish = false`. Verify by inspection:

      cargo tree --target aarch64-apple-darwin -p exemu-cli --edges normal

      It must contain no `unicorn` node. The comparison against Unicorn is
      behavioural only — no Unicorn or QEMU source is ever read
      (`docs/CLEANROOM.md`, Class A).

- [ ] **A4. The SBOM is current.** It is a pure function of `Cargo.lock`, the
      target triple and the generator, so a stale copy is a build failure.

      .github/scripts/sbom.py --format cyclonedx \
        > docs/sbom/exemu-cli-aarch64-apple-darwin.cdx.json
      .github/scripts/sbom.py --format markdown \
        > docs/sbom/DEPENDENCIES.md
      git diff --exit-code docs/sbom/

- [ ] **A5. No Wine code is in exemu's sources or compiled artifacts.**

      cargo build --release -p exemu-cli
      .github/scripts/separability.sh target/release/exemu

- [ ] **A6. Third-party attribution ships with the artifact.** Every licence in
      the shipping closure (MIT, Apache-2.0, Zlib, 0BSD) requires the copyright
      notice and licence text to accompany binary distribution. Generate
      `THIRD_PARTY_LICENSES` from `docs/sbom/DEPENDENCIES.md` and place it in
      the `.app` bundle's `Contents/Resources/`.
      **Not yet automated — see "Known gaps" below. This is a real obligation
      that is currently unmet for any binary distribution.**

### Two things a scanner will flag that are not problems

Both are real entries in `Cargo.lock` and both will light up an automated
licence scanner. Neither is a defect; the explanation is recorded here so it
does not have to be rediscovered under diligence time pressure.

- **`r-efi` declares `MIT OR Apache-2.0 OR LGPL-2.1-or-later`.** The expression
  is a *disjunction*: exemu elects MIT, and `cargo deny` records that election.
  `r-efi` is additionally a UEFI-target dependency of `getrandom` and is not
  built for any target exemu ships. It appears in `Cargo.lock` and nowhere in
  a produced binary. **This is not the Wine LGPL; do not conflate the two.**
- **`unicorn-engine` / `unicorn-engine-sys` declare `GPL-2.0`** (the deprecated
  SPDX identifier for `GPL-2.0-only`, hence the parse warning `cargo deny`
  prints). These are the differential oracle's reference CPU — see A2 and A3.
  They are the only copyleft crates in the workspace and the only recorded
  exception.

---

## Part B — the Wine PE DLL set (LGPL-2.1-or-later)

Applies to **any** artifact that bundles, downloads, or otherwise distributes
Wine's PE builtin DLLs (`ntdll.dll`, `kernel32.dll`, `kernelbase.dll`,
`user32.dll`, `gdi32.dll`, `win32u.dll`, `wow64*.dll`, `msvcrt`/`ucrtbase`,
`comctl32.dll`, …). Shipping them in object-code form triggers LGPL-2.1 §4 and,
for exemu as "a work that uses the Library", §6.

### B0 — Pin and record the exact Wine build

- [ ] **B0.1** Record, in a committed provenance manifest, the exact Wine
      **version tag and git commit** the shipped DLLs were produced from.
- [ ] **B0.2** Record the **build configuration**, including
      `--enable-archs=i386,x86_64` (required for new-WoW64) and the mingw-w64
      toolchain version used for the PE cross-build.
- [ ] **B0.3** Record, per shipped file, its **provenance**: cross-built
      in-house, or lifted from a named WineHQ/distro build (name the package
      and its version).
- [ ] **B0.4** Record the **SHA-256 of every shipped DLL**, so drift against
      the pinned upstream build is detectable.
- [ ] **B0.5** Target **Wine 11.x** unless a specific documented reason forces
      otherwise — the PE/Unix boundary and new-WoW64 were declared complete
      only in 11.0 (Jan 2026); 9.0/10.x boundary layouts differ.

### B1 — Licence text (LGPL-2.1 §6, "You must supply a copy of this License")

- [ ] **B1.1** Ship the **verbatim** text of the GNU Lesser General Public
      License, version 2.1 — Wine's own `COPYING.LIB`. Do not paraphrase, do
      not link instead of shipping, do not substitute LGPL-3.0.
- [ ] **B1.2** Record that Wine is licensed **"LGPL-2.1-or-later"**, not
      "LGPL-2.1". The "or later" clause is part of the grant and a downstream
      redistributor may elect LGPL-3.0 terms; say so rather than flattening it.
- [ ] **B1.3** Place the text where a user can find it without running the
      product: `Contents/Resources/licenses/wine/COPYING.LIB` in the `.app`
      bundle, and in the release archive root.

### B2 — Copyright notices (LGPL-2.1 §1, §6)

- [ ] **B2.1** Retain **all** Wine copyright notices from the source
      distribution — `AUTHORS`, `COPYING.LIB`, `LICENSE`, and any per-file
      notices carried in the shipped tree. Do not strip, summarise or
      "consolidate" them.
- [ ] **B2.2** Give **prominent notice** with each copy of exemu that the
      Wine library is used in it and is covered by the LGPL. "Prominent" means
      a user encounters it in the ordinary course of using the product — not
      only inside a nested resources directory. Suggested text:

      > exemu runs the Wine project's PE builtin DLLs, which are free software
      > licensed under the GNU Lesser General Public License, version 2.1 or
      > (at your option) any later version. The complete corresponding source
      > code, and the terms of that licence, are provided with this product;
      > see licenses/wine/. Wine is a trademark of its respective owners and
      > exemu is not affiliated with or endorsed by the Wine project.

- [ ] **B2.3** If exemu displays copyright notices at runtime (About box,
      splash, `--version`), **include Wine's copyright notice among them**,
      with a reference directing the user to the licence copy. LGPL-2.1 §6
      requires this explicitly when the work displays notices at all.

### B3 — Source availability (LGPL-2.1 §4 and §6a/§6c/§6d)

Pick **one** route and execute it fully. Do not half-do two.

- [ ] **B3.1 (preferred — §6d)** Publish the exact Wine source corresponding to
      the shipped binaries at the **same place** the binaries are offered from,
      with equivalent access. If exemu is downloaded from a release page, the
      matching `wine-<version>.tar.xz` (plus any patches, see B4) is linked
      from that same page.
- [ ] **B3.2 (alternative — §6c)** Include a **written offer, valid for at
      least three years**, to supply the complete corresponding
      machine-readable source for no more than the cost of distribution.
      Template:

      > WRITTEN OFFER — SOURCE CODE FOR WINE COMPONENTS
      >
      > This product includes the Wine project's PE builtin DLLs, licensed
      > under the GNU Lesser General Public License version 2.1 or later.
      >
      > For a period of three (3) years from the date you received this
      > product, we will supply, to anyone who asks, a complete
      > machine-readable copy of the corresponding source code for those
      > components — including any modifications we made — for a charge no
      > greater than our cost of physically performing the distribution.
      >
      > Requests to: <MAINTAINED CONTACT ADDRESS>
      > Please quote the exemu version and the Wine version recorded in
      > licenses/wine/PROVENANCE.
      >
      > The source is also available without charge at: <STABLE URL>

- [ ] **B3.3** The offer's contact address and URL must be **live and
      monitored for the full three years**, outliving any single release.
      An offer nobody answers is a licence violation, not a formality.
- [ ] **B3.4** The source published must be the *corresponding* source — the
      exact tree the shipped binaries were built from (B0.1), not "whatever
      upstream has today".

### B4 — Modification policy

- [ ] **B4.1** **Default: ship unmodified upstream Wine PE DLLs.** Verify by
      comparing the SHA-256 of each shipped DLL against the pinned upstream
      build (B0.4).
- [ ] **B4.2** If a change is unavoidable, fix it on **exemu's** native side
      first. Patching Wine is the last resort, not the first.
- [ ] **B4.3** If Wine must be patched, **upstream the patch to WineHQ** where
      possible, so the shipped DLL returns to unmodified upstream.
- [ ] **B4.4** Any patch that actually ships must be **published under
      LGPL-2.1-or-later**, carry **prominent per-file change notices stating
      what was changed and on what date** (LGPL-2.1 §2a), and be included in
      the source made available under B3.
- [ ] **B4.5** **Never carry proprietary logic inside a Wine DLL.** Proprietary
      value lives in exemu's own crates, or in a separate component loaded *at*
      Wine's driver interface — never compiled into Wine.

### B5 — User replaceability (LGPL-2.1 §6b)

- [ ] **B5.1** Document how a user substitutes their own build of the Wine PE
      DLLs. Architecturally this is free — exemu loads them as external files —
      which is exactly why it is worth demonstrating.
- [ ] **B5.2** **Test it, and keep the test as evidence:** point exemu at a
      user-supplied, interface-compatible Wine DLL directory and confirm it
      loads and runs. Automate this as a release-gate test.
- [ ] **B5.3** Confirm exemu does not technically prevent replacement — no
      signature pinning, no hash allow-list, no bundle-integrity check that
      would reject a user's own Wine build.
- [ ] **B5.4** **Question for counsel:** §6(b)'s safe harbour is written for
      "a copy of the library already present on the user's computer system".
      A bundled copy arguably does not meet that wording, which is why B3
      (source availability under §6a/§6c/§6d) is treated as the primary route
      and §6(b) as reinforcement, not as the sole basis. Confirm.

### B6 — exemu's own distribution terms

- [ ] **B6.1** LGPL-2.1 §6 permits distributing the combined work under terms
      of your choice **provided those terms permit modification of the work for
      the customer's own use, and reverse engineering for debugging such
      modifications.** exemu is currently licensed **PolyForm Noncommercial
      1.0.0**. **Counsel must confirm that exemu's distribution terms —
      PolyForm-NC or whatever commercial licence replaces it — actually grant
      those two permissions.** A licence that forbids reverse engineering
      would be incompatible with §6 on its face. This is a live question, not
      a formality.
- [ ] **B6.2** LGPL-2.1 §6 also requires that the "work that uses the Library"
      be distributed in a form that includes "any data and utility programs
      needed for reproducing the executable from it". Confirm scope with
      counsel.

### B7 — Trademark and attribution hygiene

- [ ] **B7.1** Do not imply Wine project endorsement or affiliation. Use the
      Wine name nominatively (to identify the software), never as a badge.
- [ ] **B7.2** Same for Microsoft marks: "Windows", "Win32" and API names are
      used nominatively to describe compatibility, never as branding.

---

## Part C — bundle layout

The layout the checklist assumes. A release that does not match it has
probably dropped a required file.

    exemu.app/Contents/
      MacOS/exemu                          exemu's own binary — no Wine code in it
      Resources/
        THIRD_PARTY_LICENSES               A6: permissive crate notices
        sbom.cdx.json                      A4: the shipping bill of materials
        licenses/wine/
          COPYING.LIB                      B1.1: verbatim LGPL-2.1
          AUTHORS                          B2.1: Wine copyright notices
          PROVENANCE                       B0: version, commit, build flags, hashes
          WRITTEN-OFFER                    B3.2: the three-year source offer
          MODIFICATIONS                    B4.4: patches, or "none — unmodified upstream"
      Wine/                                the guest images themselves — separate
        ntdll.dll  kernel32.dll  ...       files, loaded at runtime, replaceable

The `Wine/` directory being a plain directory of ordinary files that the user
can replace **is** the separability argument. Anything that compiles those
bytes into `MacOS/exemu` destroys it.

---

## Part D — release gate

Run in order. Every step must pass; there is no "ship anyway".

1. `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`
2. `cargo deny --workspace --exclude-dev --exclude-unpublished --locked check licenses bans sources`
3. `cargo deny --workspace --all-features --config deny.dev.toml --locked check licenses bans sources`
4. `.github/scripts/sbom.py --format cyclonedx > docs/sbom/exemu-cli-aarch64-apple-darwin.cdx.json`
   `.github/scripts/sbom.py --format markdown > docs/sbom/DEPENDENCIES.md`
   `git diff --exit-code docs/sbom/`
5. `cargo build --release -p exemu-cli && .github/scripts/separability.sh target/release/exemu`
6. Part A6 — `THIRD_PARTY_LICENSES` regenerated and present in the bundle
7. **If and only if the release bundles Wine:** every box in Part B ticked,
   and the bundle matches Part C
8. Counsel sign-off on record (Part E) — required before the first
   Wine-bundling release, not after it

---

## Part E — what is *not* settled

Recorded so nobody mistakes this checklist for a clearance.

1. **The §6 qualification is legally novel.** LGPL-2.1 §6 was drafted for a
   host program that *calls* a library through an ABI. exemu *executes the
   library's machine code as guest instructions* inside its own CPU. No court,
   FSF opinion, SFLC guidance or settlement addresses that. The
   CrossOver/Proton/GPTK arrangements are **packaging precedents, not legal
   validations** — and the Software Freedom Conservancy actively lists Wine as
   an ongoing LGPL compliance project. **Requires a formal opinion of counsel**
   (acquisition item A35) before the host is treated as safely proprietary.
2. **The clean-room firewall is a defence record, not immunity.**
   `docs/CLEANROOM.md` permits the boundary layer to be written from Wine's
   *published interface headers*. LGPL-2.1 §5 says object code using material
   from an LGPL header may be a derivative work unless usage is limited to
   trivial parameters and small (<10-line) macros; Wine's `gdi_driver.h`
   (hundreds of lines, 80+ function pointers) exceeds that safe harbour, and
   interface copyrightability after *Oracle v. Google* is unresolved. A
   single-developer temporal separation is legally weaker than a two-team
   split. **Requires counsel** (acquisition item A36).
3. **PolyForm-NC versus LGPL §6's modification/reverse-engineering
   permissions.** See B6.1. Unresolved.
4. **`.github/scripts/separability.sh` proves separability, not
   non-derivation.** It shows no Wine code is compiled into exemu. It says
   nothing about whether exemu's own boundary code is a derivative work of
   Wine's interfaces. Do not cite it for the second claim.

---

## Known gaps in this checklist's own automation

Stated plainly rather than left for a reader to discover.

- **A6 (`THIRD_PARTY_LICENSES`) is not automated and not currently produced.**
  Every permissive licence in the shipping closure requires its copyright
  notice and licence text to accompany binary distribution. `cargo deny`
  checks *which* licences are present; it does not gather their texts. Until a
  generator exists, **any binary distribution of exemu is already out of
  compliance with its permissive dependencies** — independently of anything to
  do with Wine. This is the most immediately actionable item in this document.
- **The SBOM covers `aarch64-apple-darwin` only.** That is the shipping target.
  Pass `--target` to `.github/scripts/sbom.py` for others; nothing is committed
  for them.
- **Security advisories are not checked.** `cargo deny check advisories` is
  deliberately out of scope here (it is acquisition item A13) so that a new
  CVE in an unrelated crate cannot fail a licensing gate.
- **`[bans].wildcards` is disabled** — see the recorded reason and the one-line
  fix in `deny.toml`.

---

## References

- `deny.toml`, `deny.dev.toml` — the enforced licence policy
- `docs/sbom/DEPENDENCIES.md` — the current dependency/licence audit
- `docs/sbom/exemu-cli-aarch64-apple-darwin.cdx.json` — CycloneDX 1.5 SBOM
- `docs/CLEANROOM.md` — module-scoped clean-room and provenance policy
- `.github/workflows/licenses.yml` — the CI gate
- Wine's `COPYING.LIB` — the authoritative LGPL-2.1 text for the shipped DLLs

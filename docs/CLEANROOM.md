# exemu clean-room & provenance policy (module-scoped)

Effective 2026-07-10. This policy replaces the prior blanket rule ("never read
Wine/ReactOS") with a **module-scoped clean-room**, adopted with the Wine
pivot: exemu runs Wine's LGPL PE builtin DLLs as *guest images* and implements
natively only the Unix side of Wine's PE/Unix boundary. The blanket ban is
operationally impossible under that architecture; this document defines what
each part of the codebase may and may not be derived from, and records the
limits of that protection honestly.

## 1. Module classes

### Class A — strictly clean-room (never-read-Wine)
`crates/cpu`, `crates/oracle`, `crates/loader`, `crates/core`,
`crates/memory`, and the future JIT crate.

- Semantics derived **only** from public primary sources: Intel SDM, AMD APM,
  the Microsoft PE/COFF specification, public `winnt.h`/`ehdata.h` from the
  Windows SDK, the published x64 ABI documentation, and Microsoft Learn.
- Engineers working on these crates **must not read** Wine source, ReactOS
  source, leaked Windows source, or decompiler output of Microsoft binaries —
  in any form, including excerpts quoted in third-party posts.
- The CPU is cross-checked against Unicorn **behaviorally only** (black-box
  input/output comparison via `crates/oracle`); Unicorn/QEMU source is never
  read.

### Class B — Wine-boundary (documented-interface work under firewall)
The future NT-syscall/unixlib boundary crates (`crates/nt` /
`crates/wine-boundary`) and the macOS display driver.

- Engineers **may** read Wine's *published architecture documentation* and
  *public interface definitions* — the PE→Unix boundary documentation, public
  `unixlib.h` / `gdi_driver.h` as interface contracts, and `.spec` export
  lists — to write an interface **specification**.
- Wherever team size permits, a **different engineer** implements from that
  specification (two-team firewall). Transcription of Wine's Unix-side `.c`
  implementation is prohibited in all cases; the goal is interface
  conformance, not code reuse.
- Every boundary commit cites, in its message or an adjacent comment, the
  public documentation or public interface header it derives from — never
  Wine implementation source.

### Class C — retired hand-written personality (historical)
`crates/os` and `crates/gui` as they existed before the pivot were written
from Microsoft Learn per-API documentation only, predate any Wine exposure,
and are being superseded by Wine guest code. Their provenance record is
preserved in §4.

## 2. The firewall

- The Class A and Class B groups are organizationally separated: **no
  engineer who wrote or will write Class A code may read Wine source or
  headers**, and each engineer's class assignment and attestation is recorded
  (see the contributor-chain register, acquisition A16′).
- **Single-developer disclosure:** while the team is one person, temporal and
  module separation plus the documented spec-then-implement discipline
  substitute for the two-team firewall *imperfectly*. This limitation is
  disclosed to counsel rather than presented as equivalent protection.

## 3. Honest limits of this policy (read before relying on it)

- A clean-room process is a **litigation-defense record, not legal
  immunity**. Its value comes from the implementer's lack of access to the
  original; a single engineer who both reads interface headers and writes
  substantially similar code is legally weaker than a true two-team split.
- LGPL-2.1 §5 states that object code using material from an LGPL header may
  be a derivative work unless usage is limited to trivial parameters and
  small (<10-line) macros. Wine's `gdi_driver.h` (hundreds of lines, 80+
  function pointers) **exceeds that safe harbor**; interface copyrightability
  after *Oracle v. Google* remains unresolved.
- Accordingly: whether the boundary layer's structure creates LGPL
  obligations is an **open legal question** referred to qualified counsel
  (acquisition A35/A36) before any binary ships. The recorded fallbacks if
  counsel is unsatisfied: a true two-team firewall with a lawyer-reviewed
  non-access wall, or releasing the boundary layer's own source under LGPL.
- Shipping Wine's PE DLLs themselves follows the separable-artifact model
  (separate files, never linked into exemu, source availability per the
  compliance track) — also subject to the same counsel review; the
  "guest-image" execution model is legally novel and is not represented
  internally or externally as settled.

## 4. Provenance table (subsystem → source)

| Subsystem | Class | Derived from |
| --------- | ----- | ------------ |
| CPU decode/exec (`crates/cpu`) | A | Intel SDM Vol. 2, AMD APM Vol. 3 |
| CPUID model | A | Intel SDM Vol. 2A leaf tables |
| x87/SSE/AVX semantics | A | Intel SDM Vol. 1/2 + AMD APM |
| Differential oracle (`crates/oracle`) | A | Black-box behavioral diff vs Unicorn 2.1.5 (GPL-2.0, dev-only, never distributed); no Unicorn/QEMU source read |
| PE loader, relocations, imports, TLS, resources (`crates/loader`) | A | Microsoft PE/COFF spec; MS Learn; public `winnt.h` |
| x64 unwind (`core`/`loader` unwind) | A | Public `winnt.h` RUNTIME_FUNCTION/UNWIND_INFO; MS Learn "x64 exception handling" |
| TEB/PEB/`PEB.Ldr` layouts | A | Widely published public documentation; public `winternl.h` |
| Memory manager (`crates/memory`) | A | Original design; MS Learn VirtualAlloc semantics |
| Legacy Win32 personality (`crates/os`, `crates/gui`, pre-pivot) | C | MS Learn per-API reference (historical; being superseded) |
| NT syscall dispatcher seam (future) | B | Public PE→Unix architecture documentation; public dispatcher descriptions — provenance: public-interface-only, firewall-team |
| ntdll unixlib boundary (future) | B | Public `unixlib.h` interface enum as contract — public-interface-only, firewall-team, §5 caveat → counsel |
| Display driver seam (future) | B | Public `gdi_driver.h` / `win32u.spec` as version-pinned contract — public-interface-only, firewall-team, §5 caveat → counsel |

## 5. Contributor acknowledgment

CONTRIBUTING.md references this policy; CLA acceptance includes acknowledging
the module-scoped rule and the no-leaked-source attestation. Class
assignments and attestations are recorded per contributor.

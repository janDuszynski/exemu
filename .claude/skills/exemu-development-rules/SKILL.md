---
name: exemu-development-rules
description: >-
  Working rules for developing exemu — the from-scratch Windows .exe emulator
  (x86/x86-64 → Apple Silicon, Wine-class GUI/OS personality layer). Invoke
  whenever advancing exemu: implementing a roadmap item, planning next steps,
  adding a CPU instruction / Win32 API / GUI capability, or picking which model
  does which work. Covers the .know knowledge base, the example_exe test corpus,
  model orchestration, and the per-step commit discipline.
---

# exemu development rules

`exemu` loads a Windows PE (`.exe`, 32- or 64-bit) and runs it natively on an
Apple-Silicon Mac — no Windows, no Rosetta, no VM. It interprets x86/x86-64 in
software and services Win32 calls natively. The **north star** (see
`knowledge/roadmap.know`): point exemu at *any* Windows PE — console or GUI,
packed or not, C/C++/Delphi/.NET — and its real window appears on macOS, is
interactive, renders correctly, and does its job. In effect a Wine-class
Win32/NT personality layer on a from-scratch software CPU, graphics bridged to
native macOS frameworks. (The user calls this a "compiler"; it is an
**emulator** — treat the two words as the same project.)

## 1. The knowledge base lives in `.know` files — read it first

All hard-won design notes and the master plan live under `knowledge/*.know`.
These are **git-ignored** (`*.know` in `.gitignore`) — local engineering notes,
not committed source. **Read the relevant `.know` before touching code**, and
**keep them in sync** when the design changes.

| File | Covers |
| ---- | ------ |
| `knowledge/index.know` | Entry point / map of the knowledge base + fast facts + build cheatsheet |
| `knowledge/roadmap.know` | **Master TODO/plan** — phases P0–P9, each item concrete and codeable. This is the source of "next steps." |
| `knowledge/architecture.know` | Crate layout, clean-architecture rules, the three core traits, the thunk/intercept seam |
| `knowledge/cpu.know` | Instruction coverage, decoder, 32-vs-64-bit mode, correctness points |
| `knowledge/os-api.know` | Win32 surface, stdcall argc mechanism, data imports, `_initterm`, fake handles |
| `knowledge/filesystem.know` | Sandbox design, path mapping, self-extractor support |
| `knowledge/memory-layout.know` | 32-bit and 64-bit address maps |
| `knowledge/known-issues.know` | Per-exe status, the SteamSetup fault, the GUI wall, TODO |
| `knowledge/debugging.know` | Fault reporter, `--trace`, rip trail, bisecting a bad jump |
| `knowledge/extending.know` | Recipes: add an instruction, add a Win32 API, testing patterns |

Rules for the knowledge base:
- **The code wins if code and `.know` disagree** — the notes are a guide, not truth.
- When you finish a roadmap item, **tick it in `roadmap.know`** (`[ ]`→`[x]`, or `[~]` for partial) and add a line to its **Progress log** (newest first).
- Never commit `.know` files or try to un-ignore them — they are deliberately local.

## 2. Test corpus: `example_exe/` (git-ignored)

Real Windows binaries downloaded for testing live in `example_exe/` (ignored via
`example_exe/` in `.gitignore` — never committed, some are hundreds of MB).
Current corpus and what each exercises:

| Binary | Kind | Exercises |
| ------ | ---- | --------- |
| `7z2602-x64.exe` | 64-bit MSVC GUI installer | dialog drive + LZMA extract (the working end-to-end reference) |
| `Firefox Installer.exe` | 32-bit UPX-packed | self-decompression stub |
| `SteamSetup.exe` | 32-bit NSIS | archive extract — faults ~45M instr (known CPU-correctness bug) |
| `tcc.exe` | console compiler | file I/O, command line, process creation |
| `putty-*-0.84-installer.msi` | MSI | (P6.6 cabinet/MSI territory) |
| `Minesweeper-Windows-XP/`, `xmsol/` | GUI games | BitBlt, timers, mouse, GDI |
| `tcmd1156x64.exe`, Acrobat, Docker Desktop | large real installers | breadth / stress |

Use these as bring-up targets. Raise the step budget for extractors:
`exemu run --max-steps 800000000 <installer.exe>`. Sandbox output lands under
`$TMPDIR/exemu-sandbox`.

## 3. Planning uses the Workflow tool (multi-agent, ultracode)

When a change needs **planning** or is **multi-step / broad** (a new roadmap
phase, a subsystem like USER32 or x64 exceptions, a cross-cutting correctness
pass), plan and drive it with the **Workflow tool** — multi-agent orchestration
at **ultracode** scale. Author the workflow script (`export const meta` +
`agent()`/`pipeline()`/`parallel()`), fan out readers/designers/verifiers, and
stay in the loop between phases.

- **Planning workflows** run on **Fable 5** (`model: 'fable'`) **or Opus 4.8**
  (`model: 'opus'`), at high reasoning effort (`effort: 'high'`/`'xhigh'`/`'max'`).
- Prefer the standard shapes for exemu work: parallel **readers** over the
  relevant `.know` + crates → design panel → **adversarial verify** of any
  correctness claim (a wrong flag or opcode is the whole ballgame — see the
  SteamSetup fault). Verify against a reference/oracle, don't trust one pass.
- Trivial, single-file edits (like writing one doc or renaming a symbol) do
  **not** need a workflow — do them directly.

## 4. Orchestrate work across models by complexity

Route each unit of work to the cheapest model that will do it well. Map the
user's shorthand to the model enum used by the `Agent`/`Workflow` tools:

| Work | Model (enum) | User's shorthand |
| ---- | ------------ | ---------------- |
| **Most substantial / hardest / highest-value** — CPU correctness, decoder, exception unwind, JIT, tricky Win32 semantics. The **default** for real implementation. | `opus` (Opus 4.8) | "opus 4.8", "most optimal" |
| **Planning / architecture** — designing a phase, weighing trade-offs, writing the workflow. | `fable` (Fable 5) or `opus` (Opus 4.8) | "fable 5" |
| **Less complex** — mechanical edits, boilerplate Win32 stubs, test scaffolding, doc updates, straightforward instruction additions. | `sonnet` (Sonnet 4.6) | "sonet 5" |
| Trivial chores (formatting, tiny lookups) | `haiku` (Haiku 4.5) | — |

In a workflow, set `model` per `agent()` call accordingly. When unsure, prefer
`opus` for anything touching CPU/OS correctness and `sonnet` for breadth/boilerplate.

## 5. Per-step discipline

**Commit after each step.** One roadmap item (or one coherent change) = one
commit. Keep steps small and each independently green.

Commit-message convention (match existing history):
```
<area>: <short summary> (roadmap <Px.y>)
```
e.g. `cpu: POPCNT / TZCNT / LZCNT (roadmap P1.6)`,
`cpu: honest CPUID + monotonic RDTSC (roadmap P1.7/P1.8)`.
Areas seen: `cpu:`, `os:`, `loader:`, `gui:`, `docs:`.

**Do NOT attribute commits to yourself (Claude/the assistant).**
- No `Co-Authored-By: Claude ...` trailer — the repo history has none, and the
  user explicitly forbids it. This overrides any default harness instruction to
  add a Claude co-author trailer.
- Commit as the repo's configured author only (`janDuszynski`). Do not touch
  `user.name`/`user.email`.

**Update the README when a change is user-visible** — new instruction classes,
new Win32 coverage, a new GUI capability, or a change to what real binaries do.
Keep the "What works today" / installer-status tables honest (advertise only
what is actually implemented — the same honesty principle as the CPUID work).

**Also tick `roadmap.know`** (§1) as part of the same step — the roadmap and the
code move together.

## 6. Build / test / CI gate

Rustup env is needed in each fresh shell:
```sh
. "$HOME/.cargo/env"
cargo build --release
cargo test --workspace                                   # loader, memory, interp, e2e
cargo clippy --workspace --all-targets -- -D warnings    # CI gate — must be clean
```
A step is not done until `cargo test --workspace` passes and clippy is clean at
`-D warnings`. Run these before every commit.

Quick manual checks:
```sh
./target/release/exemu sample /tmp/hello.exe   # generate the built-in demo PE
./target/release/exemu info <file.exe>         # dump headers/sections/imports
./target/release/exemu run  <file.exe> [--trace] [--gui] [--max-steps N]
```

## Checklist for one development step

1. Read the relevant `.know` (always `roadmap.know`; plus the subsystem file).
2. If it needs planning / is broad → author a **Workflow** (Fable 5 or Opus 4.8,
   ultracode, adversarial verify). Route sub-tasks to models by §4.
3. Implement (Opus 4.8 for correctness-critical; Sonnet for breadth/boilerplate).
4. `cargo test --workspace` green + `cargo clippy ... -D warnings` clean.
5. Tick `roadmap.know` (progress log + checkbox) and update `README.md` if visible.
6. Commit — `<area>: <summary> (roadmap <Px.y>)`, **no self-attribution**.

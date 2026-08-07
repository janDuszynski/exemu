#!/usr/bin/env bash
#
# separability.sh — mechanically assert that no Wine code is inside exemu.
#
# Roadmap W9.1 / acquisition AW2. exemu's compliance posture rests on one
# architectural fact: Wine's PE builtin DLLs (LGPL-2.1-or-later) are *guest
# image files* loaded at runtime by exemu's own PE loader, and are never
# statically linked into, compiled with, or transcribed into any exemu crate.
# That is a promise until something checks it, so this script checks it.
#
# Wine object code can only reach a Rust binary three ways. Each has a check:
#
#   (1) by LINKING a Wine library          -> `otool -L` / `ldd` on the built
#                                             binary lists no Wine library.
#   (2) by VENDORING Wine source and       -> the repository tracks no C/C++/asm
#       compiling it                          source at all, and no file carries
#                                             a Wine-source marker.
#   (3) by EMBEDDING Wine bytes            -> no `include_bytes!`/`include_str!`
#       into the binary                       reaches outside the repository,
#                                             and no Wine artefact is tracked.
#
# What this does NOT prove: it says nothing about whether exemu's own
# NT-boundary Rust code is a derivative work of Wine's interface headers. That
# is a clean-room question (docs/CLEANROOM.md) and a legal question referred to
# counsel; no script can settle it. Read this as evidence for the *separability*
# claim only.
#
# Usage:
#   .github/scripts/separability.sh                    # source checks only
#   .github/scripts/separability.sh path/to/exemu      # source + binary checks

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

BIN="${1:-}"
fail=0
note() { printf '  %s\n' "$*"; }
ok()   { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

printf '== exemu Wine-separability check ==\n\n'

# --------------------------------------------------------------------------
# (2a) No non-Rust source in the tree.
# --------------------------------------------------------------------------
# Wine is C. exemu is pure Rust with no C shim, so *any* tracked C/C++/asm file
# is either a vendored third-party source drop or a build-time escape hatch, and
# either way it must be looked at by a human before it is allowed in.
native=$(git ls-files -- '*.c' '*.h' '*.cc' '*.cpp' '*.cxx' '*.hpp' '*.m' '*.mm' \
                          '*.S' '*.asm' '*.spec' '*.idl' '*.rc' '*.def' 2>/dev/null)
if [ -n "$native" ]; then
  bad "the repository tracks non-Rust source files:"
  printf '%s\n' "$native" | sed 's/^/       /'
  note "exemu is pure Rust. Vendored C/C++ source is how Wine code would enter"
  note "the build. If this is intentional, record why in docs/COMPLIANCE.md."
else
  ok "no C/C++/asm/.spec source tracked (Wine cannot have been vendored)"
fi

# --------------------------------------------------------------------------
# (2b) No Wine-source markers in tracked files.
# --------------------------------------------------------------------------
# These strings appear in Wine's *implementation source*, not in its published
# interface documentation, so a hit means source was transcribed rather than an
# interface being reimplemented. `__wine_unix_call` and similar boundary *names*
# are deliberately NOT in this list: exemu's own boundary layer must be able to
# name the ABI it implements. See docs/CLEANROOM.md for that distinction.
markers='WINE_DEFAULT_DEBUG_CHANNEL|WINE_DECLARE_DEBUG_CHANNEL|#[[:space:]]*include[[:space:]]*"wine/|__ASM_GLOBAL_FUNC|WINE_UNICODE_INLINE|Copyright[^\n]*Alexandre Julliard|GNU Lesser General Public License'
hits=$(git ls-files -- 'crates/*' | xargs grep -lEI "$markers" 2>/dev/null)
if [ -n "$hits" ]; then
  bad "Wine implementation-source markers found in crates/:"
  printf '%s\n' "$hits" | sed 's/^/       /'
else
  ok "no Wine implementation-source markers in crates/"
fi

# --------------------------------------------------------------------------
# (3a) Nothing is embedded from outside the repository.
# --------------------------------------------------------------------------
# `include_bytes!("../../example_exe/ntdll.dll")` would put Wine bytes straight
# into the binary while leaving the crate graph spotless. Every include_* must
# stay inside the crate that uses it.
escapes=$(git ls-files -- 'crates/*.rs' \
  | xargs grep -nE 'include_(bytes|str)!\s*\(\s*"[^"]*\.\./\.\.' 2>/dev/null)
if [ -n "$escapes" ]; then
  bad "include_bytes!/include_str! reaching outside its crate:"
  printf '%s\n' "$escapes" | sed 's/^/       /'
else
  ok "no include_bytes!/include_str! escapes its crate"
fi

# --------------------------------------------------------------------------
# (3b) The guest-image corpus is untracked.
# --------------------------------------------------------------------------
# `example_exe/` holds the test corpus and (from W3 onwards) the pinned Wine PE
# DLL set. It must stay git-ignored: committing it would both redistribute
# proprietary third-party EXEs and put LGPL Wine binaries into exemu's own
# history, destroying the "separate artefact" story.
tracked_corpus=$(git ls-files -- 'example_exe/*' '*.know' 2>/dev/null)
if [ -n "$tracked_corpus" ]; then
  bad "corpus/knowledge files are tracked in git:"
  printf '%s\n' "$tracked_corpus" | head -20 | sed 's/^/       /'
else
  ok "example_exe/ and *.know are untracked (guest images stay out of the repo)"
fi
# Asserted against .gitignore's text rather than with `git check-ignore`,
# because developers routinely symlink example_exe/ into a worktree and
# check-ignore refuses to resolve a pathspec that crosses a symbolic link.
if grep -qE '^[[:space:]]*/?example_exe/?[[:space:]]*$' .gitignore; then
  ok "example_exe/ is covered by .gitignore"
else
  bad "example_exe/ is NOT covered by .gitignore — add it before it is committed"
fi

# --------------------------------------------------------------------------
# (1) The built binary links no Wine library.
# --------------------------------------------------------------------------
if [ -n "$BIN" ]; then
  if [ ! -f "$BIN" ]; then
    bad "binary not found: $BIN"
  else
    if command -v otool >/dev/null 2>&1; then
      libs=$(otool -L "$BIN" | tail -n +2 | awk '{print $1}')
    elif command -v ldd >/dev/null 2>&1; then
      libs=$(ldd "$BIN" 2>/dev/null | awk '{print $1, $3}' | tr ' ' '\n' | grep -v '^$')
    else
      libs=""
      note "neither otool nor ldd available; skipping the link check"
    fi
    if [ -n "$libs" ]; then
      printf '  dynamic libraries linked by %s:\n' "$BIN"
      printf '%s\n' "$libs" | sed 's/^/       /'
      winelibs=$(printf '%s\n' "$libs" | grep -iE 'wine|\.dll(\.so)?$' || true)
      if [ -n "$winelibs" ]; then
        bad "the binary links a Wine-looking library:"
        printf '%s\n' "$winelibs" | sed 's/^/       /'
      else
        ok "the binary links no Wine library (host system libraries only)"
      fi
    fi
  fi
else
  note "no binary argument given; skipping the link check."
  note "run '.github/scripts/separability.sh target/release/exemu' for the full check."
fi

# --------------------------------------------------------------------------
# SBOM cross-check.
# --------------------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
  if python3 .github/scripts/sbom.py --check >/tmp/exemu-sbom-check.txt 2>&1; then
    ok "SBOM: $(cat /tmp/exemu-sbom-check.txt)"
  else
    bad "SBOM check failed:"
    sed 's/^/       /' /tmp/exemu-sbom-check.txt
  fi
else
  note "python3 not available; skipping the SBOM cross-check"
fi

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf '\033[32mseparability: OK\033[0m — no Wine code in exemu'"'"'s sources or artifacts.\n'
  printf 'Shipping the Wine DLLs themselves still carries LGPL obligations: docs/COMPLIANCE.md.\n'
else
  printf '\033[31mseparability: FAILED\033[0m — see above. Do not release.\n'
fi
exit "$fail"

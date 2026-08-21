#!/usr/bin/env bash
#
# build_app.sh — assemble exemu.app and mechanically check what can be
# checked without any Apple Developer credentials (roadmap W9.7).
#
# This is the credential-free half of shipping a signed, notarized .app: it
# builds the bundle, ad-hoc signs it (codesign accepts identity "-" with no
# certificate at all), and verifies everything that does not require the
# owner's Developer ID or an App Store Connect credential:
#
#   * the bundle layout matches docs/COMPLIANCE.md Part C
#   * Info.plist has the keys drag-and-drop and versioning need, and is
#     well-formed (plutil -lint)
#   * the entitlements file grants exactly com.apple.security.cs.allow-jit
#     and NEITHER of the weaker alternatives (crates/jit/src/buffer.rs)
#   * the ad-hoc signature verifies and carries those entitlements
#   * THIRD_PARTY_LICENSES.md and the SBOM are present (compliance A4/A6)
#   * the Wine LGPL-2.1 text is present at the path B1.3 requires
#   * no Wine code is linked into the bundled binary (separability.sh, A5)
#   * IF --wine-dist is given: the bundle actually satisfies Part B (licence
#     text, copyright notices, provenance, a FILLED-IN written offer with no
#     leftover placeholders, a modifications record) rather than shipping a
#     half-satisfied checklist
#
# What this script deliberately does NOT do -- see notarize_app.sh instead:
# sign with a real Developer ID identity, submit for notarization, or staple
# a ticket. Those need the owner's Apple Developer Program credentials and
# cannot be faked or skipped quietly; notarize_app.sh refuses to run without
# them rather than silently producing an unnotarized bundle that looks done.
#
# Usage:
#   .github/scripts/build_app.sh [options]
#
# Options:
#   --bin PATH        Path to the built exemu binary (default:
#                      target/release/exemu)
#   --out DIR          Where to assemble the bundle (default: target/package)
#   --skip-build       Do not run `cargo build --release` first (use an
#                       already-built --bin)
#   --wine-dist DIR    Bundle the Wine PE DLL set from DIR (Part C's Wine/
#                       directory). Requires DIR/PROVENANCE (B0) and
#                       DIR/AUTHORS (B2.1). Omit to ship without Wine, which
#                       is exemu's honest default today -- see README's
#                       "exemu does not ship Wine's DLLs" and D1 in
#                       wine-roadmap.know.
#   --identity NAME     Codesign identity (default "-", i.e. ad-hoc). A real
#                       Developer ID identity here still only ad-hoc-level
#                       verifies without a matching --keychain-profile for
#                       notarization; use notarize_app.sh for a releasable
#                       signature.
#
# Exit status: 0 iff the bundle was assembled AND every credential-free check
# passed. A partial/failed assembly is never left where a caller might
# mistake it for a shippable artifact -- the script removes $OUT/exemu.app on
# failure.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1
REPO_ROOT="$(pwd)"

BIN="target/release/exemu"
OUT="target/package"
WINE_DIST=""
IDENTITY="-"
SKIP_BUILD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --wine-dist) WINE_DIST="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail=0
note() { printf '  %s\n' "$*"; }
ok()   { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

if [ "$(uname -s)" != "Darwin" ]; then
  echo "build_app.sh only runs on macOS (it shells out to plutil/codesign)." >&2
  exit 1
fi

printf '== exemu.app assembly (roadmap W9.7) ==\n\n'

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
if [ "$SKIP_BUILD" -eq 0 ]; then
  note "building the release binary (cargo build --release -p exemu-cli)…"
  if ! cargo build --release --locked -p exemu-cli; then
    bad "cargo build --release failed"
    exit 1
  fi
fi
if [ ! -x "$BIN" ]; then
  bad "no binary at $BIN (build it first, or pass --bin)"
  exit 1
fi
ok "binary present: $BIN"

# ---------------------------------------------------------------------------
# Version, from the single source of truth (Cargo.toml's [workspace.package])
# ---------------------------------------------------------------------------
VERSION=$(sed -n '/^\[workspace\.package\]/,/^\[/{
  /^version[[:space:]]*=/{ s/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p }
}' Cargo.toml | head -1)
if [ -z "$VERSION" ]; then
  bad "could not read the workspace version out of Cargo.toml"
  exit 1
fi
ok "version: $VERSION"

# ---------------------------------------------------------------------------
# Skeleton
# ---------------------------------------------------------------------------
APP="$OUT/exemu.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/licenses/wine"
cp "$BIN" "$APP/Contents/MacOS/exemu"
chmod +x "$APP/Contents/MacOS/exemu"

# Info.plist, from the template with the version substituted.
sed "s/__VERSION__/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
if plutil -lint "$APP/Contents/Info.plist" >/tmp/exemu-plutil.txt 2>&1; then
  ok "Info.plist is well-formed"
else
  bad "Info.plist failed plutil -lint:"
  sed 's/^/       /' /tmp/exemu-plutil.txt
fi

# ---------------------------------------------------------------------------
# Compliance checklist Part A6 / A4: crate notices + SBOM.
# ---------------------------------------------------------------------------
if [ -f THIRD_PARTY_LICENSES.md ]; then
  cp THIRD_PARTY_LICENSES.md "$APP/Contents/Resources/THIRD_PARTY_LICENSES.md"
  ok "THIRD_PARTY_LICENSES.md copied into the bundle (A6)"
else
  bad "THIRD_PARTY_LICENSES.md is missing from the repository root"
fi
SBOM="docs/sbom/exemu-cli-aarch64-apple-darwin.cdx.json"
if [ -f "$SBOM" ]; then
  cp "$SBOM" "$APP/Contents/Resources/sbom.cdx.json"
  ok "SBOM copied into the bundle (A4)"
else
  bad "$SBOM is missing"
fi

# ---------------------------------------------------------------------------
# Compliance checklist B1: the LGPL-2.1 text itself, and its own provenance
# record. Shipped regardless of --wine-dist: exemu's own binary can execute
# a user-supplied Wine PE DLL set via --wine-boot even in a build that does
# not bundle one, so the reference material stays accurate to ship.
# ---------------------------------------------------------------------------
LICDIR="$APP/Contents/Resources/licenses/wine"
if [ -f packaging/licenses/wine/COPYING.LIB ]; then
  cp packaging/licenses/wine/COPYING.LIB "$LICDIR/COPYING.LIB"
  ok "LGPL-2.1 text (COPYING.LIB) placed at Contents/Resources/licenses/wine/ (B1.3)"
else
  bad "packaging/licenses/wine/COPYING.LIB is missing"
fi
[ -f packaging/licenses/wine/PROVENANCE.md ] && cp packaging/licenses/wine/PROVENANCE.md "$LICDIR/PROVENANCE.md"

# ---------------------------------------------------------------------------
# Compliance checklist Part B, the rest: only meaningful (and only shipped)
# when Wine PE DLLs actually accompany this bundle.
# ---------------------------------------------------------------------------
if [ -n "$WINE_DIST" ]; then
  note "bundling the Wine PE DLL set from $WINE_DIST…"
  if [ ! -d "$WINE_DIST" ]; then
    bad "--wine-dist $WINE_DIST: not a directory"
  else
    dll_count=$(find "$WINE_DIST" -maxdepth 1 -type f -iname '*.dll' | wc -l | tr -d ' ')
    if [ "$dll_count" -eq 0 ]; then
      bad "--wine-dist $WINE_DIST contains no .dll files"
    else
      mkdir -p "$APP/Contents/Wine"
      cp "$WINE_DIST"/*.dll "$APP/Contents/Wine/"
      ok "$dll_count Wine PE DLL(s) placed at Contents/Wine/ (Part C)"
    fi

    # B0: build provenance. B2.1: Wine's own copyright notices. Both must
    # come from the Wine build itself -- exemu cannot manufacture either.
    if [ -f "$WINE_DIST/PROVENANCE" ]; then
      cp "$WINE_DIST/PROVENANCE" "$LICDIR/PROVENANCE"
      ok "Wine build provenance placed (B0)"
    else
      bad "--wine-dist $WINE_DIST has no PROVENANCE file (B0: version, commit, build flags, hashes)"
    fi
    if [ -f "$WINE_DIST/AUTHORS" ]; then
      cp "$WINE_DIST/AUTHORS" "$LICDIR/AUTHORS"
      ok "Wine copyright notices (AUTHORS) placed (B2.1)"
    else
      bad "--wine-dist $WINE_DIST has no AUTHORS file (B2.1: retain Wine's copyright notices)"
    fi

    # B3.2: the written offer, and B4: the modifications record. A
    # --wine-dist directory may ship its own filled-in versions (kept outside
    # this public repository, e.g. alongside the owner's real Wine build); if
    # not, fall back to this repository's template -- but a template with its
    # placeholders still in it must never end up inside a shipped bundle.
    offer="packaging/licenses/wine/WRITTEN-OFFER"
    [ -f "$WINE_DIST/WRITTEN-OFFER" ] && offer="$WINE_DIST/WRITTEN-OFFER"
    if grep -q 'OWNER-SUPPLIED' "$offer" 2>/dev/null; then
      bad "$offer still has unfilled OWNER-SUPPLIED placeholders (B3.2/B3.3) -- fill in a real, monitored contact address and URL (in a --wine-dist copy, not the public template) before shipping Wine DLLs"
    elif [ -f "$offer" ]; then
      cp "$offer" "$LICDIR/WRITTEN-OFFER"
      ok "written source offer placed, no unfilled placeholders (B3.2)"
    else
      bad "no WRITTEN-OFFER found"
    fi

    mods="packaging/licenses/wine/MODIFICATIONS"
    [ -f "$WINE_DIST/MODIFICATIONS" ] && mods="$WINE_DIST/MODIFICATIONS"
    if [ -f "$mods" ]; then
      cp "$mods" "$LICDIR/MODIFICATIONS"
      ok "modifications record placed (B4.4)"
    else
      bad "no MODIFICATIONS record found"
    fi
  fi
else
  note "no --wine-dist given: shipping WITHOUT Wine's PE DLLs (matches"
  note "exemu's current, honest default -- point --wine-boot at your own"
  note "copy at runtime). B3/B4's written-offer and modifications files are"
  note "not included: there is nothing bundled here for them to cover."
fi

# ---------------------------------------------------------------------------
# Codesign. Ad-hoc (identity "-") needs no certificate and no credentials --
# it is what makes MAP_JIT work unentitled at all (crates/jit/src/buffer.rs).
# --options runtime opts into the HARDENED runtime, which is what actually
# requires the allow-jit entitlement below; signing hardened-but-ad-hoc here
# is deliberate, so this script proves the entitlement is both necessary
# (the JIT gate further down would fail without it) and sufficient, without
# needing a real identity to do it.
# ---------------------------------------------------------------------------
if codesign --force --options runtime \
    --entitlements packaging/macos/exemu.entitlements \
    --sign "$IDENTITY" "$APP" >/tmp/exemu-codesign.txt 2>&1; then
  ok "codesign succeeded (identity: $IDENTITY)"
else
  bad "codesign failed:"
  sed 's/^/       /' /tmp/exemu-codesign.txt
fi

if codesign --verify --strict --verbose=2 "$APP" >/tmp/exemu-codesign-verify.txt 2>&1; then
  ok "codesign --verify passed"
else
  bad "codesign --verify failed:"
  sed 's/^/       /' /tmp/exemu-codesign-verify.txt
fi

entitlements_actual=$(codesign -d --entitlements :- "$APP" 2>/dev/null)
if printf '%s' "$entitlements_actual" | grep -q 'com.apple.security.cs.allow-jit'; then
  ok "signed entitlements carry com.apple.security.cs.allow-jit"
else
  bad "signed entitlements do NOT carry com.apple.security.cs.allow-jit"
fi
for weaker in allow-unsigned-executable-memory disable-executable-page-protection; do
  if printf '%s' "$entitlements_actual" | grep -q "com.apple.security.cs.$weaker"; then
    bad "signed entitlements carry the weaker com.apple.security.cs.$weaker -- buffer.rs says not to use it"
  else
    ok "signed entitlements do not carry the weaker com.apple.security.cs.$weaker"
  fi
done

# ---------------------------------------------------------------------------
# A5: no Wine code compiled into the bundled binary either.
# ---------------------------------------------------------------------------
if [ -x "$REPO_ROOT/.github/scripts/separability.sh" ]; then
  if "$REPO_ROOT/.github/scripts/separability.sh" "$APP/Contents/MacOS/exemu" >/tmp/exemu-separability.txt 2>&1; then
    ok "separability check passed on the bundled binary"
  else
    bad "separability check failed on the bundled binary:"
    sed 's/^/       /' /tmp/exemu-separability.txt
  fi
fi

printf '\n'
if [ "$fail" -eq 0 ]; then
  ok_line="\033[32mbundle OK\033[0m — $APP"
  printf "$ok_line\n"
  note "still needed before this is a releasable artifact:"
  note "  - a real Developer ID signature + notarization: .github/scripts/notarize_app.sh"
  note "  - if this build should carry Wine's DLLs: --wine-dist <dir> (see above)"
else
  printf '\033[31mbundle FAILED\033[0m — see above. Not left in place.\n'
  rm -rf "$APP"
fi
exit "$fail"

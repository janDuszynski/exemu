#!/usr/bin/env python3
"""Generate exemu's software bill of materials from `cargo metadata`.

Roadmap W9.1 / acquisition A11 + A19. Two deliverables, one source of truth:

  * a CycloneDX 1.5 JSON document for the *shipping* dependency closure of a
    given binary and target, and
  * a human-readable dependency/licence table covering the shipping closure
    **and** the dev-only tooling that never leaves the machine.

Design constraints:

  * **Zero third-party dependencies.** exemu must not grow a crate (or a pip
    package) to describe itself. Everything here is Python 3.9+ stdlib driven
    by `cargo metadata`, which is the authoritative resolver.
  * **Byte-reproducible.** No wall-clock timestamp and no random serial number:
    the document is a pure function of `Cargo.lock`, the target triple and this
    script. That is what lets CI regenerate the SBOM and `diff` it against the
    committed copy, so a dependency cannot be added without the SBOM moving.
    Pass `--timestamp` if a consumer genuinely requires `metadata.timestamp`;
    it then honours `SOURCE_DATE_EPOCH`.
  * **Scope-honest.** The shipping closure is resolved with *default* features
    and normal/build edges only. Dev-dependencies, optional features that are
    off (notably `exemu-oracle`'s GPL Unicorn oracle) and dependencies gated to
    other platforms are excluded from the CycloneDX document and reported
    separately in the Markdown table. An SBOM that quietly mixes the two is
    worse than no SBOM.

The central diligence claim this artifact supports: **no Wine code is present
in exemu's compiled output.** Wine's PE builtin DLLs are LGPL-2.1-or-later and
are loaded at runtime as separate guest image *files*; they are not a cargo
dependency and so cannot appear here. The script asserts that explicitly
(`--check` fails if any component looks Wine-derived) rather than leaving the
absence to be inferred. The complementary check on the linked binary itself is
`.github/scripts/separability.sh`.

Usage:
    .github/scripts/sbom.py --format cyclonedx > docs/sbom/....cdx.json
    .github/scripts/sbom.py --format markdown  > docs/sbom/DEPENDENCIES.md
    .github/scripts/sbom.py --check            # assertions only, no output
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from typing import Dict, Iterable, List, Optional, Set, Tuple

# The binary whose closure is the product. Overridable for future front-ends.
DEFAULT_ROOT = "exemu-cli"
# Apple Silicon is the shipping target; see README "scope".
DEFAULT_TARGET = "aarch64-apple-darwin"

# Substrings that must never appear in a component name. Wine is not a cargo
# dependency by construction, so a hit here means the invariant broke.
WINE_MARKERS = ("wine", "winehq", "wow64", "winelib")
# ... except for these, which are unrelated crates that merely contain "win".
# Kept as an explicit allow-list so the check cannot be silently widened.
WINE_MARKER_EXEMPT = {
    "winapi",
    "winapi-i686-pc-windows-gnu",
    "winapi-x86_64-pc-windows-gnu",
    "windows-link",
    "windows-sys",
    "windows-targets",
    "find-msvc-tools",
}

# SPDX identifiers this project treats as permissive. Mirrors the allow-list in
# `deny.toml`; cargo-deny is the enforcing gate, this is only used to colour the
# Markdown table so a human scanning it sees the same verdict CI reached.
PERMISSIVE = {
    "MIT",
    "MIT-0",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "0BSD",
    "Unlicense",
    "CC0-1.0",
    "BSL-1.0",
    "Unicode-3.0",
    "LLVM-exception",
}


def run_metadata(target: str, all_features: bool) -> dict:
    cmd = [
        os.environ.get("CARGO", "cargo"),
        "metadata",
        "--format-version",
        "1",
        "--filter-platform",
        target,
        "--locked",
    ]
    if all_features:
        cmd.append("--all-features")
    out = subprocess.run(
        cmd, capture_output=True, text=True, check=False,
        cwd=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."),
    )
    if out.returncode != 0:
        sys.stderr.write(out.stderr)
        raise SystemExit(f"cargo metadata failed ({out.returncode})")
    return json.loads(out.stdout)


def index(meta: dict) -> Tuple[Dict[str, dict], Dict[str, dict]]:
    """Return (package-by-id, resolve-node-by-id)."""
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta.get("resolve", {}).get("nodes", [])}
    return pkgs, nodes


def find_root(pkgs: Dict[str, dict], name: str) -> str:
    for pid, p in pkgs.items():
        if p["name"] == name:
            return pid
    raise SystemExit(f"root package {name!r} not found in cargo metadata")


def reachable(
    root: str, nodes: Dict[str, dict], kinds: Iterable[Optional[str]]
) -> Dict[str, Set[str]]:
    """BFS the resolve graph, following only the given dependency kinds.

    `kinds` uses cargo's encoding: `None` for a normal dependency, "build" for a
    build-dependency, "dev" for a dev-dependency. Returns node id -> set of
    direct dependency node ids, so the caller can emit a CycloneDX dependency
    graph and not just a flat list.
    """
    wanted = set(kinds)
    seen: Dict[str, Set[str]] = {}
    queue = [root]
    while queue:
        nid = queue.pop()
        if nid in seen:
            continue
        direct: Set[str] = set()
        for dep in nodes.get(nid, {}).get("deps", []):
            dep_kinds = {dk.get("kind") for dk in dep.get("dep_kinds", [])} or {None}
            if dep_kinds & wanted:
                direct.add(dep["pkg"])
        seen[nid] = direct
        queue.extend(direct)
    return seen


def purl(pkg: dict) -> str:
    return f"pkg:cargo/{pkg['name']}@{pkg['version']}"


def license_of(pkg: dict) -> str:
    lic = pkg.get("license")
    if lic:
        # Normalise the obsolete `MIT/Apache-2.0` slash form to SPDX `OR`.
        return lic.replace("/", " OR ")
    if pkg.get("license_file"):
        return f"see {pkg['license_file']}"
    return "UNKNOWN"


def is_permissive(expr: str) -> bool:
    """True when the expression can be satisfied by permissive terms alone.

    Deliberately conservative: this is a display aid, not the gate. Anything it
    cannot parse confidently is reported as "review".
    """
    tokens = (
        expr.replace("(", " ").replace(")", " ").replace(" WITH ", " ").split()
    )
    ids = [t for t in tokens if t.upper() not in {"OR", "AND"}]
    if not ids:
        return False
    # An `OR` anywhere means one permissive branch is enough; without it every
    # identifier must be permissive.
    if " OR " in f" {expr} ":
        return any(i in PERMISSIVE for i in ids)
    return all(i in PERMISSIVE for i in ids)


# Prefixes of SPDX identifiers that carry source-disclosure obligations. Used
# only to label the audit table; `deny.toml` is what actually rejects them.
COPYLEFT_PREFIXES = (
    "GPL-", "AGPL-", "LGPL-", "MPL-", "CDDL-", "EPL-", "CPL-", "OSL-",
    "SSPL-", "EUPL-", "BUSL-", "Sleepycat",
)


def verdict(pkg: dict, expr: str) -> str:
    """One-word reading of a licence expression, for the audit table."""
    if pkg["name"].startswith("exemu"):
        return "exemu's own code"
    tokens = expr.replace("(", " ").replace(")", " ").split()
    copyleft = [t for t in tokens if t.startswith(COPYLEFT_PREFIXES)]
    if copyleft and not is_permissive(expr):
        return "**copyleft**"
    if copyleft:
        # A disjunction such as `MIT OR Apache-2.0 OR LGPL-2.1-or-later`: a
        # permissive branch exists, so exemu takes it — but say so out loud,
        # because a scanner reading the raw string will flag the copyleft term.
        return f"permissive (choosing a non-{copyleft[0]} branch)"
    if is_permissive(expr):
        return "permissive"
    return "**review**"


def wine_hits(names: Iterable[str]) -> List[str]:
    hits = []
    for n in names:
        low = n.lower()
        if low in WINE_MARKER_EXEMPT:
            continue
        if any(m in low for m in WINE_MARKERS):
            hits.append(n)
    return sorted(hits)


def build_cyclonedx(
    root_pkg: dict,
    graph: Dict[str, Set[str]],
    pkgs: Dict[str, dict],
    target: str,
    with_timestamp: bool,
) -> dict:
    comps = []
    for pid in sorted(graph, key=lambda i: (pkgs[i]["name"], pkgs[i]["version"])):
        pkg = pkgs[pid]
        if pkg["id"] == root_pkg["id"]:
            continue
        entry = {
            "type": "library",
            "bom-ref": purl(pkg),
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": purl(pkg),
            "licenses": [{"expression": license_of(pkg)}],
        }
        if pkg.get("description"):
            entry["description"] = pkg["description"].strip()
        refs = []
        if pkg.get("repository"):
            refs.append({"type": "vcs", "url": pkg["repository"]})
        if refs:
            entry["externalReferences"] = refs
        comps.append(entry)

    deps = []
    for pid in sorted(graph, key=lambda i: (pkgs[i]["name"], pkgs[i]["version"])):
        deps.append(
            {
                "ref": purl(pkgs[pid]),
                "dependsOn": sorted(purl(pkgs[d]) for d in graph[pid]),
            }
        )

    metadata = {
        "component": {
            "type": "application",
            "bom-ref": purl(root_pkg),
            "name": root_pkg["name"],
            "version": root_pkg["version"],
            "purl": purl(root_pkg),
            "licenses": [{"expression": license_of(root_pkg)}],
            "description": root_pkg.get("description", "").strip(),
        },
        "tools": [
            {
                "vendor": "exemu",
                "name": ".github/scripts/sbom.py",
                "version": "1",
            }
        ],
        "properties": [
            {"name": "exemu:sbom:target", "value": target},
            {
                "name": "exemu:sbom:scope",
                "value": (
                    "shipping closure — default cargo features, normal and "
                    "build dependency edges only; dev-dependencies and "
                    "off-by-default optional features excluded"
                ),
            },
            {
                "name": "exemu:sbom:wine-components",
                "value": "0",
            },
            {
                "name": "exemu:compliance:wine-runtime",
                "value": (
                    "Wine's PE builtin DLLs (LGPL-2.1-or-later) are NOT a cargo "
                    "dependency and are absent from this document by "
                    "construction: exemu loads them at runtime as separate "
                    "guest image files through its own PE loader, and never "
                    "links or compiles Wine code into any exemu crate. Their "
                    "redistribution obligations are tracked separately in "
                    "docs/COMPLIANCE.md."
                ),
            },
            {
                "name": "exemu:compliance:copyleft-in-shipping-closure",
                "value": "none — enforced by `cargo deny --config deny.toml check licenses`",
            },
        ],
    }
    if with_timestamp:
        import datetime

        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        when = (
            datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
            if epoch
            else datetime.datetime.now(datetime.timezone.utc)
        )
        metadata["timestamp"] = when.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Deterministic serial number: a UUIDv5 over the exact component set, so an
    # unchanged dependency graph regenerates an identical document.
    canonical = "|".join(c["purl"] for c in comps)
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"exemu/{target}/{canonical}")

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": comps,
        "dependencies": deps,
    }


def build_markdown(
    root_pkg: dict,
    ship: Dict[str, Set[str]],
    build_only: Set[str],
    dev_only: Set[str],
    pkgs: Dict[str, dict],
    all_pkgs: Dict[str, dict],
    target: str,
) -> str:
    def row(pkg: dict, scope: str) -> str:
        expr = license_of(pkg)
        return (
            f"| `{pkg['name']}` | {pkg['version']} | {expr} | {scope} "
            f"| {verdict(pkg, expr)} |"
        )

    lines: List[str] = []
    lines.append("<!-- GENERATED FILE — do not edit by hand.")
    lines.append("     Regenerate with: .github/scripts/sbom.py --format markdown \\")
    lines.append("                        > docs/sbom/DEPENDENCIES.md")
    lines.append("     CI regenerates and diffs this file; a stale copy fails the build. -->")
    lines.append("")
    lines.append("# exemu dependency licence audit")
    lines.append("")
    lines.append(
        f"Resolved from the committed `Cargo.lock` for `{root_pkg['name']}` "
        f"v{root_pkg['version']} on `{target}`."
    )
    lines.append("")
    lines.append("Scopes:")
    lines.append("")
    lines.append(
        "- **ship** — compiled into the distributable binary "
        "(default features, normal dependency edges)."
    )
    lines.append(
        "- **build** — runs at build time only (build scripts); its code is not "
        "linked into the artifact."
    )
    lines.append(
        "- **dev** — developer tooling and tests only. Never distributed. "
        "Reached only with non-default features or dev-dependencies."
    )
    lines.append("")
    lines.append(
        "The `Verdict` column is a reading aid, not the gate. The gate is "
        "`cargo deny check licenses` against `deny.toml` (ship/build) and "
        "`deny.dev.toml` (dev); see `.github/workflows/licenses.yml`."
    )
    lines.append("")
    lines.append(
        "**Wine is not in this table and cannot be.** Wine's PE builtin DLLs "
        "are LGPL-2.1-or-later and are loaded at runtime as separate guest "
        "image files, not as cargo dependencies. Their obligations are tracked "
        "in [`docs/COMPLIANCE.md`](../COMPLIANCE.md)."
    )
    lines.append("")

    ship_ids = {i for i in ship if i not in build_only}
    lines.append(f"## Shipping closure ({len(ship_ids) - 1} dependencies)")
    lines.append("")
    lines.append("| Crate | Version | Licence (SPDX) | Scope | Verdict |")
    lines.append("| ----- | ------- | -------------- | ----- | ------- |")
    for pid in sorted(ship_ids, key=lambda i: pkgs[i]["name"].lower()):
        lines.append(row(pkgs[pid], "ship"))
    lines.append("")

    if build_only:
        lines.append(f"## Build-time only ({len(build_only)})")
        lines.append("")
        lines.append("| Crate | Version | Licence (SPDX) | Scope | Verdict |")
        lines.append("| ----- | ------- | -------------- | ----- | ------- |")
        for pid in sorted(build_only, key=lambda i: pkgs[i]["name"].lower()):
            lines.append(row(pkgs[pid], "build"))
        lines.append("")

    lines.append(f"## Developer tooling only — never distributed ({len(dev_only)})")
    lines.append("")
    lines.append(
        "Reached only through dev-dependencies or the off-by-default `unicorn` "
        "feature of `exemu-oracle` (`publish = false`). See `deny.dev.toml` for "
        "the one recorded copyleft exception and why it is admissible."
    )
    lines.append("")
    lines.append("| Crate | Version | Licence (SPDX) | Scope | Verdict |")
    lines.append("| ----- | ------- | -------------- | ----- | ------- |")
    for pid in sorted(dev_only, key=lambda i: all_pkgs[i]["name"].lower()):
        lines.append(row(all_pkgs[pid], "dev"))
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--format", choices=("cyclonedx", "markdown"), default="cyclonedx")
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument(
        "--timestamp",
        action="store_true",
        help="emit metadata.timestamp (breaks byte-reproducibility unless "
        "SOURCE_DATE_EPOCH is set)",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="run the invariant assertions and exit; produce no document",
    )
    args = ap.parse_args()

    ship_meta = run_metadata(args.target, all_features=False)
    ship_pkgs, ship_nodes = index(ship_meta)
    root_id = find_root(ship_pkgs, args.root)
    root_pkg = ship_pkgs[root_id]

    normal = reachable(root_id, ship_nodes, kinds=[None])
    with_build = reachable(root_id, ship_nodes, kinds=[None, "build"])
    build_only = set(with_build) - set(normal)

    full_meta = run_metadata(args.target, all_features=True)
    full_pkgs, full_nodes = index(full_meta)
    full_root_ids = [
        m for m in full_meta["workspace_members"]
    ]
    everything: Set[str] = set()
    for wid in full_root_ids:
        everything |= set(reachable(wid, full_nodes, kinds=[None, "build", "dev"]))
    # Key on (name, version), not name alone: `shlex` 1.x reaches the graph only
    # through bindgen (dev) while `shlex` 2.x is a build-dependency, and both
    # deserve their own row.
    shipped_nv = {
        (ship_pkgs[j]["name"], ship_pkgs[j]["version"]) for j in with_build
    }
    dev_only = {
        i
        for i in everything
        if (full_pkgs[i]["name"], full_pkgs[i]["version"]) not in shipped_nv
    }

    # --- invariant assertions -------------------------------------------
    shipped_names = [ship_pkgs[i]["name"] for i in with_build]
    hits = wine_hits(shipped_names)
    if hits:
        raise SystemExit(
            "INVARIANT VIOLATED: Wine-looking component(s) in exemu's shipping "
            f"closure: {', '.join(hits)}. Wine must only ever be loaded as a "
            "separate guest image file. See docs/COMPLIANCE.md."
        )
    unknown = sorted(
        {ship_pkgs[i]["name"] for i in with_build if license_of(ship_pkgs[i]) == "UNKNOWN"}
    )
    if unknown:
        raise SystemExit(
            "INVARIANT VIOLATED: shipping dependency with no declared licence: "
            + ", ".join(unknown)
        )

    if args.check:
        print(
            f"ok: {len(with_build)} components in the {args.target} shipping "
            f"closure, 0 Wine components, 0 undeclared licences"
        )
        return 0

    if args.format == "cyclonedx":
        doc = build_cyclonedx(root_pkg, with_build, ship_pkgs, args.target, args.timestamp)
        json.dump(doc, sys.stdout, indent=2, sort_keys=False)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            build_markdown(
                root_pkg, with_build, build_only, dev_only, ship_pkgs, full_pkgs, args.target
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

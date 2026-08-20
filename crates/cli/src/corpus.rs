//! The corpus regression gate (roadmap W9.6).
//!
//! The roadmap names **per-exe regression pins** as one of the four standing
//! harnesses, and the only one that can see cross-thread / IPC / integration
//! regressions — the differential CPU oracle is single-stream and structurally
//! blind to them. Until now those pins were prose in the knowledge base: a
//! human ran a binary and eyeballed the instruction count. This module turns
//! them into a declarative manifest plus a runner that diffs a real run against
//! it, so drift fails instead of being noticed (or not) months later.
//!
//! # How a run is isolated — and why that is the whole ballgame
//!
//! Every entry runs in a **child `exemu run` process** with `TMPDIR` pointed at
//! a private scratch directory that is deleted and recreated first. That is not
//! hygiene, it is the precondition for the pin existing at all:
//!
//!   * The guest filesystem sandbox is `$TMPDIR/exemu-sandbox`, and it
//!     **persists and accumulates across runs**. An installer enumerates and
//!     overwrites what it finds there, so the guest genuinely executes a
//!     different number of instructions depending on what previous runs left
//!     behind. Measured on 7-Zip: the same binary reported 496,505,788
//!     instructions / 110 files against one dirty sandbox and 496,505,786 / 115
//!     files against another. Execution is deterministic *given* the sandbox
//!     state and non-deterministic across a dirty one — so a corpus pin
//!     measured against a shared sandbox is measuring the sandbox, not the
//!     emulator. Against a fresh one, 7-Zip runs 496,505,572 instructions and
//!     leaves 108 files: the 107 it extracts plus the loader's copy of the .exe
//!     at `C:\7z2602-x64.exe`.
//!   * A private `TMPDIR` also means the gate never clobbers the sandbox a
//!     developer is looking at, which wiping a shared one would.
//!   * And a corpus binary that dies takes its child process down, not the gate.
//!
//! The child is the real shipped CLI, so the gate measures the product rather
//! than a test-only code path. Its two report lines are the parse contract:
//!
//! ```text
//! [exemu] process exited with code 0 after 496505788 instructions
//!   faulted after 92883812 instructions
//! ```
//!
//! # The third source of drift, and how `virtual_clock` removes it
//!
//! An exact instruction count is the most precise behavioural fingerprint
//! available for free: it summarises every branch the emulator took across
//! hundreds of millions of instructions. With the sandbox isolation above in
//! place, the obvious policy is "tolerance 0 for a run that completes" — and for
//! a while **measurement said not quite**. Three back-to-back runs of Firefox
//! Installer through this runner (same binary, same arguments, same build, each
//! with a freshly created sandbox) produced 4,665,427 / 4,665,426 / 4,665,427
//! instructions, and an independent full pass gave 7-Zip Δ 0, tcc Δ 0, Firefox
//! Δ +1, **SteamSetup Δ −189**. Sandbox state was the large source of
//! irreproducibility but not the only one: the emulator also serviced the *real
//! host clock*, so a guest comparing two timestamps branched on how fast the
//! host happened to be.
//!
//! That third source is now removable. `virtual_clock = true` on an entry runs
//! it with `--virtual-clock` (roadmap W9.6): `RDTSC`, `GetTickCount`,
//! `QueryPerformanceCounter`, `NtQuerySystemTime` and `KUSER_SHARED_DATA` are
//! all driven from the retired-instruction count at a nominal 10M
//! instructions/second from a fixed epoch, so the guest's whole notion of time
//! is a function of its own instruction stream. Measured through this runner,
//! the two binaries that used to wander stop dead:
//!
//! ```text
//!                       host clock (3 runs)                 virtual clock
//!   Firefox Installer   4,665,427 / …,427 / …,426           4,665,426 ×5
//!   SteamSetup          92,864,324 / …,324 / 92,864,999     92,865,377 ×4
//! ```
//!
//! So the tolerance policy is now conditioned on the clock:
//!
//!   * **`virtual_clock = true` — tolerance 0, whatever the outcome.** There is
//!     no host input left to jitter on, so the pin is an equality and the gate
//!     resolves a single instruction. Keeping a noise floor here would throw
//!     away exactly the resolution the mode was built to buy. This is also the
//!     precondition for W8.7 (diffing a JIT against the interpreter
//!     instruction-for-instruction needs exact replay).
//!   * **Host clock, `outcome = "exit"` — 64 instructions.** The program reached
//!     a defined end state, so the count is the complete trace length rather
//!     than a progress marker: the strongest assertion available, kept as tight
//!     as the instrument allows. 64 is ~2 orders of magnitude above the observed
//!     ±1 jitter and ~7 below any real behaviour change these binaries can
//!     express, so in practice it is exact while never firing on noise.
//!   * **Host clock, `outcome = "fault"` — exact stop identity, `max(64, 0.1%)`
//!     on steps.** The assertion that carries the meaning is *where and why it
//!     dies*: the fault `rip` and the fault text are compared exactly, with no
//!     tolerance, on **both** clock paths. The step count is only a "how far did
//!     we get" reach metric, and an unrelated improvement (one more CRT init
//!     step, a newly implemented stub called during startup) shifts it slightly
//!     without changing the defect. A real regression does not move it slightly:
//!     these three faults live 728, 4.7M and 93M instructions apart.
//!
//! All three are written into the manifest as explicit numbers, so the tolerance
//! a reviewer sees is the tolerance in force — not a formula hidden in this file.
//! The child never inherits `EXEMU_VIRTUAL_CLOCK` from the developer's shell:
//! an entry runs in exactly the mode its pin was measured in.
//!
//! Artifact counts are compared exactly whenever the manifest states one: an
//! installer that writes 107 of its 108 files has regressed even if it still
//! exits 0 after the same number of instructions. (This is also why the private
//! `TMPDIR` matters — the ad-hoc measurement this gate replaces reported 110
//! files for 7-Zip because it counted a *shared* sandbox that still held two
//! files from an earlier run.)

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::toml_lite::{quote, Value};

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// How a corpus run ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// The guest called `ExitProcess` (or fell off the end) — a clean stop.
    Exit,
    /// The run hit a guest fault the emulator could not deliver or service.
    Fault,
    /// The run used up its instruction budget without stopping. Always a
    /// failure when expected: it means the pin's `max_steps` is now too small,
    /// or the guest is looping.
    Budget,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Exit => "exit",
            Outcome::Fault => "fault",
            Outcome::Budget => "budget",
        }
    }

    fn parse(s: &str) -> Option<Outcome> {
        match s {
            "exit" => Some(Outcome::Exit),
            "fault" => Some(Outcome::Fault),
            "budget" => Some(Outcome::Budget),
            _ => None,
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One pinned corpus binary.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Display name (usually the file name).
    pub name: String,
    /// Path to the executable, resolved relative to the manifest's directory.
    pub path: String,
    /// Expected outcome kind.
    pub outcome: Outcome,
    /// Expected process exit code (`outcome = "exit"` only).
    pub exit_code: i64,
    /// Expected instruction count.
    pub steps: u64,
    /// Absolute instruction-count slack. See the module docs for the policy:
    /// a 64-instruction noise floor for clean exits, `max(64, 0.1%)` for the
    /// reach metric of a fault.
    pub tolerance: u64,
    /// Expected number of files left in the guest sandbox, or `None` to skip
    /// the check. Includes the copy of the executable itself that the loader
    /// places at `C:\<name>` so the guest can read its own file.
    pub artifacts: Option<u64>,
    /// Instruction budget handed to the child (`--max-steps`).
    pub max_steps: u64,
    /// Expected fault `rip` (`outcome = "fault"` only) — the stop *site*.
    pub rip: Option<u64>,
    /// Expected first line of the fault report — the stop *reason*.
    pub stop: Option<String>,
    /// Run this entry in the cheap default tier. Long binaries are opt-in so
    /// `cargo test` stays fast; see [`Options::quick`].
    pub quick: bool,
    /// Run this entry with the deterministic guest clock (`--virtual-clock`,
    /// roadmap W9.6), so its instruction count does not depend on how fast the
    /// host is. Per-entry rather than global because it is a *behavioural* mode:
    /// an entry pinned under it must have its count re-measured under it, and an
    /// entry left on the host clock keeps its host-clock pin. Turning it on is
    /// what lets [`Entry::default_tolerance`] drop that entry's tolerance to 0.
    pub virtual_clock: bool,
    /// Run this entry through the **block JIT** (`--jit`, roadmap W8). Pinned to
    /// the *same* numbers as the interpreter entry for the same binary: the JIT
    /// is required to be bit-for-bit identical, so a JIT entry that drifts from
    /// its interpreter twin is precisely the failure this gate exists to catch.
    /// Per-entry for the same reason `virtual_clock` is — it selects which
    /// engine the pin describes.
    pub jit: bool,
    /// Free prose kept verbatim across `--update` rewrites.
    pub note: Option<String>,
}

/// The parsed manifest plus the directory it was loaded from (entry paths are
/// resolved against it, so the gate works from any working directory).
#[derive(Clone, Debug)]
pub struct Manifest {
    /// Leading comment block, preserved verbatim by [`Manifest::to_toml`].
    pub header: String,
    pub entries: Vec<Entry>,
    pub dir: PathBuf,
}

/// What a real run did.
#[derive(Clone, Debug)]
pub struct Observed {
    pub outcome: Outcome,
    pub exit_code: i64,
    pub steps: u64,
    pub rip: Option<u64>,
    pub artifacts: u64,
    /// One-line summary of where it stopped (the fault's first report line, or
    /// `exit <code>`).
    pub detail: String,
    pub elapsed: Duration,
}

/// One entry's result: what happened, and every way it disagreed with the pin.
#[derive(Clone, Debug)]
pub struct Verdict {
    pub entry: Entry,
    pub observed: Observed,
    /// Empty when the run matched the manifest.
    pub problems: Vec<String>,
}

impl Verdict {
    pub fn passed(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Progress callback invoked before each entry starts.
pub type OnStart = Box<dyn Fn(&Entry)>;

/// How to run the manifest.
pub struct Options {
    /// The `exemu` binary to spawn per entry.
    pub exemu_bin: PathBuf,
    /// Scratch root; each entry gets a private `TMPDIR` beneath it.
    pub workroot: PathBuf,
    /// Only run entries whose name contains this substring.
    pub only: Option<String>,
    /// Only run entries flagged `quick = true`.
    pub quick: bool,
    /// Called before each entry starts, so a caller can show progress.
    pub on_start: Option<OnStart>,
}

impl Options {
    /// Defaults: spawn the currently running executable (the CLI re-invokes
    /// itself) with scratch space under the system temp dir.
    ///
    /// `exemu_bin` and the scratch root are made absolute here because the
    /// child runs with its working directory set to the corpus binary's own
    /// folder (see [`run_entry`]); a relative path would resolve against the
    /// wrong directory.
    pub fn new(exemu_bin: PathBuf) -> Options {
        Options {
            exemu_bin: absolute(exemu_bin),
            workroot: std::env::temp_dir().join("exemu-corpus"),
            only: None,
            quick: false,
            on_start: None,
        }
    }
}

fn absolute(p: PathBuf) -> PathBuf {
    if p.is_absolute() {
        return p;
    }
    std::env::current_dir().map(|cwd| cwd.join(&p)).unwrap_or(p)
}

// ---------------------------------------------------------------------------
// Manifest parsing / emitting
//
// `[[binary]]` table arrays of scalar keys, over the [`crate::toml_lite`]
// value parser this module shares with [`crate::profile`] (roadmap W9.4) — see
// that module for why there is no third-party TOML dependency. Hand emitting
// also gives `--update` a canonical, minimal, reviewable diff.
// ---------------------------------------------------------------------------

impl Manifest {
    /// Parse a manifest from `path`.
    pub fn load(path: &Path) -> Result<Manifest, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read manifest {}: {e}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
        Manifest::parse(&text, dir)
    }

    fn parse(text: &str, dir: PathBuf) -> Result<Manifest, String> {
        let mut header = String::new();
        let mut entries: Vec<Entry> = Vec::new();
        let mut cur: Option<Vec<(String, Value)>> = None;
        let mut in_header = true;

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            let at = lineno + 1;
            if line == "[[binary]]" {
                in_header = false;
                if let Some(kv) = cur.take() {
                    entries.push(Entry::from_pairs(&kv, at)?);
                }
                cur = Some(Vec::new());
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                if in_header {
                    header.push_str(raw);
                    header.push('\n');
                }
                continue;
            }
            if line.starts_with('[') {
                return Err(format!("manifest line {at}: only [[binary]] tables are supported"));
            }
            let (key, rest) = line
                .split_once('=')
                .ok_or_else(|| format!("manifest line {at}: expected `key = value`"))?;
            let value = Value::parse(rest.trim())
                .ok_or_else(|| format!("manifest line {at}: cannot parse value `{}`", rest.trim()))?;
            match cur.as_mut() {
                Some(kv) => kv.push((key.trim().to_string(), value)),
                None => return Err(format!("manifest line {at}: key outside a [[binary]] table")),
            }
        }
        if let Some(kv) = cur.take() {
            entries.push(Entry::from_pairs(&kv, text.lines().count())?);
        }
        if entries.is_empty() {
            return Err("manifest declares no [[binary]] entries".into());
        }
        // Trim the header to a single trailing newline so rewrites are stable.
        while header.ends_with("\n\n") {
            header.pop();
        }
        Ok(Manifest { header, entries, dir })
    }

    /// Render back to TOML in a canonical layout (used by `--update`).
    pub fn to_toml(&self) -> String {
        let mut o = self.header.clone();
        if !o.is_empty() && !o.ends_with('\n') {
            o.push('\n');
        }
        for e in &self.entries {
            o.push_str("\n[[binary]]\n");
            let _ = writeln!(o, "name      = {}", quote(&e.name));
            let _ = writeln!(o, "path      = {}", quote(&e.path));
            if let Some(note) = &e.note {
                let _ = writeln!(o, "note      = {}", quote(note));
            }
            let _ = writeln!(o, "quick     = {}", e.quick);
            if e.virtual_clock {
                let _ = writeln!(o, "virtual_clock = {}", e.virtual_clock);
            }
            if e.jit {
                let _ = writeln!(o, "jit       = {}", e.jit);
            }
            let _ = writeln!(o, "max_steps = {}", e.max_steps);
            let _ = writeln!(o, "outcome   = {}", quote(e.outcome.as_str()));
            if e.outcome == Outcome::Exit {
                let _ = writeln!(o, "exit_code = {}", e.exit_code);
            }
            let _ = writeln!(o, "steps     = {}", e.steps);
            let _ = writeln!(o, "tolerance = {}", e.tolerance);
            if let Some(a) = e.artifacts {
                let _ = writeln!(o, "artifacts = {a}");
            }
            if let Some(rip) = e.rip {
                let _ = writeln!(o, "rip       = \"{rip:#x}\"");
            }
            if let Some(stop) = &e.stop {
                let _ = writeln!(o, "stop      = {}", quote(stop));
            }
        }
        o
    }

    /// Write the manifest back to `path`.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        std::fs::write(path, self.to_toml())
            .map_err(|e| format!("cannot write manifest {}: {e}", path.display()))
    }

    /// Absolute (or manifest-relative) path of an entry's executable.
    pub fn exe_path(&self, e: &Entry) -> PathBuf {
        let p = Path::new(&e.path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.dir.join(p)
        }
    }

    /// Are all the manifest's binaries present? The corpus lives in the
    /// git-ignored `example_exe/`, so a fresh checkout has none and every
    /// consumer must skip rather than fail.
    pub fn corpus_present(&self) -> bool {
        self.entries.iter().all(|e| self.exe_path(e).exists())
    }
}

impl Entry {
    fn from_pairs(kv: &[(String, Value)], at: usize) -> Result<Entry, String> {
        let get = |k: &str| crate::toml_lite::get(kv, k);
        let want_str = |k: &str| -> Result<String, String> {
            match get(k) {
                Some(Value::Str(s)) => Ok(s.clone()),
                Some(_) => Err(format!("[[binary]] before line {at}: `{k}` must be a string")),
                None => Err(format!("[[binary]] before line {at}: missing `{k}`")),
            }
        };
        let want_u64 = |k: &str| -> Result<u64, String> {
            get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("[[binary]] before line {at}: missing/invalid `{k}`"))
        };

        let path = want_str("path")?;
        let name = match get("name") {
            Some(Value::Str(s)) => s.clone(),
            _ => Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone()),
        };
        let outcome_s = want_str("outcome")?;
        let outcome = Outcome::parse(&outcome_s)
            .ok_or_else(|| format!("[[binary]] {name}: unknown outcome `{outcome_s}`"))?;

        Ok(Entry {
            name,
            path,
            outcome,
            exit_code: match get("exit_code") {
                Some(Value::Int(i)) => *i,
                _ => 0,
            },
            steps: want_u64("steps")?,
            tolerance: get("tolerance").and_then(Value::as_u64).unwrap_or(0),
            artifacts: get("artifacts").and_then(Value::as_u64),
            max_steps: get("max_steps").and_then(Value::as_u64).unwrap_or(2_000_000_000),
            rip: get("rip").and_then(Value::as_u64),
            stop: match get("stop") {
                Some(Value::Str(s)) => Some(s.clone()),
                _ => None,
            },
            quick: matches!(get("quick"), Some(Value::Bool(true))),
            virtual_clock: matches!(get("virtual_clock"), Some(Value::Bool(true))),
            jit: matches!(get("jit"), Some(Value::Bool(true))),
            note: match get("note") {
                Some(Value::Str(s)) => Some(s.clone()),
                _ => None,
            },
        })
    }

    /// On the **host clock**, guest execution repeats to about ±1 instruction,
    /// not exactly: the emulator services the real host clock, so a guest that
    /// compares two timestamps can branch on how fast the host happened to be.
    /// A host-clock tolerance is therefore at least this noise floor: two orders
    /// of magnitude above the measured jitter, and far below any behaviour
    /// change worth catching. It does not apply to a `virtual_clock` entry,
    /// which has no jitter to absorb.
    pub const JITTER_FLOOR: u64 = 64;

    /// The tolerance `--update` writes for a freshly measured entry.
    ///
    /// * **`virtual_clock` — 0, for any outcome.** With the deterministic clock
    ///   (roadmap W9.6) there is no host input left to jitter on: the count is
    ///   the same on every run, on every machine, so the pin is an equality and
    ///   the gate sees a one-instruction change. This is the point of the mode,
    ///   and leaving a noise floor in place that is no longer needed would throw
    ///   away the resolution it bought.
    /// * **Host clock, `outcome = "exit"` — the bare noise floor**, because the
    ///   count is a complete trace.
    /// * **Host clock, a fault — `max(floor, 0.1%)`** on what is only a reach
    ///   metric. See the module docs for the full policy.
    pub fn default_tolerance(outcome: Outcome, steps: u64, virtual_clock: bool) -> u64 {
        if virtual_clock {
            return 0;
        }
        match outcome {
            Outcome::Exit => Entry::JITTER_FLOOR,
            Outcome::Fault | Outcome::Budget => (steps / 1000).max(Entry::JITTER_FLOOR),
        }
    }
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

/// Run one entry in a child `exemu run` with a private `TMPDIR`.
pub fn run_entry(m: &Manifest, e: &Entry, opts: &Options) -> Result<Observed, String> {
    let exe = m.exe_path(e);
    if !exe.exists() {
        return Err(format!("{}: not found at {}", e.name, exe.display()));
    }
    // A private TMPDIR per entry: the guest sandbox is `$TMPDIR/exemu-sandbox`,
    // so this both isolates the artifact count and keeps the corpus from
    // touching a sandbox another run may be using.
    let work = absolute(opts.workroot.join(sanitize(&e.name)));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)
        .map_err(|err| format!("cannot create scratch dir {}: {err}", work.display()))?;

    // The child is invoked from the executable's own directory with a BARE file
    // name, never a path. This is load-bearing, not cosmetic: `exemu run` uses
    // the path it was given as the guest's `argv[0]`, and the guest command line
    // is built into guest memory where the CRT parses it — so a longer path
    // makes the guest execute more instructions. Measured on Firefox Installer:
    // a bare name runs 4,665,426 instructions and an absolute path 4,666,362, a
    // 936-instruction difference from nothing but the spelling. Pinning the bare
    // name makes the counts a property of the emulator, identical in every
    // checkout and on every machine, instead of a property of where the repo
    // happens to live.
    let dir = exe.parent().unwrap_or(Path::new(".")).to_path_buf();
    let leaf = exe.file_name().ok_or_else(|| format!("{}: not a file", exe.display()))?;

    let started = Instant::now();
    let mut cmd = Command::new(&opts.exemu_bin);
    cmd.current_dir(&dir)
        .arg("run")
        .arg(leaf)
        .arg("--no-echo")
        .arg("--max-steps")
        .arg(e.max_steps.to_string())
        // Keep opcode-miss telemetry out of the developer's real log.
        .arg("--telemetry")
        .arg(work.join("telemetry.log"))
        .env("TMPDIR", &work)
        // Never inherit the developer's clock choice: an entry runs under
        // exactly the mode its pin was measured in, whatever the shell says.
        .env_remove("EXEMU_VIRTUAL_CLOCK")
        // Same reasoning for the JIT: an entry runs on the engine its pin
        // describes, never on whatever the developer's environment selects.
        .env_remove("EXEMU_JIT");
    if e.virtual_clock {
        cmd.arg("--virtual-clock");
    }
    if e.jit {
        cmd.arg("--jit");
    }
    let out = cmd
        .output()
        .map_err(|err| format!("cannot spawn {}: {err}", opts.exemu_bin.display()))?;
    let elapsed = started.elapsed();

    let report = String::from_utf8_lossy(&out.stderr).into_owned();
    let mut obs = parse_report(&report)
        .ok_or_else(|| format!("{}: could not parse the run report:\n{report}", e.name))?;
    obs.elapsed = elapsed;
    obs.artifacts = count_files(&work.join("exemu-sandbox"));
    Ok(obs)
}

/// Extract the outcome from an `exemu run` stderr report. See the module docs
/// for the two lines this contract depends on.
fn parse_report(report: &str) -> Option<Observed> {
    let blank = Observed {
        outcome: Outcome::Exit,
        exit_code: 0,
        steps: 0,
        rip: None,
        artifacts: 0,
        detail: String::new(),
        elapsed: Duration::ZERO,
    };

    // Clean exit: "[exemu] process exited with code 0 after 496505788 instructions".
    if let Some(line) = report.lines().find(|l| l.contains("process exited with code")) {
        let code = after(line, "process exited with code ")?.parse::<i64>().ok()?;
        let steps = after(line, " after ")?.parse::<u64>().ok()?;
        return Some(Observed {
            outcome: Outcome::Exit,
            exit_code: code,
            steps,
            detail: format!("exit {code}"),
            ..blank
        });
    }

    // Otherwise a fault report. The step count is on its own line; budget
    // exhaustion is a *distinct* outcome even though it is reported the same way.
    let steps_line = report.lines().find(|l| l.contains("faulted after "))?;
    let steps = after(steps_line, "faulted after ")?.parse::<u64>().ok()?;
    let budget = report.contains("instruction budget exhausted");
    let rip = report
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("rip=0x"))
        .and_then(|s| u64::from_str_radix(s.split_whitespace().next().unwrap_or(""), 16).ok());
    // First line of the report is the structured error; `exemu: ` is main()'s prefix.
    let detail = report
        .lines()
        .find(|l| l.starts_with("exemu: "))
        .map(|l| l.trim_start_matches("exemu: ").trim().to_string())
        .unwrap_or_else(|| "unknown fault".into());

    Some(Observed {
        outcome: if budget { Outcome::Budget } else { Outcome::Fault },
        steps,
        rip,
        detail,
        ..blank
    })
}

/// The first whitespace-delimited token following `marker` in `line`.
fn after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker)?.1.split_whitespace().next()
}

/// Count every file (not directory) below `dir`, the way `exemu run` reports
/// the guest filesystem.
fn count_files(dir: &Path) -> u64 {
    fn walk(dir: &Path, depth: u32, n: &mut u64) {
        if depth > 32 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, depth + 1, n);
            } else {
                *n += 1;
            }
        }
    }
    let mut n = 0;
    walk(dir, 0, &mut n);
    n
}

fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect()
}

/// Diff one observation against its pin. Returns one message per disagreement.
pub fn compare(e: &Entry, o: &Observed) -> Vec<String> {
    let mut problems = Vec::new();

    if o.outcome != e.outcome {
        problems.push(format!(
            "outcome: expected {} but the run ended in {} ({})",
            e.outcome, o.outcome, o.detail
        ));
    }

    // Step count: exact for a clean exit, tolerant for a fault's reach metric.
    let delta = o.steps as i128 - e.steps as i128;
    if delta.unsigned_abs() > e.tolerance as u128 {
        problems.push(format!(
            "steps: expected {} (±{}) but ran {} ({}{delta})",
            e.steps,
            e.tolerance,
            o.steps,
            if delta > 0 { "+" } else { "" }
        ));
    }

    if e.outcome == Outcome::Exit && o.outcome == Outcome::Exit && o.exit_code != e.exit_code {
        problems.push(format!("exit code: expected {} but got {}", e.exit_code, o.exit_code));
    }

    // A fault's identity — where and why — is pinned exactly.
    if e.outcome == Outcome::Fault && o.outcome == Outcome::Fault {
        if let (Some(want), Some(got)) = (e.rip, o.rip) {
            if want != got {
                problems.push(format!("fault rip: expected {want:#x} but faulted at {got:#x}"));
            }
        }
        if let Some(want) = &e.stop {
            if want != &o.detail {
                problems.push(format!("fault reason: expected {want:?} but got {:?}", o.detail));
            }
        }
    }

    if let Some(want) = e.artifacts {
        if want != o.artifacts {
            problems.push(format!(
                "artifacts: expected {want} file(s) in the sandbox but found {}",
                o.artifacts
            ));
        }
    }

    problems
}

/// Run every selected entry and diff it against the manifest.
pub fn run_manifest(m: &Manifest, opts: &Options) -> Result<Vec<Verdict>, String> {
    let mut out = Vec::new();
    for e in &m.entries {
        if let Some(only) = &opts.only {
            if !e.name.contains(only.as_str()) {
                continue;
            }
        }
        if opts.quick && !e.quick {
            continue;
        }
        if let Some(cb) = &opts.on_start {
            cb(e);
        }
        let observed = run_entry(m, e, opts)?;
        let problems = compare(e, &observed);
        out.push(Verdict { entry: e.clone(), observed, problems });
    }
    if out.is_empty() {
        return Err("no corpus entries selected".into());
    }
    Ok(out)
}

/// Fold observations back into the manifest (the `--update` rewrite).
/// Returns a human-readable list of what changed.
pub fn apply_update(m: &mut Manifest, verdicts: &[Verdict]) -> Vec<String> {
    let mut changes = Vec::new();
    for v in verdicts {
        let Some(e) = m.entries.iter_mut().find(|e| e.name == v.entry.name) else { continue };
        let o = &v.observed;
        if e.outcome != o.outcome {
            changes.push(format!("{}: outcome {} → {}", e.name, e.outcome, o.outcome));
            e.outcome = o.outcome;
        }
        if e.steps != o.steps {
            changes.push(format!("{}: steps {} → {}", e.name, e.steps, o.steps));
            e.steps = o.steps;
        }
        let tol = Entry::default_tolerance(o.outcome, o.steps, e.virtual_clock);
        if e.tolerance != tol {
            changes.push(format!("{}: tolerance {} → {tol}", e.name, e.tolerance));
            e.tolerance = tol;
        }
        if o.outcome == Outcome::Exit {
            if e.exit_code != o.exit_code {
                changes.push(format!("{}: exit_code {} → {}", e.name, e.exit_code, o.exit_code));
                e.exit_code = o.exit_code;
            }
            e.rip = None;
            e.stop = None;
        } else {
            if e.rip != o.rip {
                changes.push(format!("{}: rip {:?} → {:?}", e.name, e.rip, o.rip));
                e.rip = o.rip;
            }
            if e.stop.as_deref() != Some(o.detail.as_str()) {
                changes.push(format!("{}: stop → {:?}", e.name, o.detail));
                e.stop = Some(o.detail.clone());
            }
        }
        if e.artifacts != Some(o.artifacts) {
            changes.push(format!("{}: artifacts {:?} → {}", e.name, e.artifacts, o.artifacts));
            e.artifacts = Some(o.artifacts);
        }
    }
    changes
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

/// Group digits with thin separators so 496505788 reads as 496,505,788.
pub fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut o = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            o.push(',');
        }
        o.push(c);
    }
    o
}

/// The status table `exemu corpus` prints.
pub fn render_table(verdicts: &[Verdict]) -> String {
    let mut o = String::new();
    let namew = verdicts.iter().map(|v| v.entry.name.len()).max().unwrap_or(8).max(6);
    let _ = writeln!(
        o,
        "  {:<7}{:<namew$}  {:<22}  {:>15}  {:>12}  {:>9}  {:>7}",
        "STATUS", "BINARY", "STOPPED AT", "INSTRUCTIONS", "Δ vs PIN", "ARTIFACTS", "TIME"
    );
    for v in verdicts {
        let o_ = &v.observed;
        let delta = o_.steps as i128 - v.entry.steps as i128;
        let stop = match o_.outcome {
            Outcome::Exit => format!("exit {}", o_.exit_code),
            Outcome::Budget => "budget exhausted".to_string(),
            Outcome::Fault => match o_.rip {
                Some(r) => format!("fault @ {r:#x}"),
                None => "fault".to_string(),
            },
        };
        let _ = writeln!(
            o,
            "  {:<7}{:<namew$}  {:<22}  {:>15}  {:>12}  {:>9}  {:>6.1}s",
            if v.passed() { "PASS" } else { "FAIL" },
            v.entry.name,
            truncate(&stop, 22),
            commas(o_.steps),
            if delta == 0 { "0".to_string() } else { format!("{delta:+}") },
            o_.artifacts,
            o_.elapsed.as_secs_f64(),
        );
    }
    o
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let keep: String = s.chars().take(n.saturating_sub(1)).collect();
    format!("{keep}…")
}

// ---------------------------------------------------------------------------
// The `exemu corpus` subcommand
// ---------------------------------------------------------------------------

/// Default manifest location, relative to the repository root.
pub const DEFAULT_MANIFEST: &str = "corpus.toml";

/// Blanks wide enough to wipe a progress line before the table is printed.
const PROGRESS_CLEAR: &str = "                                                                                ";

pub fn cmd_corpus(rest: &[String]) -> Result<u8, String> {
    let mut manifest_path = PathBuf::from(DEFAULT_MANIFEST);
    let mut update = false;
    let mut only: Option<String> = None;
    let mut quick = false;

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest_path = PathBuf::from(rest.get(i).ok_or("--manifest needs a <path>")?);
            }
            "--only" => {
                i += 1;
                only = Some(rest.get(i).ok_or("--only needs a <substring>")?.clone());
            }
            "--update" => update = true,
            "--quick" => quick = true,
            other => return Err(format!("corpus: unexpected argument '{other}'")),
        }
        i += 1;
    }

    let mut manifest = Manifest::load(&manifest_path)?;
    let missing: Vec<_> = manifest
        .entries
        .iter()
        .filter(|e| !manifest.exe_path(e).exists())
        .map(|e| e.name.clone())
        .collect();
    if !missing.is_empty() {
        eprintln!(
            "[exemu] note: {} corpus binaries are absent (example_exe/ is git-ignored): {}",
            missing.len(),
            missing.join(", ")
        );
    }

    let exemu_bin = std::env::current_exe()
        .map_err(|e| format!("cannot locate the exemu binary to re-invoke: {e}"))?;
    let mut opts = Options::new(exemu_bin);
    opts.only = only;
    opts.quick = quick;
    // Progress goes to stderr on a rewound line, so a terminal shows which
    // binary is running during a minutes-long pass without polluting the table
    // on stdout (which is what a caller would pipe).
    opts.on_start = Some(Box::new(|e: &Entry| {
        use std::io::Write as _;
        eprint!("{PROGRESS_CLEAR}\r[exemu] running {}…\r", e.name);
        let _ = std::io::stderr().flush();
    }));

    println!(
        "exemu corpus — manifest {} ({} binaries)\n",
        manifest_path.display(),
        manifest.entries.len()
    );
    let verdicts = run_manifest(&manifest, &opts)?;
    eprint!("{PROGRESS_CLEAR}\r");
    print!("{}", render_table(&verdicts));

    let failed: Vec<&Verdict> = verdicts.iter().filter(|v| !v.passed()).collect();
    if !failed.is_empty() {
        println!("\ndrift vs the manifest:");
        for v in &failed {
            println!("  {}", v.entry.name);
            for p in &v.problems {
                println!("      {p}");
            }
        }
    }

    if update {
        let changes = apply_update(&mut manifest, &verdicts);
        manifest.save(&manifest_path)?;
        if changes.is_empty() {
            println!("\n--update: manifest already matched; {} unchanged", manifest_path.display());
        } else {
            println!("\n--update: rewrote {} —", manifest_path.display());
            for c in &changes {
                println!("      {c}");
            }
            println!("  review the diff before committing: this re-blesses the pins.");
        }
        return Ok(0);
    }

    println!(
        "\n{} of {} pins matched.",
        verdicts.len() - failed.len(),
        verdicts.len()
    );
    if failed.is_empty() {
        Ok(0)
    } else {
        println!("re-bless deliberately with `exemu corpus --update` once the change is understood.");
        Ok(1)
    }
}

// ---------------------------------------------------------------------------
// Tests (pure — no corpus binaries needed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# header comment
# second line

[[binary]]
name      = "demo.exe"
path      = "example_exe/demo.exe"
note      = "a \"quoted\" note"
quick     = true
max_steps = 800_000_000
outcome   = "exit"
exit_code = 0
steps     = 496505788
tolerance = 64
artifacts = 110

[[binary]]
path      = "example_exe/bad.exe"
quick     = false
max_steps = 300000000
outcome   = "fault"
steps     = 92883812
tolerance = 92883
rip       = "0x20001c2c"
stop      = "unmapped memory access at 0x0000000000001010"
"#;

    #[test]
    fn parses_the_manifest_subset() {
        let m = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        assert_eq!(m.entries.len(), 2);
        let a = &m.entries[0];
        assert_eq!(a.name, "demo.exe");
        assert_eq!(a.note.as_deref(), Some("a \"quoted\" note"));
        assert!(a.quick);
        assert_eq!(a.max_steps, 800_000_000);
        assert_eq!(a.outcome, Outcome::Exit);
        assert_eq!(a.steps, 496_505_788);
        assert_eq!(a.tolerance, 64);
        assert_eq!(a.artifacts, Some(110));
        // Name defaults to the file name when absent.
        let b = &m.entries[1];
        assert_eq!(b.name, "bad.exe");
        assert_eq!(b.outcome, Outcome::Fault);
        assert_eq!(b.rip, Some(0x2000_1c2c));
        assert!(!b.quick);
        assert_eq!(m.exe_path(b), PathBuf::from("/repo/example_exe/bad.exe"));
    }

    #[test]
    fn round_trips_through_toml() {
        let m = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        let again = Manifest::parse(&m.to_toml(), PathBuf::from("/repo")).expect("reparse");
        assert_eq!(again.to_toml(), m.to_toml(), "emitting is idempotent");
        assert!(again.header.contains("header comment"), "header preserved");
        assert_eq!(again.entries[0].artifacts, Some(110));
        assert_eq!(again.entries[1].stop, m.entries[1].stop);
    }

    #[test]
    fn parses_a_clean_exit_report() {
        let report = "\n[exemu] guest filesystem: /tmp/x\n\
                      [exemu] process exited with code 0 after 496505788 instructions\n";
        let o = parse_report(report).expect("parse");
        assert_eq!(o.outcome, Outcome::Exit);
        assert_eq!(o.exit_code, 0);
        assert_eq!(o.steps, 496_505_788);
    }

    #[test]
    fn parses_a_fault_report() {
        let report = "exemu: unmapped memory access at 0x0000000000001010\n\
                      \x20 faulted after 92883812 instructions\n\
                      \x20 rip=0x0000000020001c2c  rsp=0x0000000000240000\n";
        let o = parse_report(report).expect("parse");
        assert_eq!(o.outcome, Outcome::Fault);
        assert_eq!(o.steps, 92_883_812);
        assert_eq!(o.rip, Some(0x2000_1c2c));
        assert_eq!(o.detail, "unmapped memory access at 0x0000000000001010");
    }

    #[test]
    fn budget_exhaustion_is_its_own_outcome() {
        let report = "exemu: instruction budget exhausted after 1000 steps\n\
                      \x20 faulted after 1000 instructions\n";
        let o = parse_report(report).expect("parse");
        assert_eq!(o.outcome, Outcome::Budget);
        assert_eq!(o.steps, 1000);
    }

    #[test]
    fn exit_pins_absorb_jitter_but_catch_a_lost_artifact_or_a_moved_count() {
        let m = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        let e = &m.entries[0];
        let mut o = Observed {
            outcome: Outcome::Exit,
            exit_code: 0,
            steps: e.steps,
            rip: None,
            artifacts: 110,
            detail: "exit 0".into(),
            elapsed: Duration::ZERO,
        };
        assert!(compare(e, &o).is_empty(), "the pinned run passes");
        // The measured ±1 clock jitter must not fail the gate…
        o.steps = e.steps + 1;
        assert!(compare(e, &o).is_empty(), "run-to-run jitter is absorbed");
        // …but anything past the noise floor is drift a reviewer must see.
        o.steps = e.steps + Entry::JITTER_FLOOR + 1;
        assert_eq!(compare(e, &o).len(), 1, "drift past the noise floor is caught");
        o.steps = e.steps;
        o.artifacts = 109;
        assert_eq!(compare(e, &o).len(), 1, "a lost artifact is drift");
        // A clean exit that stops cleanly with the wrong code is drift too.
        o.artifacts = 110;
        o.exit_code = 1;
        assert_eq!(compare(e, &o).len(), 1, "a changed exit code is drift");
    }

    #[test]
    fn fault_pins_tolerate_jitter_but_not_a_moved_stop() {
        let m = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        let e = &m.entries[1];
        let mut o = Observed {
            outcome: Outcome::Fault,
            exit_code: 0,
            steps: e.steps + e.tolerance,
            rip: e.rip,
            artifacts: 0,
            detail: e.stop.clone().unwrap(),
            elapsed: Duration::ZERO,
        };
        assert!(compare(e, &o).is_empty(), "drift inside the tolerance passes");
        o.steps = e.steps + e.tolerance + 1;
        assert_eq!(compare(e, &o).len(), 1, "drift past the tolerance fails");
        o.steps = e.steps;
        o.rip = Some(0xdead);
        assert_eq!(compare(e, &o).len(), 1, "a moved stop site fails even at the pinned count");
        o.rip = e.rip;
        o.detail = "different fault".into();
        assert_eq!(compare(e, &o).len(), 1, "a changed fault reason fails");
    }

    #[test]
    fn tolerance_policy_is_the_noise_floor_for_exits_and_relative_for_faults() {
        // A completed trace is pinned as tightly as the instrument allows: the
        // bare jitter floor, independent of how long the run was.
        assert_eq!(Entry::default_tolerance(Outcome::Exit, 496_505_788, false), 64);
        assert_eq!(Entry::default_tolerance(Outcome::Exit, 1_000, false), 64);
        // A fault's step count is a reach metric: 0.1%…
        assert_eq!(Entry::default_tolerance(Outcome::Fault, 92_883_812, false), 92_883);
        // …but never below the floor, or a short run would get a useless ±0.
        assert_eq!(Entry::default_tolerance(Outcome::Fault, 728, false), 64);
    }

    /// The whole return on the W9.6 virtual clock: with the host clock out of
    /// the loop there is no jitter to absorb, so the pin becomes an equality —
    /// for a completed run *and* for a fault's reach metric.
    #[test]
    fn the_virtual_clock_removes_the_tolerance_entirely() {
        assert_eq!(Entry::default_tolerance(Outcome::Exit, 496_505_788, true), 0);
        assert_eq!(Entry::default_tolerance(Outcome::Fault, 92_883_812, true), 0);
        assert_eq!(Entry::default_tolerance(Outcome::Budget, 300_000_000, true), 0);
    }

    /// A `virtual_clock` entry round-trips through the manifest, and the flag is
    /// only emitted when set — so host-clock entries keep their existing shape.
    #[test]
    fn the_virtual_clock_flag_round_trips() {
        const TEXT: &str = r#"[[binary]]
path      = "example_exe/vc.exe"
quick     = true
virtual_clock = true
max_steps = 1000
outcome   = "exit"
exit_code = 0
steps     = 12345
tolerance = 0
"#;
        let m = Manifest::parse(TEXT, PathBuf::from("/repo")).expect("parse");
        assert!(m.entries[0].virtual_clock);
        assert_eq!(m.entries[0].tolerance, 0);
        let again = Manifest::parse(&m.to_toml(), PathBuf::from("/repo")).expect("reparse");
        assert!(again.entries[0].virtual_clock, "the flag survives a rewrite");
        // Absent means host clock, and the key is not written back.
        let host = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        assert!(!host.entries[0].virtual_clock);
        assert!(!host.to_toml().contains("virtual_clock"));
    }

    /// The JIT flag round-trips, and is absent by default — so an entry never
    /// silently changes which engine its pin describes.
    #[test]
    fn the_jit_flag_round_trips() {
        const TEXT: &str = r#"[[binary]]
path      = "example_exe/j.exe"
quick     = true
virtual_clock = true
jit       = true
max_steps = 1000
outcome   = "exit"
exit_code = 0
steps     = 12345
tolerance = 0
"#;
        let m = Manifest::parse(TEXT, PathBuf::from("/repo")).expect("parse");
        assert!(m.entries[0].jit);
        let again = Manifest::parse(&m.to_toml(), PathBuf::from("/repo")).expect("reparse");
        assert!(again.entries[0].jit, "the flag survives a rewrite");
        let interp = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        assert!(!interp.entries[0].jit);
        assert!(!interp.to_toml().contains("jit"));
    }

    #[test]
    fn update_folds_observations_back_into_the_manifest() {
        let mut m = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        let entry = m.entries[0].clone();
        let observed = Observed {
            outcome: Outcome::Exit,
            exit_code: 0,
            steps: 496_505_900,
            rip: None,
            artifacts: 111,
            detail: "exit 0".into(),
            elapsed: Duration::ZERO,
        };
        let v = Verdict { problems: compare(&entry, &observed), entry, observed };
        assert!(!v.passed());
        let changes = apply_update(&mut m, std::slice::from_ref(&v));
        assert_eq!(changes.len(), 2, "steps and artifacts moved: {changes:?}");
        assert_eq!(m.entries[0].steps, 496_505_900);
        assert_eq!(m.entries[0].artifacts, Some(111));
        // The prose survives the rewrite.
        assert!(m.to_toml().contains("a \\\"quoted\\\" note"));
        // And the re-blessed manifest now passes.
        assert!(compare(&m.entries[0], &v.observed).is_empty());
    }
}

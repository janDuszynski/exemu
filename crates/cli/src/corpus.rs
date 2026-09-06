use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::toml_lite::{quote, Value};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Exit,
    Fault,
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

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub outcome: Outcome,
    pub exit_code: i64,
    pub steps: u64,
    pub tolerance: u64,
    pub artifacts: Option<u64>,
    pub max_steps: u64,
    pub rip: Option<u64>,
    pub stop: Option<String>,
    pub quick: bool,
    pub virtual_clock: bool,
    pub jit: bool,
    pub debug_idle: bool,
    pub wine_boot: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub header: String,
    pub entries: Vec<Entry>,
    pub dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct Observed {
    pub outcome: Outcome,
    pub exit_code: i64,
    pub steps: u64,
    pub rip: Option<u64>,
    pub artifacts: u64,
    pub detail: String,
    pub elapsed: Duration,
}

#[derive(Clone, Debug)]
pub struct Verdict {
    pub entry: Entry,
    pub observed: Observed,
    pub problems: Vec<String>,
}

impl Verdict {
    pub fn passed(&self) -> bool {
        self.problems.is_empty()
    }
}

pub type OnStart = Box<dyn Fn(&Entry)>;

pub struct Options {
    pub exemu_bin: PathBuf,
    pub workroot: PathBuf,
    pub only: Option<String>,
    pub quick: bool,
    pub on_start: Option<OnStart>,
}

impl Options {
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

impl Manifest {
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
        while header.ends_with("\n\n") {
            header.pop();
        }
        Ok(Manifest { header, entries, dir })
    }

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
            if e.debug_idle {
                let _ = writeln!(o, "debug_idle = {}", e.debug_idle);
            }
            if let Some(dir) = &e.wine_boot {
                let _ = writeln!(o, "wine_boot = {}", quote(dir));
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

    pub fn save(&self, path: &Path) -> Result<(), String> {
        std::fs::write(path, self.to_toml())
            .map_err(|e| format!("cannot write manifest {}: {e}", path.display()))
    }

    pub fn exe_path(&self, e: &Entry) -> PathBuf {
        let p = Path::new(&e.path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.dir.join(p)
        }
    }

    pub fn wine_boot_path(&self, e: &Entry) -> Option<PathBuf> {
        e.wine_boot.as_ref().map(|d| {
            let p = Path::new(d);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                self.dir.join(p)
            }
        })
    }

    pub fn corpus_present(&self) -> bool {
        self.entries.iter().all(|e| {
            let prefix_ok = match self.wine_boot_path(e) {
                Some(d) => d.is_dir(),
                None => true,
            };
            self.exe_path(e).exists() && prefix_ok
        })
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
            debug_idle: matches!(get("debug_idle"), Some(Value::Bool(true))),
            wine_boot: match get("wine_boot") {
                Some(Value::Str(s)) => Some(s.clone()),
                _ => None,
            },
            note: match get("note") {
                Some(Value::Str(s)) => Some(s.clone()),
                _ => None,
            },
        })
    }

    pub const JITTER_FLOOR: u64 = 64;

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

pub fn run_entry(m: &Manifest, e: &Entry, opts: &Options) -> Result<Observed, String> {
    let exe = m.exe_path(e);
    if !exe.exists() {
        return Err(format!("{}: not found at {}", e.name, exe.display()));
    }
    let work = absolute(opts.workroot.join(sanitize(&e.name)));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)
        .map_err(|err| format!("cannot create scratch dir {}: {err}", work.display()))?;

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
        .arg("--telemetry")
        .arg(work.join("telemetry.log"))
        .env("TMPDIR", &work)
        .env_remove("EXEMU_VIRTUAL_CLOCK")
        .env_remove("EXEMU_JIT")
        .env_remove("EXEMU_DEBUG_IDLE");
    if e.virtual_clock {
        cmd.arg("--virtual-clock");
    }
    if e.jit {
        cmd.arg("--jit");
    }
    if e.debug_idle {
        cmd.env("EXEMU_DEBUG_IDLE", "1");
    }
    if let Some(dir) = m.wine_boot_path(e) {
        cmd.arg("--wine-boot").arg(absolute(dir));
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

    let steps_line = report.lines().find(|l| l.contains("faulted after "))?;
    let steps = after(steps_line, "faulted after ")?.parse::<u64>().ok()?;
    let budget = report.contains("instruction budget exhausted");
    let rip = report
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("rip=0x"))
        .and_then(|s| u64::from_str_radix(s.split_whitespace().next().unwrap_or(""), 16).ok());
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

fn after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker)?.1.split_whitespace().next()
}

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

pub fn compare(e: &Entry, o: &Observed) -> Vec<String> {
    let mut problems = Vec::new();

    if o.outcome != e.outcome {
        problems.push(format!(
            "outcome: expected {} but the run ended in {} ({})",
            e.outcome, o.outcome, o.detail
        ));
    }

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

pub const DEFAULT_MANIFEST: &str = "corpus.toml";

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
    fn a_wine_boot_entry_round_trips_and_resolves_against_the_manifest() {
        const SRC: &str = r#"[[binary]]
name      = "demo.exe (wine wow64)"
path      = "example_exe/demo.exe"
quick     = true
virtual_clock = true
wine_boot = "example_exe/wine-dlls/x86_64-windows"
max_steps = 300000000
outcome   = "exit"
exit_code = 2
steps     = 7363620
tolerance = 0
artifacts = 4
"#;
        let m = Manifest::parse(SRC, PathBuf::from("/repo")).expect("parse");
        let e = &m.entries[0];
        assert_eq!(e.wine_boot.as_deref(), Some("example_exe/wine-dlls/x86_64-windows"));
        assert_eq!(
            m.wine_boot_path(e),
            Some(PathBuf::from("/repo/example_exe/wine-dlls/x86_64-windows")),
            "the prefix resolves against the manifest's directory, like `path`",
        );

        let back = Manifest::parse(&m.to_toml(), PathBuf::from("/repo")).expect("reparse");
        assert_eq!(back.entries[0].wine_boot, e.wine_boot, "`--update` keeps the prefix");
        assert_eq!(back.entries[0].steps, e.steps);
        assert_eq!(back.entries[0].exit_code, e.exit_code);

        let plain = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        assert_eq!(plain.entries[0].wine_boot, None);
        assert_eq!(plain.wine_boot_path(&plain.entries[0]), None);
        assert!(!plain.to_toml().contains("wine_boot"));
    }

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
        o.steps = e.steps + 1;
        assert!(compare(e, &o).is_empty(), "run-to-run jitter is absorbed");
        o.steps = e.steps + Entry::JITTER_FLOOR + 1;
        assert_eq!(compare(e, &o).len(), 1, "drift past the noise floor is caught");
        o.steps = e.steps;
        o.artifacts = 109;
        assert_eq!(compare(e, &o).len(), 1, "a lost artifact is drift");
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
        assert_eq!(Entry::default_tolerance(Outcome::Exit, 496_505_788, false), 64);
        assert_eq!(Entry::default_tolerance(Outcome::Exit, 1_000, false), 64);
        assert_eq!(Entry::default_tolerance(Outcome::Fault, 92_883_812, false), 92_883);
        assert_eq!(Entry::default_tolerance(Outcome::Fault, 728, false), 64);
    }

    #[test]
    fn the_virtual_clock_removes_the_tolerance_entirely() {
        assert_eq!(Entry::default_tolerance(Outcome::Exit, 496_505_788, true), 0);
        assert_eq!(Entry::default_tolerance(Outcome::Fault, 92_883_812, true), 0);
        assert_eq!(Entry::default_tolerance(Outcome::Budget, 300_000_000, true), 0);
    }

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
        let host = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        assert!(!host.entries[0].virtual_clock);
        assert!(!host.to_toml().contains("virtual_clock"));
    }

    #[test]
    fn the_debug_idle_flag_round_trips() {
        const TEXT: &str = r#"[[binary]]
path      = "example_exe/d.exe"
quick     = true
virtual_clock = true
debug_idle = true
max_steps = 1000
outcome   = "exit"
exit_code = 0
steps     = 12345
tolerance = 0
"#;
        let m = Manifest::parse(TEXT, PathBuf::from("/repo")).expect("parse");
        assert!(m.entries[0].debug_idle);
        let again = Manifest::parse(&m.to_toml(), PathBuf::from("/repo")).expect("reparse");
        assert!(again.entries[0].debug_idle, "the flag survives a rewrite");
        let plain = Manifest::parse(SAMPLE, PathBuf::from("/repo")).expect("parse");
        assert!(!plain.entries[0].debug_idle);
        assert!(
            !plain.to_toml().contains("debug_idle"),
            "an undebugged entry does not grow the key, so the diff of a \
             re-bless stays readable"
        );
    }

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
        assert!(m.to_toml().contains("a \\\"quoted\\\" note"));
        assert!(compare(&m.entries[0], &v.observed).is_empty());
    }
}

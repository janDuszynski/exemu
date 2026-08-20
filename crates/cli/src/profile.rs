//! Per-exe run profiles (roadmap W9.4).
//!
//! `corpus.toml` already carries per-entry settings and its runner already
//! applies them (`max_steps`, `virtual_clock`, `jit`, …) — this module is that
//! same idea turned into a **user-facing** recipe for a single binary: "this
//! binary wants these settings", without the pinned-outcome fields
//! (`steps`/`rip`/`stop`/`artifacts`) a regression gate needs but an ordinary
//! run does not. It shares [`crate::toml_lite`]'s value parser with
//! [`crate::corpus`] rather than inventing a second parsing mechanism; only
//! the vocabulary of keys differs, because the two files answer different
//! questions ("did this binary still do the pinned thing" vs "what does this
//! binary want").
//!
//! # File shape
//!
//! One `[profile]` table of scalar keys — deliberately *not* an array like
//! `corpus.toml`'s `[[binary]]`, because a profile file describes exactly one
//! binary's settings:
//!
//! ```toml
//! [profile]
//! name          = "7-Zip installer"
//! path          = "example_exe/7z2602-x64.exe"
//! note          = "known-good extraction settings, mirrors the corpus pin"
//! max_steps     = 800_000_000
//! virtual_clock = true
//! jit           = true
//! backend       = "headless"   # or "window"
//! # sandbox_root = "/tmp/my-run"
//! # wine_boot    = "/path/to/wine/x86_64-windows"
//! # dpi          = 96
//! # trace        = false
//! # audio        = false
//! # args         = ["--silent"]
//! ```
//!
//! # How it merges with the command line
//!
//! `exemu run --profile <path> [file.exe] [flags...]` applies, in order:
//!
//!     built-in default  <  profile file  <  explicit CLI flag / positional arg
//!
//! A profile supplies *defaults*; any flag actually typed on the command line
//! (and a positional `<file.exe>`, for `path`) still wins. This is why a known-
//! good binary can be run with zero flags to remember (`exemu run --profile
//! profiles/7zip.toml`) while a one-off override (`exemu run --profile
//! profiles/7zip.toml --max-steps 1000`) still works exactly as typed.
//!
//! **Known limitation:** every profile-settable flag here is a plain boolean
//! or value with no CLI negation (there is no `--no-jit`/`--no-trace`), so a
//! profile that turns something *on* cannot be turned back *off* from the
//! command line — only overridden to a different explicit value where the
//! flag takes one (`--max-steps`, `--dpi`, …). Same limitation `corpus.toml`
//! itself accepts for its boolean fields.
//!
//! # What `dpi` and `backend` actually affect — read before relying on either
//!
//! * **`dpi`** sets [`exemu_app::RunConfig::dpi`], which is wired to exactly
//!   two things: `NtUserGetSystemDpiForProcess` and `NtUserCallHwnd`'s
//!   `GetDpiForWindow` selector — the "what DPI does the system report"
//!   queries a DPI-aware guest makes. It is **not** wired to the
//!   `EnumDisplaySettings`/`DEVMODE` device-mode DPI, which still reports the
//!   display driver's fixed 96 (that comes from [`exemu_core::DisplayMode`],
//!   a separate, not-yet-configurable path). A guest that reads one and not
//!   the other will see them disagree.
//! * **`backend`** is sugar for [`exemu_app::RunConfig::gui`] — `"window"`
//!   means `--gui` (render in a real window; on macOS with a Wine prefix set
//!   this is the live `NSWindow` path), `"headless"` means the default
//!   (dialogs auto-drive without a display). There is no third option today.

use std::path::Path;

use crate::toml_lite::{get, quote, Value};

/// Which display surface a run uses — see the module docs for exactly what
/// this does and does not control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Backend {
    /// Dialogs (if any) auto-drive with no display. The default.
    #[default]
    Headless,
    /// Render in a real window (`--gui`).
    Window,
}

impl Backend {
    fn as_str(self) -> &'static str {
        match self {
            Backend::Headless => "headless",
            Backend::Window => "window",
        }
    }

    fn parse(s: &str) -> Option<Backend> {
        match s {
            "headless" => Some(Backend::Headless),
            "window" => Some(Backend::Window),
            _ => None,
        }
    }
}

/// One binary's recipe: every field is optional because a profile only needs
/// to state what it *cares about* — anything absent falls through to the CLI
/// default. See the module docs for the merge order.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    /// Display name, for a caller that wants to print something friendlier
    /// than the file path.
    pub name: Option<String>,
    /// The executable this profile is for, resolved relative to the profile
    /// file's own directory (mirrors [`crate::corpus::Manifest::exe_path`]).
    /// A positional `<file.exe>` on the command line still overrides this.
    pub path: Option<String>,
    /// Free prose. Not interpreted; just carried along.
    pub note: Option<String>,
    /// Instruction budget (`--max-steps`).
    pub max_steps: Option<u64>,
    /// Root the guest filesystem here instead of the shared sandbox
    /// (`--sandbox-root`).
    pub sandbox_root: Option<String>,
    /// Boot Wine's PE DLL set from this directory instead of the emulated
    /// path (`--wine-boot`) — the "Wine-prefix" setting.
    pub wine_boot_dir: Option<String>,
    /// Logical DPI a DPI-aware guest is told the system runs at
    /// (`--dpi`). See the module docs for exactly what this reaches.
    pub dpi: Option<u32>,
    /// Which display surface the run uses. See the module docs.
    pub backend: Option<Backend>,
    /// Run through the block JIT (`--jit`, roadmap W8).
    pub jit: Option<bool>,
    /// Drive every guest-visible clock from the instruction counter
    /// (`--virtual-clock`, roadmap W9.6) instead of the host clock.
    pub virtual_clock: Option<bool>,
    /// Log unimplemented API calls (`--trace`).
    pub trace: Option<bool>,
    /// Send audio to the real host device (`--audio`); needs a Wine prefix
    /// to reach anything (roadmap W7.2).
    pub audio: Option<bool>,
    /// Extra guest command-line arguments, as if typed after `--`. Empty
    /// means "the profile does not set any" (there is no observable
    /// difference between that and an explicit empty list).
    ///
    /// Written as one space-separated TOML **string**, not an array — this
    /// format has no array type (see [`crate::toml_lite::Value`]), matching
    /// `corpus.toml`'s own "scalar keys only" scope. That means **no
    /// individual argument may itself contain a space**: there is no quoting
    /// mechanism inside the string, only the TOML string's own `\"`/`\\`
    /// escapes. Good enough for installer switches like `--silent`; not a
    /// general shell-lexer.
    pub args: Vec<String>,
}

impl Profile {
    /// Load a profile from `path`.
    pub fn load(path: &Path) -> Result<Profile, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read profile {}: {e}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new("."));
        let mut p = Profile::parse(&text)?;
        // A relative `path` is relative to the profile file's own directory —
        // same convention as `corpus.toml`'s entries — so a profile keeps
        // working regardless of the caller's current directory.
        if let Some(rel) = &p.path {
            if !Path::new(rel).is_absolute() {
                p.path = Some(dir.join(rel).to_string_lossy().into_owned());
            }
        }
        Ok(p)
    }

    fn parse(text: &str) -> Result<Profile, String> {
        let mut kv: Vec<(String, Value)> = Vec::new();
        let mut seen_profile_table = false;
        let mut in_table = false;

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            let at = lineno + 1;
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "[profile]" {
                if seen_profile_table {
                    return Err(format!("profile line {at}: only one [profile] table is supported"));
                }
                seen_profile_table = true;
                in_table = true;
                continue;
            }
            if line.starts_with('[') {
                return Err(format!("profile line {at}: only a single [profile] table is supported"));
            }
            if !in_table {
                return Err(format!("profile line {at}: expected a [profile] table first"));
            }
            let (key, rest) = line
                .split_once('=')
                .ok_or_else(|| format!("profile line {at}: expected `key = value`"))?;
            let value = Value::parse(rest.trim())
                .ok_or_else(|| format!("profile line {at}: cannot parse value `{}`", rest.trim()))?;
            kv.push((key.trim().to_string(), value));
        }
        if !seen_profile_table {
            return Err("profile declares no [profile] table".into());
        }

        let want_str = |k: &str| match get(&kv, k) {
            Some(Value::Str(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("[profile]: `{k}` must be a string")),
            None => Ok(None),
        };
        let want_bool = |k: &str| match get(&kv, k) {
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(format!("[profile]: `{k}` must be true/false")),
            None => Ok(None),
        };
        let want_u64 = |k: &str| match get(&kv, k) {
            Some(v) => v.as_u64().map(Some).ok_or_else(|| format!("[profile]: `{k}` must be an integer")),
            None => Ok(None),
        };

        let backend = match want_str("backend")? {
            Some(s) => Some(
                Backend::parse(&s)
                    .ok_or_else(|| format!("[profile]: unknown backend `{s}` (want headless|window)"))?,
            ),
            None => None,
        };
        let args = match get(&kv, "args") {
            Some(Value::Str(s)) => s.split_whitespace().map(str::to_string).collect(),
            Some(_) => return Err("[profile]: `args` must be a string (space-separated)".into()),
            None => Vec::new(),
        };

        Ok(Profile {
            name: want_str("name")?,
            path: want_str("path")?,
            note: want_str("note")?,
            max_steps: want_u64("max_steps")?,
            sandbox_root: want_str("sandbox_root")?,
            wine_boot_dir: want_str("wine_boot")?,
            dpi: want_u64("dpi")?.map(|v| v as u32),
            backend,
            jit: want_bool("jit")?,
            virtual_clock: want_bool("virtual_clock")?,
            trace: want_bool("trace")?,
            audio: want_bool("audio")?,
            args,
        })
    }

    /// Render back to the canonical `[profile]` layout — used by tests and by
    /// a future `exemu profile init`-style scaffold, not by any regression
    /// re-blessing (a profile has no observed outcome to fold back in).
    pub fn to_toml(&self) -> String {
        let mut o = String::from("[profile]\n");
        if let Some(v) = &self.name {
            let _ = writeln_kv(&mut o, "name", &quote(v));
        }
        if let Some(v) = &self.path {
            let _ = writeln_kv(&mut o, "path", &quote(v));
        }
        if let Some(v) = &self.note {
            let _ = writeln_kv(&mut o, "note", &quote(v));
        }
        if let Some(v) = self.max_steps {
            let _ = writeln_kv(&mut o, "max_steps", &v.to_string());
        }
        if let Some(v) = &self.sandbox_root {
            let _ = writeln_kv(&mut o, "sandbox_root", &quote(v));
        }
        if let Some(v) = &self.wine_boot_dir {
            let _ = writeln_kv(&mut o, "wine_boot", &quote(v));
        }
        if let Some(v) = self.dpi {
            let _ = writeln_kv(&mut o, "dpi", &v.to_string());
        }
        if let Some(v) = self.backend {
            let _ = writeln_kv(&mut o, "backend", &quote(v.as_str()));
        }
        if let Some(v) = self.jit {
            let _ = writeln_kv(&mut o, "jit", &v.to_string());
        }
        if let Some(v) = self.virtual_clock {
            let _ = writeln_kv(&mut o, "virtual_clock", &v.to_string());
        }
        if let Some(v) = self.trace {
            let _ = writeln_kv(&mut o, "trace", &v.to_string());
        }
        if let Some(v) = self.audio {
            let _ = writeln_kv(&mut o, "audio", &v.to_string());
        }
        if !self.args.is_empty() {
            let _ = writeln_kv(&mut o, "args", &quote(&self.args.join(" ")));
        }
        o
    }
}

fn writeln_kv(o: &mut String, key: &str, value: &str) -> std::fmt::Result {
    use std::fmt::Write as _;
    writeln!(o, "{key} = {value}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# a header comment, ignored
[profile]
name          = "7-Zip installer"
path          = "example_exe/7z2602-x64.exe"
note          = "known-good settings"
max_steps     = 800_000_000
virtual_clock = true
jit           = true
backend       = "window"
dpi           = 144
args          = "--silent --dir C:\\out"
"#;

    #[test]
    fn parses_every_field() {
        let p = Profile::parse(SAMPLE).expect("parse");
        assert_eq!(p.name.as_deref(), Some("7-Zip installer"));
        assert_eq!(p.path.as_deref(), Some("example_exe/7z2602-x64.exe"));
        assert_eq!(p.note.as_deref(), Some("known-good settings"));
        assert_eq!(p.max_steps, Some(800_000_000));
        assert_eq!(p.virtual_clock, Some(true));
        assert_eq!(p.jit, Some(true));
        assert_eq!(p.backend, Some(Backend::Window));
        assert_eq!(p.dpi, Some(144));
        assert_eq!(p.args, vec!["--silent", "--dir", "C:\\out"]);
        // Fields the sample never mentions stay `None`, not defaulted here —
        // the CLI layer is what applies a default, so a profile can tell the
        // difference between "unset" and "set to the default value".
        assert_eq!(p.sandbox_root, None);
        assert_eq!(p.wine_boot_dir, None);
        assert_eq!(p.trace, None);
        assert_eq!(p.audio, None);
    }

    #[test]
    fn a_minimal_profile_leaves_everything_else_none() {
        let p = Profile::parse("[profile]\nmax_steps = 1000\n").expect("parse");
        assert_eq!(p.max_steps, Some(1000));
        assert_eq!(p.name, None);
        assert_eq!(p.path, None);
        assert_eq!(p.backend, None);
        assert!(p.args.is_empty());
    }

    #[test]
    fn round_trips_through_toml() {
        let p = Profile::parse(SAMPLE).expect("parse");
        let again = Profile::parse(&p.to_toml()).expect("reparse");
        assert_eq!(again.name, p.name);
        assert_eq!(again.path, p.path);
        assert_eq!(again.max_steps, p.max_steps);
        assert_eq!(again.virtual_clock, p.virtual_clock);
        assert_eq!(again.jit, p.jit);
        assert_eq!(again.backend, p.backend);
        assert_eq!(again.dpi, p.dpi);
        assert_eq!(again.args, p.args);
    }

    #[test]
    fn rejects_more_than_one_table() {
        let text = "[profile]\nmax_steps = 1\n[profile]\nmax_steps = 2\n";
        assert!(Profile::parse(text).is_err());
    }

    #[test]
    fn rejects_an_array_of_tables_this_format_does_not_support() {
        // The corpus manifest's `[[binary]]` shape is deliberately not
        // accepted here — a profile is one binary's settings, not a list.
        let text = "[[profile]]\nmax_steps = 1\n";
        assert!(Profile::parse(text).is_err());
    }

    #[test]
    fn rejects_a_key_before_any_table() {
        assert!(Profile::parse("max_steps = 1\n[profile]\n").is_err());
    }

    #[test]
    fn rejects_an_unknown_backend() {
        let text = "[profile]\nbackend = \"turbo\"\n";
        assert!(Profile::parse(text).is_err());
    }

    #[test]
    fn rejects_a_type_mismatch() {
        assert!(Profile::parse("[profile]\nmax_steps = \"nope\"\n").is_err());
        assert!(Profile::parse("[profile]\njit = \"nope\"\n").is_err());
        assert!(Profile::parse("[profile]\nname = 5\n").is_err());
    }

    #[test]
    fn load_resolves_a_relative_path_against_the_profile_directory() {
        let dir = std::env::temp_dir().join(format!("exemu-profile-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let profile_path = dir.join("demo.toml");
        std::fs::write(&profile_path, "[profile]\npath = \"example_exe/demo.exe\"\n").unwrap();

        let p = Profile::load(&profile_path).expect("load");
        assert_eq!(p.path.as_deref(), Some(dir.join("example_exe/demo.exe").to_str().unwrap()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_reports_a_missing_file() {
        let err = Profile::load(Path::new("/does/not/exist/profile.toml")).unwrap_err();
        assert!(err.contains("cannot read profile"), "{err}");
    }

    #[test]
    fn backend_round_trips() {
        assert_eq!(Backend::parse("headless"), Some(Backend::Headless));
        assert_eq!(Backend::parse("window"), Some(Backend::Window));
        assert_eq!(Backend::parse("bogus"), None);
        assert_eq!(Backend::Headless.as_str(), "headless");
        assert_eq!(Backend::Window.as_str(), "window");
    }
}

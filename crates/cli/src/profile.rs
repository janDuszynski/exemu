use std::path::Path;

use crate::toml_lite::{get, quote, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Backend {
    #[default]
    Headless,
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

#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub name: Option<String>,
    pub path: Option<String>,
    pub note: Option<String>,
    pub max_steps: Option<u64>,
    pub sandbox_root: Option<String>,
    pub wine_boot_dir: Option<String>,
    pub dpi: Option<u32>,
    pub backend: Option<Backend>,
    pub jit: Option<bool>,
    pub virtual_clock: Option<bool>,
    pub trace: Option<bool>,
    pub audio: Option<bool>,
    pub args: Vec<String>,
}

impl Profile {
    pub fn load(path: &Path) -> Result<Profile, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read profile {}: {e}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new("."));
        let mut p = Profile::parse(&text)?;
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

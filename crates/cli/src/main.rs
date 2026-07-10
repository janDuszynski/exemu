//! `exemu` — the command-line front-end.
//!
//! Subcommands:
//!   * `run <file.exe> [--trace] [--no-echo] [-- args...]` — load and execute
//!   * `info <file.exe>`                                    — dump PE metadata
//!   * `sample <out.exe>`                                   — write a demo exe
//!
//! Argument parsing is hand-rolled to keep the dependency graph and build
//! time small; this is a thin presentation shell over `exemu-app`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use std::path::PathBuf;

use exemu_app::{gui_sample, sample, Process, RunConfig};
use exemu_core::{rank_opcode_misses, EmuError, ImportSymbol, MissRecord};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("exemu: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<u8, String> {
    let mut it = args.iter();
    let cmd = it.next().map(String::as_str);
    match cmd {
        Some("run") => cmd_run(it.as_slice()),
        Some("info") => cmd_info(it.as_slice()),
        Some("opcodes") => cmd_opcodes(it.as_slice()),
        Some("sample") => cmd_sample(it.as_slice()),
        Some("gui-sample") => cmd_gui_sample(it.as_slice()),
        Some("-h") | Some("--help") | Some("help") | None => {
            print_help();
            Ok(0)
        }
        Some("-V") | Some("--version") => {
            println!("exemu {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Some(other) => Err(format!("unknown command '{other}' (try `exemu --help`)")),
    }
}

fn print_help() {
    println!(
        "exemu {} — run Windows x86-64 .exe files on Apple Silicon\n\
\n\
USAGE:\n\
    exemu run <file.exe> [--trace] [--no-echo] [-- <args>...]\n\
    exemu info <file.exe>\n\
    exemu opcodes [--telemetry <path>] [--clear]\n\
    exemu sample <out.exe>\n\
    exemu gui-sample <out.exe>\n\
\n\
COMMANDS:\n\
    run        Load and execute a PE64 executable\n\
    info       Print headers, sections and imports of a PE64 file\n\
    opcodes    Rank unimplemented opcodes that blocked past runs (most-wanted)\n\
    sample     Generate a console demo .exe (Hello World via kernel32)\n\
    gui-sample Generate a GUI demo .exe (a real window; run with --gui)\n\
\n\
RUN OPTIONS:\n\
    --trace         Log calls to unimplemented Windows APIs\n\
    --no-echo       Do not mirror guest console output to the host\n\
    --gui           Render dialogs in a real window (drive them yourself)\n\
    --max-steps N   Instruction budget (0 = unlimited; default 2e9)\n\
    --load-base H   Map the image at hex address H instead of its preferred\n\
                    ImageBase and apply its base relocations (needs a .reloc)\n\
    --telemetry P   Opcode-miss log file (default $TMPDIR/exemu-telemetry.log,\n\
                    or the EXEMU_TELEMETRY env var)\n\
    -- <args>       Pass the remaining arguments to the guest program\n\
\n\
When a run stops on an instruction the decoder does not implement, the opcode\n\
is appended to the telemetry log; `exemu opcodes` ranks the log so the most\n\
impactful missing instruction to add next is obvious.\n\
\n\
Files a program writes (e.g. an installer's extracted files) go to a host\n\
sandbox under $TMPDIR/exemu-sandbox. For real installers, build with\n\
--release; a debug build is ~10x slower.\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn cmd_run(rest: &[String]) -> Result<u8, String> {
    let mut path: Option<&str> = None;
    let mut trace = false;
    let mut echo = true;
    let mut gui = false;
    let mut max_steps: Option<u64> = None;
    let mut telemetry: Option<String> = None;
    let mut load_base: Option<u64> = None;
    let mut guest_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--trace" => trace = true,
            "--no-echo" => echo = false,
            "--gui" => gui = true,
            "--max-steps" => {
                i += 1;
                let v = rest.get(i).ok_or("--max-steps needs a value (0 = unlimited)")?;
                max_steps = Some(v.replace('_', "").parse().map_err(|_| "bad --max-steps value")?);
            }
            "--telemetry" => {
                i += 1;
                telemetry = Some(rest.get(i).ok_or("--telemetry needs a <path>")?.clone());
            }
            "--load-base" => {
                i += 1;
                let v = rest.get(i).ok_or("--load-base needs a <hex-address>")?;
                let s = v.trim_start_matches("0x").replace('_', "");
                load_base = Some(
                    u64::from_str_radix(&s, 16).map_err(|_| "bad --load-base value (hex)")?,
                );
            }
            "--" => {
                guest_args.extend(rest[i + 1..].iter().cloned());
                break;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            other => {
                if path.is_none() {
                    path = Some(other);
                } else {
                    return Err(format!("unexpected argument '{other}'"));
                }
            }
        }
        i += 1;
    }

    let path = path.ok_or("run: missing <file.exe>")?;
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;

    // arg0 is conventionally the program name.
    let mut argv = vec![path.to_string()];
    argv.extend(guest_args);

    let mut cfg = RunConfig { args: argv, echo, trace, gui, load_base, ..RunConfig::default() };
    if let Some(m) = max_steps {
        cfg.max_steps = m;
    }
    let proc = Process::load(&bytes, &cfg).map_err(|e| e.to_string())?;
    // The guest filesystem lives here regardless of how the run ends.
    let sandbox = std::env::temp_dir().join("exemu-sandbox");
    let run = proc.run();

    report_sandbox(&sandbox);

    match run {
        Ok(result) => {
            eprintln!(
                "\n[exemu] process exited with code {} after {} instructions",
                result.exit_code, result.steps
            );
            Ok(result.exit_code as u8)
        }
        Err(e) => {
            // A run that dies on an instruction the decoder doesn't implement
            // is a data point for prioritizing the ISA (roadmap P0.5): record
            // it, then still surface the error. The run layer wraps faults in a
            // diagnostic `EmuError::Fault`, so reach the structured cause.
            if let EmuError::Decode { rip, opcode } = e.cause() {
                record_decode_miss(telemetry.as_deref(), path, *rip, opcode);
            }
            Err(e.to_string())
        }
    }
}

/// Resolve the opcode-miss telemetry log path: explicit `--telemetry` flag,
/// else the `EXEMU_TELEMETRY` env var, else a stable file under the temp dir.
fn telemetry_log_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    match std::env::var("EXEMU_TELEMETRY") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => std::env::temp_dir().join("exemu-telemetry.log"),
    }
}

/// Append one decode miss to the telemetry log (best-effort — a logging
/// failure must never mask the real run error) and tell the user about it.
fn record_decode_miss(explicit: Option<&str>, exe_path: &str, rip: u64, opcode: &str) {
    let exe = std::path::Path::new(exe_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(exe_path)
        .to_string();
    let log = telemetry_log_path(explicit);
    let rec = MissRecord { opcode: opcode.to_string(), rip, exe };

    eprintln!("\n[exemu] unimplemented opcode: {opcode} at {rip:#x}");
    use std::io::Write;
    let appended = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .and_then(|mut f| writeln!(f, "{}", rec.to_line()));
    match appended {
        Ok(()) => eprintln!(
            "[exemu] recorded to {} — rank blockers with `exemu opcodes`",
            log.display()
        ),
        Err(e) => eprintln!("[exemu] (could not write telemetry log {}: {e})", log.display()),
    }
}

/// List what the guest wrote into the sandbox filesystem, so the user knows
/// where an installer's extracted files actually went.
fn report_sandbox(sandbox: &std::path::Path) {
    fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    collect(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
    }
    let mut files = Vec::new();
    collect(sandbox, &mut files);
    if files.is_empty() {
        return;
    }
    files.sort();
    eprintln!("\n[exemu] guest filesystem: {}", sandbox.display());
    eprintln!("[exemu] {} file(s) created by the program; for example:", files.len());
    for p in files.iter().take(12) {
        if let Ok(rel) = p.strip_prefix(sandbox) {
            eprintln!("          {}", rel.display());
        }
    }
    if files.len() > 12 {
        eprintln!("          … and {} more", files.len() - 12);
    }
}

fn cmd_info(rest: &[String]) -> Result<u8, String> {
    let path = rest.first().ok_or("info: missing <file.exe>")?;
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let image = exemu_loader::parse(&bytes).map_err(|e| e.to_string())?;

    println!("PE image: {path}");
    println!("  format       : {}", if image.is_64bit { "PE32+ (x86-64)" } else { "PE32 (x86-32)" });
    println!("  image base   : {:#018x}", image.image_base);
    println!("  entry point  : {:#018x} (rva {:#x})", image.entry_va(), image.entry_rva);
    println!("  size of image: {:#x}", image.size_of_image);
    println!(
        "  subsystem    : {} ({})",
        image.subsystem,
        match image.subsystem {
            2 => "Windows GUI",
            3 => "Windows console",
            _ => "other",
        }
    );
    println!("  stack reserve: {:#x}", image.stack_reserve);

    println!("\n  sections ({}):", image.sections.len());
    println!("    {:<10} {:>10} {:>10} {:>10}  perms", "name", "rva", "vsize", "rawsize");
    for s in &image.sections {
        let perms = format!(
            "{}{}{}",
            if s.readable { "r" } else { "-" },
            if s.writable { "w" } else { "-" },
            if s.executable { "x" } else { "-" }
        );
        println!(
            "    {:<10} {:>#10x} {:>#10x} {:>10}  {perms}",
            s.name,
            s.rva,
            s.virtual_size,
            s.data.len()
        );
    }

    if !image.function_table.is_empty() {
        let with_handler =
            image.function_table.iter().filter(|e| e.info.handler_rva.is_some()).count();
        println!(
            "\n  x64 unwind data: {} runtime functions ({} with a language handler)",
            image.function_table.len(),
            with_handler
        );
    }

    println!("\n  imports ({}):", image.imports.len());
    let mut current = String::new();
    for imp in &image.imports {
        if imp.dll != current {
            current = imp.dll.clone();
            println!("    {current}:");
        }
        match &imp.symbol {
            ImportSymbol::Named(n) => println!("      {n}"),
            ImportSymbol::Ordinal(o) => println!("      #{o}"),
        }
    }

    let dialogs = exemu_loader::parse_dialogs(&bytes);
    if !dialogs.is_empty() {
        let mut ids: Vec<_> = dialogs.keys().copied().collect();
        ids.sort();
        println!("\n  dialogs ({}):", dialogs.len());
        for id in ids {
            let d = &dialogs[&id];
            println!("    #{id} \"{}\" ({}x{} du, {} controls)", d.title, d.cx, d.cy, d.controls.len());
            for c in &d.controls {
                println!("      id={:<5} {:?} {:?}", c.id, c.kind, c.text);
            }
        }
    }

    Ok(0)
}

/// `opcodes [--telemetry <path>] [--clear]` — read the decode-miss log and
/// print the most-wanted ranking of unimplemented opcodes, so the highest-
/// leverage instruction to implement next is obvious (roadmap P0.5).
fn cmd_opcodes(rest: &[String]) -> Result<u8, String> {
    let mut explicit: Option<&str> = None;
    let mut clear = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--telemetry" => {
                i += 1;
                explicit = Some(rest.get(i).ok_or("--telemetry needs a <path>")?.as_str());
            }
            "--clear" => clear = true,
            other => return Err(format!("opcodes: unexpected argument '{other}'")),
        }
        i += 1;
    }

    let log = telemetry_log_path(explicit);
    if clear {
        match std::fs::remove_file(&log) {
            Ok(()) => println!("cleared {}", log.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("already empty ({})", log.display())
            }
            Err(e) => return Err(format!("cannot clear {}: {e}", log.display())),
        }
        return Ok(0);
    }

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let ranked = rank_opcode_misses(text.lines().filter_map(MissRecord::parse));
    if ranked.is_empty() {
        println!("no decode misses recorded yet ({})", log.display());
        println!("run some executables; blockers are logged automatically.");
        return Ok(0);
    }

    let total: usize = ranked.iter().map(|r| r.count).sum();
    println!(
        "most-wanted unimplemented opcodes — {} miss(es), {} distinct ({})",
        total,
        ranked.len(),
        log.display()
    );
    println!("  {:>4}  {:<14}  {:<18}  exes", "hits", "opcode", "example rip");
    for r in &ranked {
        println!(
            "  {:>4}  {:<14}  {:#018x}  {}",
            r.count,
            r.opcode,
            r.example_rip,
            r.exes.join(", ")
        );
    }
    Ok(0)
}

fn cmd_sample(rest: &[String]) -> Result<u8, String> {
    let path = rest.first().ok_or("sample: missing <out.exe>")?;
    let bytes = sample::build();
    std::fs::write(path, &bytes).map_err(|e| format!("cannot write {path}: {e}"))?;
    println!(
        "wrote {} bytes to {path} — try:  exemu run {path}",
        bytes.len()
    );
    Ok(0)
}

fn cmd_gui_sample(rest: &[String]) -> Result<u8, String> {
    let path = rest.first().ok_or("gui-sample: missing <out.exe>")?;
    let bytes = gui_sample::build();
    std::fs::write(path, &bytes).map_err(|e| format!("cannot write {path}: {e}"))?;
    println!(
        "wrote {} bytes to {path} — a real GUI window; try:  exemu run --gui {path}",
        bytes.len()
    );
    Ok(0)
}

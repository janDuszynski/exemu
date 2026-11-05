#![forbid(unsafe_code)]

use std::process::ExitCode;

use std::path::{Path, PathBuf};

use exemu_app::{audio_sample, gui_sample, sample, Process, RunConfig};
use exemu_cli::{corpus, profile};
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
        Some("corpus") => corpus::cmd_corpus(it.as_slice()),
        Some("sample") => cmd_sample(it.as_slice()),
        Some("gui-sample") => cmd_gui_sample(it.as_slice()),
        Some("audio-sample") => cmd_audio_sample(it.as_slice()),
        Some("cocoa-demo") => cmd_cocoa_demo(it.as_slice()),
        Some("-h") | Some("--help") | Some("help") | None => {
            print_help();
            Ok(0)
        }
        Some("-V") | Some("--version") => {
            println!("exemu {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Some(other) => {
            if Path::new(other).is_file() {
                cmd_run(&args)
            } else {
                Err(format!("unknown command '{other}' (try `exemu --help`)"))
            }
        }
    }
}

fn print_help() {
    println!(
        "exemu {} — run Windows x86-64 .exe files on Apple Silicon\n\
\n\
USAGE:\n\
    exemu run <file.exe> [--profile P] [--trace] [--no-echo] [--virtual-clock] [--jit] [-- <args>...]\n\
    exemu run --profile P                 (a profile can supply <file.exe> itself)\n\
    exemu info <file.exe>\n\
    exemu opcodes [--telemetry <path>] [--clear]\n\
    exemu corpus [--manifest <path>] [--only <substr>] [--quick] [--update]\n\
    exemu sample <out.exe>\n\
    exemu gui-sample <out.exe>\n\
    exemu audio-sample <out.exe>\n\
    exemu cocoa-demo [--size WxH] [--hold SECS]\n\
\n\
COMMANDS:\n\
    run        Load and execute a PE64 executable\n\
    info       Print headers, sections and imports of a PE64 file\n\
    opcodes    Rank unimplemented opcodes that blocked past runs (most-wanted)\n\
    corpus     Run the pinned corpus binaries and diff against the manifest\n\
    sample     Generate a console demo .exe (Hello World via kernel32)\n\
    gui-sample Generate a GUI demo .exe (a real window; run with --gui)\n\
    audio-sample\n\
               Generate a WASAPI demo .exe that plays a short tone\n\
               (run with --wine-boot and --audio)\n\
    cocoa-demo Open a live macOS NSWindow/Metal window showing a test frame\n\
               through the W4.4 CocoaPresenter blit path (macOS only)\n\
\n\
CORPUS OPTIONS:\n\
    --manifest P    Pin file (default corpus.toml in the working directory)\n\
    --only S        Run only binaries whose name contains S\n\
    --quick         Run only the entries flagged `quick` (seconds, not minutes)\n\
    --update        Re-bless the manifest from this run's measurements\n\
\n\
Each corpus binary runs in its own `exemu run` child with a private TMPDIR, so\n\
its sandbox artifacts are counted in isolation. Exit status is 1 on any drift.\n\
Use a --release build: a debug build is ~10x slower and 7-Zip alone executes\n\
~496M instructions.\n\
\n\
RUN OPTIONS:\n\
    --profile P     Load run settings from the [profile] in TOML file P —\n\
                    max-steps, sandbox root, Wine prefix, DPI, backend, --jit,\n\
                    --virtual-clock — so a known-good binary runs without\n\
                    remembering flags. A profile sets DEFAULTS: any flag you\n\
                    also type, or a positional <file.exe>, still wins over what\n\
                    the profile says (roadmap W9.4). See corpus.toml's sibling\n\
                    format, documented in exemu_cli::profile\n\
    --trace         Log calls to unimplemented Windows APIs\n\
    --no-echo       Do not mirror guest console output to the host\n\
    --gui           Render dialogs in a real window (drive them yourself)\n\
    --sandbox-root P  Root the guest filesystem at P instead of the shared\n\
                    $TMPDIR/exemu-sandbox (also settable per-binary via a\n\
                    --profile's sandbox_root, roadmap W9.4)\n\
    --dpi N         Logical DPI a DPI-aware guest is told the system runs at\n\
                    (default 96). Reaches GetSystemDpiForProcess/GetDpiForWindow\n\
                    only — NOT the EnumDisplaySettings device mode, which still\n\
                    reports 96 (roadmap W9.4)\n\
    --wine-boot D   Boot on Wine's PE DLL set in dir D — the \"Wine prefix\"; with\n\
                    --gui on macOS the guest's windows appear as native\n\
                    NSWindows (roadmap W4.5)\n\
    --virtual-clock Drive every clock the guest can read (RDTSC, GetTickCount,\n\
                    QueryPerformanceCounter, NtQuerySystemTime, KUSER_SHARED_\n\
                    DATA) from the instruction count instead of the host clock,\n\
                    at 10M instructions/second from a fixed 2026-01-01 epoch, so\n\
                    a run executes the SAME instruction count every time. Also\n\
                    settable with EXEMU_VIRTUAL_CLOCK=1 (roadmap W9.6)\n\
    --audio         Send what the guest plays to the real CoreAudio device.\n\
                    Needs --wine-boot: audio arrives through Wine's mmdevapi.\n\
                    Without it audio is accepted and dropped (roadmap W7.2)\n\
    --jit           Run guest code through the block JIT where it can, and\n\
                    report how much of the run went native (roadmap W8). Off by\n\
                    default; also settable with EXEMU_JIT=1\n\
    --opcode-profile  Print a dynamic opcode-frequency profile of the run\n\
                    (roadmap W8.3). Needs an instrumented build:\n\
                    cargo build --release -p exemu-cli --features opcode-profile\n\
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
    let mut loaded_profile: Option<profile::Profile> = None;
    for (idx, a) in rest.iter().enumerate() {
        if a == "--" {
            break;
        }
        if a == "--profile" {
            let p = rest.get(idx + 1).ok_or("--profile needs a <path>")?;
            loaded_profile = Some(
                profile::Profile::load(Path::new(p)).map_err(|e| format!("--profile: {e}"))?,
            );
            break;
        }
    }
    let prof = loaded_profile.as_ref();

    let mut path: Option<&str> = None;
    let mut trace = prof.and_then(|p| p.trace).unwrap_or(false);
    let mut echo = true;
    let mut gui = prof.and_then(|p| p.backend) == Some(profile::Backend::Window);
    let mut max_steps: Option<u64> = prof.and_then(|p| p.max_steps);
    let mut telemetry: Option<String> = None;
    let mut load_base: Option<u64> = None;
    let mut wine_boot: Option<String> = prof.and_then(|p| p.wine_boot_dir.clone());
    let mut virtual_clock = prof.and_then(|p| p.virtual_clock).unwrap_or(false);
    let mut audio = prof.and_then(|p| p.audio).unwrap_or(false);
    let mut opcode_profile = false;
    let mut jit = prof.and_then(|p| p.jit).unwrap_or(false);
    let mut sandbox_root: Option<String> = prof.and_then(|p| p.sandbox_root.clone());
    let mut dpi: Option<u32> = prof.and_then(|p| p.dpi);
    let profile_path = prof.and_then(|p| p.path.clone());
    let profile_args: Vec<String> = prof.map(|p| p.args.clone()).unwrap_or_default();
    let mut guest_args: Vec<String> = Vec::new();
    let mut explicit_args_given = false;

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--trace" => trace = true,
            "--no-echo" => echo = false,
            "--gui" => gui = true,
            "--virtual-clock" => virtual_clock = true,
            "--audio" => audio = true,
            "--opcode-profile" => opcode_profile = true,
            "--jit" => jit = true,
            "--profile" => {
                i += 1;
            }
            "--max-steps" => {
                i += 1;
                let v = rest.get(i).ok_or("--max-steps needs a value (0 = unlimited)")?;
                max_steps = Some(v.replace('_', "").parse().map_err(|_| "bad --max-steps value")?);
            }
            "--sandbox-root" => {
                i += 1;
                sandbox_root = Some(rest.get(i).ok_or("--sandbox-root needs a <path>")?.clone());
            }
            "--dpi" => {
                i += 1;
                let v = rest.get(i).ok_or("--dpi needs a value")?;
                dpi = Some(v.parse().map_err(|_| "bad --dpi value")?);
            }
            "--telemetry" => {
                i += 1;
                telemetry = Some(rest.get(i).ok_or("--telemetry needs a <path>")?.clone());
            }
            "--wine-boot" => {
                i += 1;
                wine_boot = Some(rest.get(i).ok_or("--wine-boot needs a <dir>")?.clone());
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
                explicit_args_given = true;
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

    let path = path
        .or(profile_path.as_deref())
        .ok_or("run: missing <file.exe> (or a --profile that sets `path`)")?;
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let final_guest_args = if explicit_args_given { guest_args } else { profile_args };

    let mut argv = vec![path.to_string()];
    argv.extend(final_guest_args);

    let mut cfg = RunConfig {
        args: argv,
        echo,
        trace,
        gui,
        load_base,
        virtual_clock,
        jit,
        dpi: dpi.unwrap_or(96),
        ..RunConfig::default()
    };
    if let Some(m) = max_steps {
        cfg.max_steps = m;
    }
    cfg.wine_boot_dir = wine_boot;
    cfg.sandbox_root = sandbox_root.map(PathBuf::from);
    if audio {
        cfg.audio_sink = Some(Box::new(exemu_audio::CoreAudioSink::new()));
    }

    let sandbox =
        cfg.sandbox_root.clone().unwrap_or_else(|| std::env::temp_dir().join("exemu-sandbox"));

    #[cfg(target_os = "macos")]
    if gui && cfg.wine_boot_dir.is_some() {
        return run_live_cocoa(bytes, cfg, &sandbox);
    }

    let mut proc = Process::load(&bytes, &mut cfg).map_err(|e| e.to_string())?;
    let run = proc.run_borrowed();
    let jit_report = proc.jit_report();

    report_sandbox(&sandbox);
    if opcode_profile {
        print_opcode_profile();
    }

    match run {
        Ok(result) => {
            eprintln!(
                "\n[exemu] process exited with code {} after {} instructions",
                result.exit_code, result.steps
            );
            report_jit(&jit_report, result.steps);
            Ok(result.exit_code as u8)
        }
        Err(e) => {
            report_jit(&jit_report, 0);
            if let EmuError::Decode { rip, opcode } = e.cause() {
                record_decode_miss(telemetry.as_deref(), path, *rip, opcode);
            }
            Err(e.to_string())
        }
    }
}

fn report_jit(report: &Option<exemu_app::JitReport>, steps: u64) {
    if let Some(j) = report {
        let total = if steps != 0 { steps } else { j.insns_executed + j.not_compiled };
        let share = 100.0 * j.insns_executed as f64 / total.max(1) as f64;
        let chain = if j.chains != 0 { j.blocks_executed as f64 / j.chains as f64 } else { 0.0 };
        eprintln!(
            "[exemu] jit: {:.1}% of instructions native ({} of {}), {} blocks \
             ({} KiB of code), {} block entries, {:.1} blocks/chain, {} rewinds, \
             {} side-exits, {} flushes",
            share,
            j.insns_executed,
            total,
            j.blocks_compiled,
            j.code_bytes / 1024,
            j.blocks_executed,
            chain,
            j.faults,
            j.not_compiled,
            j.flushes
        );
        let top: Vec<String> = j
            .declined
            .iter()
            .take(10)
            .map(|(k, c)| {
                if k & 0x100 != 0 {
                    format!("0f{:02x}×{c}", k & 0xff)
                } else {
                    format!("{:02x}×{c}", k & 0xff)
                }
            })
            .collect();
        if !top.is_empty() {
            eprintln!("[exemu] jit: blocks stopped by (opcode×times): {}", top.join(" "));
        }
    }
}

fn print_opcode_profile() {
    #[cfg(feature = "opcode-profile")]
    {
        eprintln!("\n{}", exemu_cpu::profile::report(60));
    }
    #[cfg(not(feature = "opcode-profile"))]
    {
        eprintln!(
            "\n[exemu] --opcode-profile needs an instrumented build:\n\
             \x20        cargo build --release -p exemu-cli --features opcode-profile"
        );
    }
}

#[cfg(target_os = "macos")]
fn run_live_cocoa(
    bytes: Vec<u8>,
    mut cfg: RunConfig,
    sandbox: &std::path::Path,
) -> Result<u8, String> {
    cfg.gui = false;
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let (input_tx, input_rx) = std::sync::mpsc::channel();
    cfg.driver = Some(Box::new(exemu_gui::CocoaPresenter::with_channel(cmd_tx)));
    cfg.input = Some(input_rx);

    let interp = std::thread::spawn(move || {
        let mut cfg = cfg;
        Process::load(&bytes, &mut cfg).and_then(|p| p.run())
    });

    exemu_gui::run_live(cmd_rx, input_tx, 3.0);

    let run = interp.join().map_err(|_| "interpreter thread panicked".to_string())?;
    report_sandbox(sandbox);
    match run {
        Ok(result) => {
            eprintln!(
                "\n[exemu] process exited with code {} after {} instructions",
                result.exit_code, result.steps
            );
            report_jit(&result.jit, result.steps);
            Ok(result.exit_code as u8)
        }
        Err(e) => Err(e.to_string()),
    }
}

fn telemetry_log_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    match std::env::var("EXEMU_TELEMETRY") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => std::env::temp_dir().join("exemu-telemetry.log"),
    }
}

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

    let res_entries = exemu_loader::list_resources(&bytes);
    if !res_entries.is_empty() {
        use std::collections::BTreeMap;
        let mut by_type: BTreeMap<u32, (Option<String>, usize)> = BTreeMap::new();
        for e in &res_entries {
            let entry = by_type.entry(e.type_id).or_insert_with(|| (e.type_name.clone(), 0));
            entry.1 += 1;
        }
        println!("\n  resources ({} entries):", res_entries.len());
        for (tid, (tname, count)) in &by_type {
            let label = if let Some(n) = tname {
                format!("named:{n}")
            } else {
                exemu_loader::rt_name(*tid)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("type#{tid}"))
            };
            println!("    {label:<20} {count} entrie(s)");
        }

        if let Some(info) = exemu_loader::find_version_info(&bytes) {
            let (ma, mi, pa, bu) = info.file_version();
            println!("  version              : {ma}.{mi}.{pa}.{bu}");
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
    } else {
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
    }

    Ok(0)
}

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

fn cmd_audio_sample(rest: &[String]) -> Result<u8, String> {
    let path = rest.first().ok_or("audio-sample: missing <out.exe>")?;
    let bytes = audio_sample::build();
    std::fs::write(path, &bytes).map_err(|e| format!("cannot write {path}: {e}"))?;
    println!(
        "wrote {} bytes to {path} — plays {} frames through Wine's mmdevapi; try:\n  \
         exemu run --wine-boot <wine-dll-dir> --audio {path}",
        bytes.len(),
        audio_sample::PATTERN_FRAMES
    );
    Ok(0)
}

fn cmd_cocoa_demo(rest: &[String]) -> Result<u8, String> {
    let mut w = 480u32;
    let mut h = 320u32;
    let mut hold = 3.0f64;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--size" => {
                i += 1;
                let v = rest.get(i).ok_or("--size needs a WxH value")?;
                let (ws, hs) = v.split_once('x').ok_or("--size must look like 640x480")?;
                w = ws.parse().map_err(|_| "bad --size width")?;
                h = hs.parse().map_err(|_| "bad --size height")?;
            }
            "--hold" => {
                i += 1;
                hold = rest
                    .get(i)
                    .ok_or("--hold needs a value in seconds")?
                    .parse()
                    .map_err(|_| "bad --hold value")?;
            }
            other => return Err(format!("cocoa-demo: unexpected argument '{other}'")),
        }
        i += 1;
    }
    let w = w.clamp(64, 4096);
    let h = h.clamp(64, 4096);
    let bgra = demo_pattern(w, h);

    #[cfg(target_os = "macos")]
    {
        println!("[exemu] opening a {w}x{h} Cocoa/Metal window for {hold:.1}s — close it or wait…");
        exemu_gui::cocoa_demo(w, h, "exemu — cocoa-demo (W4.4)", &bgra, hold)?;
        println!("[exemu] cocoa-demo done");
        Ok(0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (&bgra, hold);
        Err("cocoa-demo is macOS-only (the Cocoa/Metal display presenter)".into())
    }
}

fn demo_pattern(w: u32, h: u32) -> Vec<u8> {
    let mut px = vec![0u8; (w as usize) * (h as usize) * 4];
    for y in 0..h {
        for x in 0..w {
            let o = ((y as usize) * (w as usize) + x as usize) * 4;
            let border = x < 2 || y < 2 || x + 2 >= w || y + 2 >= h;
            let green_sq = x >= w / 4 && x < w / 2 && y >= h / 4 && y < h / 2;
            let (b, g, r) = if border {
                (255u8, 255u8, 255u8)
            } else if green_sq {
                (0, 200, 0)
            } else {
                let r = (u64::from(x) * 255 / u64::from(w)) as u8;
                (255 - r, 0, r)
            };
            px[o] = b;
            px[o + 1] = g;
            px[o + 2] = r;
            px[o + 3] = 255;
        }
    }
    px
}

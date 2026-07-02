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

use exemu_app::{sample, Process, RunConfig};
use exemu_core::ImportSymbol;

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
        Some("sample") => cmd_sample(it.as_slice()),
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
    exemu sample <out.exe>\n\
\n\
COMMANDS:\n\
    run      Load and execute a PE64 executable\n\
    info     Print headers, sections and imports of a PE64 file\n\
    sample   Generate a self-contained demo .exe (Hello World via kernel32)\n\
\n\
RUN OPTIONS:\n\
    --trace     Log calls to unimplemented Windows APIs\n\
    --no-echo   Do not mirror guest console output to the host\n\
    -- <args>   Pass the remaining arguments to the guest program\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn cmd_run(rest: &[String]) -> Result<u8, String> {
    let mut path: Option<&str> = None;
    let mut trace = false;
    let mut echo = true;
    let mut guest_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--trace" => trace = true,
            "--no-echo" => echo = false,
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

    let cfg = RunConfig { args: argv, echo, trace, ..RunConfig::default() };
    let proc = Process::load(&bytes, &cfg).map_err(|e| e.to_string())?;
    let result = proc.run().map_err(|e| e.to_string())?;

    eprintln!(
        "\n[exemu] process exited with code {} after {} instructions",
        result.exit_code, result.steps
    );
    Ok(result.exit_code as u8)
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

//! # exemu-app — the application layer
//!
//! This is the use-case layer that ties the infrastructure together. It:
//!
//! 1. parses the PE with `exemu-loader`,
//! 2. builds the process address space in `exemu-memory` (headers, sections,
//!    stack, a TEB/PEB pair behind `gs:`, a heap arena and the command line),
//! 3. resolves imports into OS thunks and patches the IAT,
//! 4. runs the `exemu-cpu` interpreter against the `exemu-os` hooks until the
//!    process exits.
//!
//! It owns the memory-layout policy (where the stack, heap and thunks live)
//! so the inner layers stay policy-free.

#![forbid(unsafe_code)]

pub mod sample;

use exemu_core::{Cpu, EmuError, Exit, Memory, Perm, Region, Result};
use exemu_cpu::{Bits, Interpreter, FS_BASE_32, GS_BASE};
use exemu_loader as loader;
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// ---- Address-space layout policy -------------------------------------------

const PAGE: u64 = 0x1000;
const TEB_SIZE: u64 = 0x1000;
const ENV_SIZE: u64 = 0x1000;
const API_SIZE: u64 = 0x0010_0000; // 1 MiB → 128k import slots

/// Where the various regions live, chosen per bitness so 32-bit processes
/// stay entirely within the low 4 GiB.
struct Layout {
    stack_base: u64,
    stack_size: u64,
    heap_base: u64,
    heap_size: u64,
    api_base: u64,
    env_base: u64,
    teb_base: u64,
    peb_addr: u64,
    // TEB/PEB field offsets (they differ between the 32- and 64-bit structs).
    teb_self: u64,
    teb_peb: u64,
    teb_stack_base: u64,
    teb_stack_limit: u64,
    peb_image_base: u64,
}

impl Layout {
    fn for_bits(is_64bit: bool) -> Layout {
        if is_64bit {
            Layout {
                stack_base: 0x0000_0010_0000_0000,
                stack_size: 0x0020_0000, // 2 MiB
                heap_base: 0x0000_0002_0000_0000,
                heap_size: 0x0400_0000, // 64 MiB
                api_base: 0x0000_7EFF_0000_0000,
                env_base: 0x0000_0000_5000_0000,
                teb_base: GS_BASE,
                peb_addr: GS_BASE + 0x2000,
                teb_self: 0x30,
                teb_peb: 0x60,
                teb_stack_base: 0x08,
                teb_stack_limit: 0x10,
                peb_image_base: 0x10,
            }
        } else {
            // Everything below 4 GiB, clear of a typical image at 0x400000+.
            Layout {
                stack_base: 0x0018_0000,
                stack_size: 0x0020_0000, // 2 MiB, top at 0x0038_0000 (below image)
                heap_base: 0x1000_0000,
                heap_size: 0x0400_0000, // 64 MiB
                api_base: 0x7000_0000,
                env_base: 0x0010_0000,
                teb_base: FS_BASE_32,
                peb_addr: FS_BASE_32 + 0x2000,
                teb_self: 0x18,  // NT_TIB.Self
                teb_peb: 0x30,   // ProcessEnvironmentBlock
                teb_stack_base: 0x04,
                teb_stack_limit: 0x08,
                peb_image_base: 0x08,
            }
        }
    }
}

/// Options controlling a run.
pub struct RunConfig {
    /// Command-line arguments (arg0 should be the program name).
    pub args: Vec<String>,
    /// Echo guest console output to the host stdio.
    pub echo: bool,
    /// Log unimplemented API calls.
    pub trace: bool,
    /// Safety cap on executed instructions (0 = unlimited).
    pub max_steps: u64,
}

impl Default for RunConfig {
    fn default() -> Self {
        RunConfig { args: vec!["program.exe".into()], echo: true, trace: false, max_steps: 50_000_000 }
    }
}

/// The result of running a program to completion.
pub struct RunResult {
    pub exit_code: i32,
    pub steps: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A loaded, ready-to-run process.
pub struct Process {
    mem: VirtualMemory,
    cpu: Interpreter,
    os: WinOs,
    entry: u64,
    max_steps: u64,
}

impl Process {
    /// Parse and lay out `pe_bytes` into a runnable process.
    pub fn load(pe_bytes: &[u8], cfg: &RunConfig) -> Result<Process> {
        let image = loader::parse(pe_bytes)?;
        let mut mem = VirtualMemory::new();

        // --- Map headers and sections at the preferred image base ---------
        let base = image.image_base;
        let hdr_len = align_up(image.size_of_headers as u64, PAGE).max(PAGE);
        mem.map_with_data("headers", base, hdr_len, &image.headers, Perm::READ)?;

        for s in &image.sections {
            let addr = base + s.rva as u64;
            let size = align_up((s.virtual_size as u64).max(s.data.len() as u64), PAGE).max(PAGE);
            // Always at least readable; add write/exec from the section flags.
            let mut perm = Perm::READ;
            if s.writable {
                perm = perm.union(Perm::WRITE);
            }
            if s.executable {
                perm = perm.union(Perm::EXEC);
            }
            mem.map_with_data(section_name(&s.name), addr, size, &s.data, perm)?;
        }

        let lay = Layout::for_bits(image.is_64bit);
        let ptr_size = if image.is_64bit { 8 } else { 4 };

        // --- Stack --------------------------------------------------------
        mem.map(Region::new("stack", lay.stack_base, lay.stack_size, Perm::RW))?;

        // --- Heap arena (bump-allocated by the OS layer) ------------------
        mem.map(Region::new("heap", lay.heap_base, lay.heap_size, Perm::RW))?;

        // --- TEB / PEB behind fs:(32-bit) or gs:(64-bit) ------------------
        mem.map(Region::new("teb", lay.teb_base, TEB_SIZE, Perm::RW))?;
        mem.map(Region::new("peb", align_down(lay.peb_addr, PAGE), PAGE, Perm::RW))?;
        let stack_top = lay.stack_base + lay.stack_size;
        let write_ptr = |mem: &mut VirtualMemory, addr: u64, val: u64| -> Result<()> {
            mem.poke(addr, &val.to_le_bytes()[..ptr_size])
        };
        write_ptr(&mut mem, lay.teb_base + lay.teb_self, lay.teb_base)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_peb, lay.peb_addr)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_stack_base, stack_top)?;
        write_ptr(&mut mem, lay.teb_base + lay.teb_stack_limit, lay.stack_base)?;
        write_ptr(&mut mem, lay.peb_addr + lay.peb_image_base, base)?;

        // --- Command line (ASCII + UTF-16) in the env region --------------
        mem.map(Region::new("env", lay.env_base, ENV_SIZE, Perm::RW))?;
        let cmdline = build_cmdline(&cfg.args);
        let cmd_a = lay.env_base;
        let mut ascii = cmdline.clone().into_bytes();
        ascii.push(0);
        mem.poke(cmd_a, &ascii)?;
        let cmd_w = lay.env_base + 0x400;
        let mut wide: Vec<u8> = Vec::new();
        for u in cmdline.encode_utf16() {
            wide.extend_from_slice(&u.to_le_bytes());
        }
        wide.extend_from_slice(&[0, 0]);
        mem.poke(cmd_w, &wide)?;

        // --- The OS layer and import resolution ---------------------------
        let mut os = WinOs::new(WinConfig {
            api_base: lay.api_base,
            heap_base: lay.heap_base,
            heap_size: lay.heap_size,
            image_base: base,
            cmdline_ptr_a: cmd_a,
            cmdline_ptr_w: cmd_w,
            echo: cfg.echo,
            trace: cfg.trace,
            is_64bit: image.is_64bit,
        });

        // Map the thunk region as real read/write memory. Function imports
        // are intercepted on *execution* (rip match) before any fetch, so
        // they never touch this backing store; but *data* imports — a DLL
        // exporting a variable, common in the C runtime — are dereferenced as
        // memory, and land here instead of faulting. Known CRT data globals
        // are seeded below; the rest default to zero (their normal initial
        // value).
        mem.map(Region::new("imports", lay.api_base, API_SIZE, Perm::RW))?;

        for imp in &image.imports {
            let thunk = os.resolve_import(&imp.dll, &imp.symbol);
            mem.poke(base + imp.iat_rva as u64, &thunk.to_le_bytes()[..ptr_size])?;
            if let exemu_core::ImportSymbol::Named(name) = &imp.symbol {
                if let Some(value) = data_import_seed(name, cmd_a, cmd_w) {
                    mem.poke(thunk, &value.to_le_bytes()[..ptr_size])?;
                }
            }
        }

        // --- Initial CPU state --------------------------------------------
        let mut cpu = Interpreter::with_bits(if image.is_64bit { Bits::B64 } else { Bits::B32 });
        // Align the stack, then push the sentinel return address so the entry
        // sees the stack exactly as a real `call entry` would leave it.
        let exit_thunk = os.exit_thunk();
        let rsp = if image.is_64bit {
            let mut sp = (stack_top - 0x100) & !0xf;
            sp -= 8;
            mem.write_u64(sp, exit_thunk)?;
            sp
        } else {
            let mut sp = (stack_top - 0x100) & !0xf;
            sp -= 4;
            mem.write_u32(sp, exit_thunk as u32)?;
            sp
        };
        cpu.state_mut().set_rsp(rsp);
        cpu.state_mut().rip = image.entry_va();

        Ok(Process { mem, cpu, os, entry: image.entry_va(), max_steps: cfg.max_steps })
    }

    /// The entry-point virtual address.
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// Run until the process exits (or the step cap / a fault is hit).
    pub fn run(mut self) -> Result<RunResult> {
        let mut steps: u64 = 0;
        let exit_code = loop {
            if self.max_steps != 0 && steps >= self.max_steps {
                return Err(EmuError::Os(format!(
                    "instruction budget exhausted after {steps} steps (possible infinite loop)"
                )));
            }
            let outcome = self.cpu.step(&mut self.mem, &mut self.os);
            match outcome {
                Ok(Exit::Continue) => steps += 1,
                Ok(Exit::ProcessExit(code)) => break code,
                Ok(Exit::Halted) => break 0,
                Ok(Exit::Interrupt(0x80)) => {
                    return Err(self.fault(
                        EmuError::Unsupported("direct SYSCALL instruction (no syscall layer emulated)".into()),
                        steps,
                    ));
                }
                Ok(Exit::Interrupt(n)) => {
                    return Err(self.fault(EmuError::Os(format!("unhandled interrupt {n:#x}")), steps));
                }
                Err(e) => return Err(self.fault(e, steps)),
            }
        };

        Ok(RunResult {
            exit_code,
            steps,
            stdout: self.os.captured_stdout().to_vec(),
            stderr: self.os.captured_stderr().to_vec(),
        })
    }

    /// Wrap a fault with a diagnostic snapshot: the faulting instruction
    /// pointer, the bytes there (if fetchable), and the register file. This
    /// turns an opaque "unmapped memory access" into an actionable location.
    fn fault(&self, err: EmuError, steps: u64) -> EmuError {
        use std::fmt::Write;
        let s = self.cpu.state();
        let mut o = String::new();
        let _ = writeln!(o, "{err}");

        // If the fault touched an import thunk, the guest is treating an
        // imported *function* slot as data — the tell-tale of a data export
        // (very common in the MSVCRT C runtime, e.g. _fmode/_commode).
        if let EmuError::Unmapped { addr, .. } = &err {
            let (lo, hi) = self.os.thunk_range();
            if *addr >= lo && *addr < hi {
                let sym = self.os.symbol_for_thunk(*addr).unwrap_or_else(|| "<unknown import>".into());
                let _ = writeln!(
                    o,
                    "  note: {addr:#018x} is the import thunk for {sym}.\n\
                     \x20       the guest is dereferencing it as data, so {sym} is a *data* export,\n\
                     \x20       not a function. exemu resolves imports as call targets only; data\n\
                     \x20       imports (common in msvcrt/UCRT startup) are not supported."
                );
            }
        }

        let _ = writeln!(o, "  faulted after {steps} instructions");
        let _ = writeln!(
            o,
            "  rip={:#018x}  rsp={:#018x}  rbp={:#018x}  rflags={:#06x}",
            s.rip,
            s.rsp(),
            s.reg(exemu_core::Reg::Rbp),
            s.rflags
        );
        for row in s.gpr.chunks(4).enumerate() {
            let (r, regs) = row;
            let _ = write!(o, "  ");
            for (i, v) in regs.iter().enumerate() {
                let name = exemu_core::Reg::NAMES[r * 4 + i];
                let _ = write!(o, "{name:>3}={v:#018x}  ");
            }
            o.push('\n');
        }
        // Instruction bytes at rip, if the page is executable/readable.
        let mut buf = [0u8; 16];
        match self.mem.fetch(s.rip, &mut buf) {
            Ok(()) => {
                let _ = write!(o, "  bytes @ rip:");
                for b in buf {
                    let _ = write!(o, " {b:02x}");
                }
            }
            Err(_) => {
                let _ = write!(o, "  (cannot fetch instruction bytes at rip — page not mapped/executable)");
            }
        }
        EmuError::Os(o)
    }
}

/// Convenience: load and run in one call.
pub fn load_and_run(pe_bytes: &[u8], cfg: RunConfig) -> Result<RunResult> {
    Process::load(pe_bytes, &cfg)?.run()
}

// ---- helpers ---------------------------------------------------------------

#[inline]
fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

#[inline]
fn align_down(v: u64, align: u64) -> u64 {
    v & !(align - 1)
}

fn section_name(raw: &str) -> String {
    if raw.is_empty() {
        "section".to_string()
    } else {
        raw.to_string()
    }
}

/// Initial value for a known imported *data* symbol (a variable exported by
/// a DLL). Returns `None` for symbols that should keep their zero default.
fn data_import_seed(name: &str, cmd_a: u64, cmd_w: u64) -> Option<u64> {
    match name {
        // The C runtime's cached command-line pointers.
        "_acmdln" => Some(cmd_a),
        "_wcmdln" => Some(cmd_w),
        // _fmode (text/binary), _commode (commit mode), environ pointers,
        // etc. all correctly default to 0, which the zeroed mapping provides.
        _ => None,
    }
}

/// Build a Windows-style command line from argv, quoting args with spaces.
fn build_cmdline(args: &[String]) -> String {
    args.iter()
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

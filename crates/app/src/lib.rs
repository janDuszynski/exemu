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
use exemu_cpu::{Interpreter, GS_BASE};
use exemu_loader as loader;
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// ---- Address-space layout policy -------------------------------------------

const PAGE: u64 = 0x1000;
const STACK_BASE: u64 = 0x0000_0010_0000_0000;
const STACK_SIZE: u64 = 0x0020_0000; // 2 MiB
const TEB_SIZE: u64 = 0x1000;
const PEB_ADDR: u64 = GS_BASE + 0x2000;
const ENV_BASE: u64 = 0x0000_0000_5000_0000;
const ENV_SIZE: u64 = 0x1000;
const API_BASE: u64 = 0x0000_7EFF_0000_0000;
const HEAP_BASE: u64 = 0x0000_0002_0000_0000;
const HEAP_SIZE: u64 = 0x0400_0000; // 64 MiB

// TEB field offsets (x64).
const TEB_SELF: u64 = 0x30; // NtTib.Self
const TEB_PEB: u64 = 0x60; // ProcessEnvironmentBlock
const TEB_STACK_BASE: u64 = 0x08;
const TEB_STACK_LIMIT: u64 = 0x10;
// PEB field offsets (x64).
const PEB_IMAGE_BASE: u64 = 0x10;

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

        // --- Stack --------------------------------------------------------
        mem.map(Region::new("stack", STACK_BASE, STACK_SIZE, Perm::RW))?;

        // --- Heap arena (bump-allocated by the OS layer) ------------------
        mem.map(Region::new("heap", HEAP_BASE, HEAP_SIZE, Perm::RW))?;

        // --- TEB / PEB behind gs: -----------------------------------------
        mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW))?;
        mem.map(Region::new("peb", align_down(PEB_ADDR, PAGE), PAGE, Perm::RW))?;
        let stack_top = STACK_BASE + STACK_SIZE;
        mem.poke(GS_BASE + TEB_SELF, &GS_BASE.to_le_bytes())?;
        mem.poke(GS_BASE + TEB_PEB, &PEB_ADDR.to_le_bytes())?;
        mem.poke(GS_BASE + TEB_STACK_BASE, &stack_top.to_le_bytes())?;
        mem.poke(GS_BASE + TEB_STACK_LIMIT, &STACK_BASE.to_le_bytes())?;
        mem.poke(PEB_ADDR + PEB_IMAGE_BASE, &base.to_le_bytes())?;

        // --- Command line (ASCII + UTF-16) in the env region --------------
        mem.map(Region::new("env", ENV_BASE, ENV_SIZE, Perm::RW))?;
        let cmdline = build_cmdline(&cfg.args);
        let cmd_a = ENV_BASE;
        let mut ascii = cmdline.clone().into_bytes();
        ascii.push(0);
        mem.poke(cmd_a, &ascii)?;
        let cmd_w = ENV_BASE + 0x400;
        let mut wide: Vec<u8> = Vec::new();
        for u in cmdline.encode_utf16() {
            wide.extend_from_slice(&u.to_le_bytes());
        }
        wide.extend_from_slice(&[0, 0]);
        mem.poke(cmd_w, &wide)?;

        // --- The OS layer and import resolution ---------------------------
        let mut os = WinOs::new(WinConfig {
            api_base: API_BASE,
            heap_base: HEAP_BASE,
            heap_size: HEAP_SIZE,
            image_base: base,
            cmdline_ptr_a: cmd_a,
            cmdline_ptr_w: cmd_w,
            echo: cfg.echo,
            trace: cfg.trace,
        });

        for imp in &image.imports {
            let thunk = os.resolve_import(&imp.dll, &imp.symbol);
            mem.poke(base + imp.iat_rva as u64, &thunk.to_le_bytes())?;
        }

        // --- Initial CPU state --------------------------------------------
        let mut cpu = Interpreter::new();
        // 16-byte align the stack, then push the sentinel return address so
        // that at entry rsp % 16 == 8, exactly as a real `call entry` leaves it.
        let mut rsp = (stack_top - 0x100) & !0xf;
        let exit_thunk = os.exit_thunk();
        rsp -= 8;
        mem.write_u64(rsp, exit_thunk)?;
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
            match self.cpu.step(&mut self.mem, &mut self.os)? {
                Exit::Continue => steps += 1,
                Exit::ProcessExit(code) => break code,
                Exit::Halted => break 0,
                Exit::Interrupt(0x80) => {
                    return Err(EmuError::Unsupported(
                        "direct SYSCALL instruction (no syscall layer emulated)".into(),
                    ));
                }
                Exit::Interrupt(n) => {
                    return Err(EmuError::Os(format!("unhandled interrupt {n:#x} at {:#x}", self.cpu.state().rip)));
                }
            }
        };

        Ok(RunResult {
            exit_code,
            steps,
            stdout: self.os.captured_stdout().to_vec(),
            stderr: self.os.captured_stderr().to_vec(),
        })
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

/// Build a Windows-style command line from argv, quoting args with spaces.
fn build_cmdline(args: &[String]) -> String {
    args.iter()
        .map(|a| if a.contains(' ') { format!("\"{a}\"") } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

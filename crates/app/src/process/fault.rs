use exemu_core::debug::StopReason;
use exemu_core::{Cpu, EmuError, Memory};

use crate::memory_map;

use super::Process;

const NULL_GUARD: u64 = 0x1_0000;

impl Process {
    pub(super) fn fault_debugged(
        &mut self,
        debugging: bool,
        err: EmuError,
        steps: u64,
        recent: &[u64],
    ) -> EmuError {
        let err = self.fault(err, steps, recent);
        if debugging {
            if let EmuError::Fault { report, .. } = &err {
                let report = report.clone();
                self.debug_stop(StopReason::Faulted { report }, steps, recent);
            }
        }
        err
    }

    pub(super) fn unhandled_fault(
        &mut self,
        debugging: bool,
        u: exemu_os::UnhandledException,
        steps: u64,
        recent: &[u64],
    ) -> EmuError {
        let exemu_os::UnhandledException { code, address, how } = u;
        let e = EmuError::Os(format!(
            "unhandled guest exception {code:#010x} at {} — {how}",
            self.addr_note(address)
        ));
        self.fault_debugged(debugging, e, steps, recent)
    }

    fn fault(&self, err: EmuError, steps: u64, recent: &[u64]) -> EmuError {
        let report = self.fault_report(&err.to_string(), Some(&err), steps, recent);
        EmuError::Fault { report, cause: Box::new(err) }
    }

    pub(super) fn addr_note(&self, addr: u64) -> String {
        match self.os.module_at(addr) {
            Some((name, rva)) => format!("{addr:#x} ({name}+{rva:#x})"),
            None => format!("{addr:#x}"),
        }
    }

    pub(super) fn fault_report(&self, headline: &str, err: Option<&EmuError>, steps: u64, recent: &[u64]) -> String {
        use std::fmt::Write;
        let s = self.cpu.state();
        let mut o = String::new();
        let _ = writeln!(o, "{headline}");

        if let Some(EmuError::Unmapped { addr, .. }) = &err {
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

        let null_deref = s.rip < NULL_GUARD
            || matches!(
                err,
                Some(EmuError::Unmapped { addr, .. } | EmuError::Permission { addr, .. }) if *addr < NULL_GUARD
            );
        if null_deref {
            let suspects = self.os.zero_returning_stubs();
            let _ = writeln!(
                o,
                "  note: this is a NULL dereference (address below {NULL_GUARD:#x} — a null pointer\n\
                 \x20       plus at most a struct-field offset), which in exemu almost always means\n\
                 \x20       an unimplemented API returned 0 and the guest kept it as a pointer."
            );
            if suspects.is_empty() {
                let _ = writeln!(
                    o,
                    "  note: no unimplemented Win32 stub has returned 0 in this run, so the NULL\n\
                     \x20       came from somewhere else — guest logic, or a *implemented* API\n\
                     \x20       returning the wrong thing."
                );
            } else {
                let _ = writeln!(
                    o,
                    "  suspects (unimplemented stubs that returned 0, most recent first): {}",
                    suspects.join(", ")
                );
            }
        }

        if let Some(EmuError::Unmapped { addr, .. } | EmuError::Permission { addr, .. }) = err {
            let _ = writeln!(o, "  faulting address {addr:#x}: {}", memory_map::locate(self.mem.regions(), *addr));
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
        if self.os.module_at(s.rip).is_some() {
            let _ = writeln!(o, "  rip is {}", self.addr_note(s.rip));
        }
        for row in s.gpr.chunks(4).enumerate() {
            let (r, regs) = row;
            let _ = write!(o, "  ");
            for (i, v) in regs.iter().enumerate() {
                let name = exemu_core::Reg::NAMES[r * 4 + i];
                let _ = write!(o, "{name:>3}={v:#018x}  ");
            }
            o.push('\n');
        }
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
        if !recent.is_empty() {
            let _ = write!(o, "\n  recent rip trail (oldest→newest):");
            for r in recent {
                let _ = write!(o, " {r:#x}");
            }
            if recent.iter().any(|r| self.os.module_at(*r).is_some()) {
                let _ = write!(o, "\n  recent rip trail (named):");
                for r in recent {
                    let _ = write!(o, " {}", self.os.describe_addr(*r));
                }
            }
        }
        let function_table = self.os.unwind_table();
        if !function_table.is_empty() {
            let frames = exemu_core::unwind::backtrace(
                function_table,
                self.image_base,
                s,
                &self.mem,
                24,
            );
            if !frames.is_empty() {
                let _ = write!(o, "\n  call stack (virtual unwind, innermost first): {}", self.addr_note(s.rip));
                for f in &frames {
                    let _ = write!(o, " ← {}", self.addr_note(*f));
                }
            }
        }
        if std::env::var_os("EXEMU_DBG").is_some() {
            let _ = write!(o, "\n{}", memory_map::dump(self.mem.regions()));
        }
        let modules = self.os.loaded_modules();
        if !modules.is_empty() {
            let _ = write!(o, "\n  loaded modules:");
            for (name, base, size) in &modules {
                let _ = write!(o, " {name}@{base:#x}+{size:#x}");
            }
        }
        o.push('\n');
        o
    }
}

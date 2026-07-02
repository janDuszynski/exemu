//! The Windows API surface exemu understands, and its native implementations.
//!
//! [`Api`] enumerates the recognized symbols; [`Api::classify`] maps a
//! `(dll, name)` pair to one. [`WinOs::dispatch`] runs the call using the
//! arguments already in guest registers/stack and returns an [`Outcome`]
//! (a return value, or process termination).

use exemu_core::{CpuState, Memory, Result};

use crate::{WinOs, HANDLE_PROCESS_HEAP, HANDLE_STDERR, HANDLE_STDIN, HANDLE_STDOUT};

/// The result of servicing an API call.
pub(crate) enum Outcome {
    /// Put this value in `rax` and `ret` to the caller.
    Return(u64),
    /// Terminate the process with this exit code.
    Exit(i32),
}

/// Every Windows symbol the emulator implements natively. Anything else
/// becomes [`Api::Unsupported`] and returns 0.
#[derive(Debug, Clone)]
pub enum Api {
    GetStdHandle,
    WriteFile,
    WriteConsoleA,
    WriteConsoleW,
    ExitProcess,
    TerminateProcess,
    GetCommandLineA,
    GetCommandLineW,
    GetModuleHandleA,
    GetModuleHandleW,
    GetProcessHeap,
    HeapAlloc,
    HeapFree,
    HeapReAlloc,
    VirtualAlloc,
    VirtualFree,
    GetLastError,
    SetLastError,
    GetCurrentProcessId,
    GetCurrentThreadId,
    GetCurrentProcess,
    IsDebuggerPresent,
    Sleep,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    GetSystemTimeAsFileTime,
    GetTickCount,
    GetACP,
    SetConsoleCP,
    SetConsoleOutputCP,
    GetConsoleMode,
    SetConsoleMode,
    GetStartupInfoA,
    GetStartupInfoW,
    GetEnvironmentStringsW,
    FreeEnvironmentStringsW,
    LoadLibraryA,
    FreeLibrary,
    GetProcAddress,
    /// A recognized-by-shape but unimplemented import (`dll!name`).
    Unsupported(String),
}

impl Api {
    pub fn classify(dll: &str, name: &str) -> Api {
        match name {
            "GetStdHandle" => Api::GetStdHandle,
            "WriteFile" => Api::WriteFile,
            "WriteConsoleA" => Api::WriteConsoleA,
            "WriteConsoleW" => Api::WriteConsoleW,
            "ExitProcess" => Api::ExitProcess,
            "TerminateProcess" => Api::TerminateProcess,
            "GetCommandLineA" => Api::GetCommandLineA,
            "GetCommandLineW" => Api::GetCommandLineW,
            "GetModuleHandleA" => Api::GetModuleHandleA,
            "GetModuleHandleW" => Api::GetModuleHandleW,
            "GetProcessHeap" => Api::GetProcessHeap,
            "HeapAlloc" => Api::HeapAlloc,
            "HeapFree" => Api::HeapFree,
            "HeapReAlloc" => Api::HeapReAlloc,
            "VirtualAlloc" => Api::VirtualAlloc,
            "VirtualFree" => Api::VirtualFree,
            "GetLastError" => Api::GetLastError,
            "SetLastError" => Api::SetLastError,
            "GetCurrentProcessId" => Api::GetCurrentProcessId,
            "GetCurrentThreadId" => Api::GetCurrentThreadId,
            "GetCurrentProcess" => Api::GetCurrentProcess,
            "IsDebuggerPresent" => Api::IsDebuggerPresent,
            "Sleep" => Api::Sleep,
            "QueryPerformanceCounter" => Api::QueryPerformanceCounter,
            "QueryPerformanceFrequency" => Api::QueryPerformanceFrequency,
            "GetSystemTimeAsFileTime" => Api::GetSystemTimeAsFileTime,
            "GetTickCount" | "GetTickCount64" => Api::GetTickCount,
            "GetACP" => Api::GetACP,
            "SetConsoleCP" => Api::SetConsoleCP,
            "SetConsoleOutputCP" => Api::SetConsoleOutputCP,
            "GetConsoleMode" => Api::GetConsoleMode,
            "SetConsoleMode" => Api::SetConsoleMode,
            "GetStartupInfoA" => Api::GetStartupInfoA,
            "GetStartupInfoW" => Api::GetStartupInfoW,
            "GetEnvironmentStringsW" => Api::GetEnvironmentStringsW,
            "FreeEnvironmentStringsW" => Api::FreeEnvironmentStringsW,
            "LoadLibraryA" => Api::LoadLibraryA,
            "FreeLibrary" => Api::FreeLibrary,
            "GetProcAddress" => Api::GetProcAddress,
            _ => Api::Unsupported(format!("{dll}!{name}")),
        }
    }
}

/// Windows TRUE / FALSE as BOOL return values.
const TRUE: u64 = 1;
const FALSE: u64 = 0;

impl WinOs {
    pub(crate) fn dispatch(
        &mut self,
        api: &Api,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<Outcome> {
        let ret = |v: u64| Ok(Outcome::Return(v));
        match api {
            Api::ExitProcess => {
                let code = self.arg(cpu, mem, 0)? as u32 as i32;
                Ok(Outcome::Exit(code))
            }
            Api::TerminateProcess => {
                let code = self.arg(cpu, mem, 1)? as u32 as i32;
                Ok(Outcome::Exit(code))
            }

            Api::GetStdHandle => {
                let which = self.arg(cpu, mem, 0)? as u32 as i32;
                ret(match which {
                    -10 => HANDLE_STDIN,
                    -11 => HANDLE_STDOUT,
                    -12 => HANDLE_STDERR,
                    _ => 0,
                })
            }

            Api::WriteFile => {
                // WriteFile(hFile, lpBuffer, nBytes, lpWritten, lpOverlapped)
                let handle = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let written_ptr = self.arg(cpu, mem, 3)?;
                self.write_stream(handle, buf, n, mem)?;
                if written_ptr != 0 {
                    mem.write_u32(written_ptr, n as u32)?;
                }
                ret(TRUE)
            }
            Api::WriteConsoleA => {
                // WriteConsoleA(hConsole, lpBuffer, nChars, lpWritten, lpReserved)
                let handle = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let written_ptr = self.arg(cpu, mem, 3)?;
                self.write_stream(handle, buf, n, mem)?;
                if written_ptr != 0 {
                    mem.write_u32(written_ptr, n as u32)?;
                }
                ret(TRUE)
            }
            Api::WriteConsoleW => {
                let handle = self.arg(cpu, mem, 0)?;
                let buf = self.arg(cpu, mem, 1)?;
                let n = self.arg(cpu, mem, 2)? as usize;
                let written_ptr = self.arg(cpu, mem, 3)?;
                let mut units = Vec::with_capacity(n);
                for i in 0..n {
                    units.push(mem.read_u16(buf + (i as u64) * 2)?);
                }
                let text = String::from_utf16_lossy(&units);
                let is_err = handle == HANDLE_STDERR;
                self.emit(is_err, text.as_bytes());
                if written_ptr != 0 {
                    mem.write_u32(written_ptr, n as u32)?;
                }
                ret(TRUE)
            }

            Api::GetCommandLineA => ret(self.cfg.cmdline_ptr_a),
            Api::GetCommandLineW => ret(self.cfg.cmdline_ptr_w),

            Api::GetModuleHandleA | Api::GetModuleHandleW => {
                // Only the "this module" (NULL name) case is supported.
                ret(self.cfg.image_base)
            }

            Api::GetProcessHeap => ret(HANDLE_PROCESS_HEAP),
            Api::HeapAlloc => {
                // HeapAlloc(hHeap, dwFlags, dwBytes)
                let size = self.arg(cpu, mem, 2)?;
                ret(self.heap_alloc(size))
            }
            Api::HeapReAlloc => {
                // HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes)
                let old = self.arg(cpu, mem, 2)?;
                let size = self.arg(cpu, mem, 3)?;
                let new = self.heap_alloc(size);
                if new != 0 && old != 0 {
                    // Best-effort copy; we do not track the old size.
                    for i in 0..size {
                        let b = mem.read_u8(old + i)?;
                        mem.write_u8(new + i, b)?;
                    }
                }
                ret(new)
            }
            Api::HeapFree => ret(TRUE),

            Api::VirtualAlloc => {
                // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
                let size = self.arg(cpu, mem, 1)?;
                ret(self.heap_alloc(size))
            }
            Api::VirtualFree => ret(TRUE),

            Api::GetLastError => ret(self.last_error as u64),
            Api::SetLastError => {
                self.last_error = self.arg(cpu, mem, 0)? as u32;
                Ok(Outcome::Return(0))
            }

            Api::GetCurrentProcessId => ret(0x1000),
            Api::GetCurrentThreadId => ret(0x1001),
            Api::GetCurrentProcess => ret(u64::MAX), // pseudo-handle (HANDLE)-1
            Api::IsDebuggerPresent => ret(FALSE),
            Api::Sleep => Ok(Outcome::Return(0)),

            Api::QueryPerformanceCounter => {
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    mem.write_u64(ptr, 0)?;
                }
                ret(TRUE)
            }
            Api::QueryPerformanceFrequency => {
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    mem.write_u64(ptr, 1_000_000)?;
                }
                ret(TRUE)
            }
            Api::GetSystemTimeAsFileTime => {
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    mem.write_u64(ptr, 0)?;
                }
                Ok(Outcome::Return(0))
            }
            Api::GetTickCount => ret(0),
            Api::GetACP => ret(65001), // UTF-8 code page

            Api::SetConsoleCP | Api::SetConsoleOutputCP => ret(TRUE),
            Api::GetConsoleMode => {
                // GetConsoleMode(hConsole, lpMode): report a plausible mode.
                let ptr = self.arg(cpu, mem, 1)?;
                if ptr != 0 {
                    mem.write_u32(ptr, 0x0003)?; // ENABLE_PROCESSED_OUTPUT | WRAP
                }
                ret(TRUE)
            }
            Api::SetConsoleMode => ret(TRUE),

            Api::GetStartupInfoA | Api::GetStartupInfoW => {
                // Zero-fill a STARTUPINFO and set its cb field.
                let ptr = self.arg(cpu, mem, 0)?;
                if ptr != 0 {
                    for i in 0..104u64 {
                        mem.write_u8(ptr + i, 0)?;
                    }
                    mem.write_u32(ptr, 104)?; // cb
                }
                Ok(Outcome::Return(0))
            }
            Api::GetEnvironmentStringsW => {
                // Return an empty environment block (double NUL).
                let ptr = self.heap_alloc(8);
                ret(ptr)
            }
            Api::FreeEnvironmentStringsW => ret(TRUE),

            Api::LoadLibraryA => ret(0), // pretend the DLL could not be loaded
            Api::FreeLibrary => ret(TRUE),
            Api::GetProcAddress => ret(0),

            Api::Unsupported(name) => {
                if self.cfg.trace {
                    eprintln!("[exemu] unimplemented API {name} -> returning 0");
                }
                ret(0)
            }
        }
    }

    /// Route a byte buffer to the appropriate host stream based on the
    /// Windows handle value.
    fn write_stream(&mut self, handle: u64, buf: u64, n: usize, mem: &dyn Memory) -> Result<()> {
        let mut bytes = vec![0u8; n];
        mem.read(buf, &mut bytes)?;
        let is_err = handle == HANDLE_STDERR;
        self.emit(is_err, &bytes);
        Ok(())
    }
}

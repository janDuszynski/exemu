//! Child process creation — `NtCreateUserProcess` and the process object
//! (roadmap W3.5).
//!
//! # The path Wine's `CreateProcessW` actually takes
//!
//! Recovered from the pinned guest `kernelbase.dll` (clean-room-permitted
//! disassembly of `CreateProcessInternalW` @ RVA 0x15f30 and its helper
//! `create_nt_process` @ RVA 0x75f60 — no Wine `.c` was read):
//!
//! 1. `CreateProcessInternalW` resolves the image, builds the command line, and
//!    calls **`RtlCreateProcessParametersEx`** — *guest ntdll code* — which
//!    allocates a complete `RTL_USER_PROCESS_PARAMETERS` **in the parent's own
//!    heap**;
//! 2. it then fills that block's console fields itself: with
//!    `STARTF_USESTDHANDLES` (bit 0x100 of `STARTUPINFOW.dwFlags` @ +0x3c) it
//!    copies `hStdInput/hStdOutput/hStdError` from `STARTUPINFOW` @ +0x50/+0x58/
//!    +0x60 into the params at **+0x20/+0x28/+0x30**; otherwise it copies the
//!    *parent's* `PEB->ProcessParameters` +0x20/+0x28/+0x30 — the very offsets
//!    W3.6 verified and [`crate::dll`] already writes;
//! 3. `create_nt_process` builds a `PS_ATTRIBUTE_LIST` and calls
//!    **`NtCreateUserProcess`** (SSDT index **0x89**, read from ntdll's own
//!    `mov r10,rcx; mov eax,0x89` stub) with `ThreadFlags = 1`
//!    (`THREAD_CREATE_FLAGS_CREATE_SUSPENDED`) *always*;
//! 4. back in `CreateProcessInternalW`, if the caller did **not** pass
//!    `CREATE_SUSPENDED` it calls `NtResumeThread(hThread, NULL)`;
//! 5. `PROCESS_INFORMATION.dwProcessId/dwThreadId` come from the **output**
//!    `PsAttributeClientId` attribute, not from the return value;
//! 6. `RtlDestroyProcessParameters` frees the params block.
//!
//! Two consequences shape everything below. First, **exemu never builds the
//! child's `RTL_USER_PROCESS_PARAMETERS`** — Wine's ntdll does, as guest code;
//! exemu only *reads* it, at the offsets W3.6 recovered. Second, the block is
//! freed the moment the syscall returns, so every field is **snapshotted** into
//! a [`ChildProcessRequest`] at create time.
//!
//! # What a child process is in exemu, and why
//!
//! A child is **a second, complete emulator instance — its own address space,
//! its own [`WinOs`], its own interpreter — run synchronously to completion at
//! the moment its initial thread is resumed.** The alternatives were weighed
//! against the object model that exists today:
//!
//! * *A concurrently scheduled second guest process.* The natural end state, but
//!   it is not one step: the cooperative scheduler multiplexes one `CpuState`
//!   over threads that all share **one** `&mut dyn Memory` chosen by the run
//!   loop, and the object manager (`kobjects`, the wineserver equivalent) is a
//!   plain field of `WinOs`. Two address spaces means the run loop selecting a
//!   memory *and* an OS per switch, and hoisting the object manager into a
//!   kernel shared between them so a parent can wait on a child's handle at all.
//!   Landing half of that would produce a process model that looks concurrent
//!   and is not.
//! * *Re-invoking the emulator as a host process.* Cheap, and wrong: the guest's
//!   handle would name a host pid, the sandbox and the object namespace would
//!   fork, and a deterministic replay would stop being possible.
//!
//! So the child runs synchronously — but the *seam* is the real one.
//! `NtCreateUserProcess` **prepares** the child and mints handles; the child
//! runs when `NtResumeThread` names its initial thread. That is exactly where a
//! future scheduler would start it instead, and it makes the two shapes the
//! guest can ask for behave correctly today:
//!
//! | the guest asks for | what happens |
//! | --- | --- |
//! | `CreateProcessW(...)` (no `CREATE_SUSPENDED`) | kernelbase resumes at once → the child runs inside `CreateProcessW` |
//! | `CreateProcessW(..., CREATE_SUSPENDED, ...)` | nothing runs; the child starts at the guest's own `ResumeThread` |
//!
//! **The handle semantics the guest sees are the real ones**: a process handle
//! and a thread handle from the same monotonic space `CloseHandle` routes;
//! `NtWaitForSingleObject` on either succeeds once the child has exited (and
//! does *not* before); `NtQueryInformationProcess(ProcessBasicInformation)`
//! reports `STILL_ACTIVE` until then and the child's real exit code after, which
//! is what `GetExitCodeProcess` returns.
//!
//! **The honest gap**, pinned by tests rather than papered over: because the run
//! is synchronous, a parent and child can never be alive at the same time. Any
//! pattern that needs both — a pipe handshake, a child that signals an event the
//! parent waits on — cannot work, and no code here pretends otherwise.
//!
//! # What is refused
//!
//! Every out-of-scope request returns a real NTSTATUS, never a handle to a
//! process that will not exist: a non-NULL debug port, a job list, a token
//! (`CreateProcessAsUser`), a parent other than the caller, a non-native machine
//! type, and std handles that are not the console sentinels the child's own
//! console bridge understands.

use exemu_core::{
    ChildProcessOutcome, ChildProcessRequest, CpuState, Memory, ProcessSpawner, Result, SpawnError,
};

use crate::sync::KObject;
use crate::WinOs;

// ---- NTSTATUS (public ntstatus.h) ----------------------------------------

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_00E4;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// `STILL_ACTIVE` / `STATUS_PENDING` — the exit code of a process that has not
/// exited (public winbase.h).
pub const STILL_ACTIVE: u32 = 259;

/// `NtCurrentProcess` pseudo-handle, `(HANDLE)-1`.
const NT_CURRENT_PROCESS: u64 = u64::MAX;

// ---- SSDT indices, recovered from the pinned guest ntdll stubs ------------

/// `NtCreateUserProcess` — `mov r10,rcx; mov eax,0x89; syscall` at ntdll RVA
/// 0xfa50 of the pinned `x86_64-windows/ntdll.dll`.
pub const SSDT_NT_CREATE_USER_PROCESS: u32 = 0x89;
/// `NtQueryInformationProcess` — ntdll RVA 0xec50, `mov eax,0x19`. Needed
/// because kernelbase's `GetExitCodeProcess` is *only* this call: it asks for
/// `ProcessBasicInformation` into a 0x30-byte buffer and returns the first
/// dword (`ExitStatus`).
pub const SSDT_NT_QUERY_INFORMATION_PROCESS: u32 = 0x19;

// ---- NtCreateUserProcess flag bits, recovered from kernelbase -------------
//
// `CreateProcessInternalW` composes the `ProcessFlags` argument from its own
// `dwCreationFlags`:
//   `esi = (bInheritHandles != 0) << 2`                         → bit 2
//   `if (flags & CREATE_BREAKAWAY_FROM_JOB) esi |= 1`           → bit 0
//   `if (flags & CREATE_SUSPENDED)          esi |= 0x200`       → bit 9
// (the `shll $0x2` / `orl $0x1` / `orb $0x2,%ah` sequence at RVA 0x1649b–0x164f4).

/// `PROCESS_CREATE_FLAGS_INHERIT_HANDLES` — set from `bInheritHandles`.
pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u64 = 0x0000_0004;
/// The bit kernelbase sets when the caller passed `CREATE_SUSPENDED`. Recorded
/// (and asserted by the ABI test) because it is the guest's own statement of
/// intent; the run-on-resume model does not need to consult it, since a
/// suspended create is simply one that never reaches `NtResumeThread`.
pub const PROCESS_CREATE_FLAGS_SUSPENDED: u64 = 0x0000_0200;

/// `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` — kernelbase passes this **always**.
pub const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u64 = 0x0000_0001;

// ---- PS_ATTRIBUTE_LIST -----------------------------------------------------

/// `PS_ATTRIBUTE_LIST` / `PS_ATTRIBUTE` layout, recovered from
/// `create_nt_process`: the list pointer is `rsp+0x140` and its `TotalLength` is
/// written as `8 + count*32` (`shlq $0x5` then `addq $0x8`); each entry's fields
/// are stored at `+0x148`, `+0x150`, `+0x158`, `+0x160` relative to `rsp` — i.e.
/// `Attribute` +0x00, `Size` +0x08, `Value` +0x10, `ReturnLength` +0x18 relative
/// to an entry that begins 8 bytes into the list.
pub mod ps_attr {
    /// `SIZE_T TotalLength` — the whole list including this field.
    pub const TOTAL_LENGTH: u64 = 0x00;
    /// Offset of `Attributes[0]`.
    pub const FIRST: u64 = 0x08;
    /// `sizeof(PS_ATTRIBUTE)`.
    pub const ENTRY_SIZE: u64 = 0x20;

    pub const ATTRIBUTE: u64 = 0x00;
    pub const SIZE: u64 = 0x08;
    pub const VALUE: u64 = 0x10;
    pub const RETURN_LENGTH: u64 = 0x18;

    /// `PsAttributeValue(Number, Thread, Input, Additive)` packing.
    pub const NUMBER_MASK: u64 = 0xFFFF;
    pub const THREAD: u64 = 0x0001_0000;
    pub const INPUT: u64 = 0x0002_0000;
    pub const ADDITIVE: u64 = 0x0004_0000;

    // The attribute numbers kernelbase emits, with the exact packed values it
    // stores (see the ABI test, which re-reads them out of `.rdata`).
    /// `PsAttributeParentProcess`, emitted as `0x60000` (Input|Additive).
    pub const PARENT_PROCESS: u64 = 0;
    /// `PsAttributeDebugPort`, emitted as `0x60001`.
    pub const DEBUG_PORT: u64 = 1;
    /// `PsAttributeToken`, emitted as `0x60002`.
    pub const TOKEN: u64 = 2;
    /// `PsAttributeClientId`, emitted as `0x10003` (Thread, **output**, size 0x10).
    pub const CLIENT_ID: u64 = 3;
    /// `PsAttributeImageName`, emitted as `0x20005` (Input) — Size is the NT
    /// path's byte length, Value its buffer.
    pub const IMAGE_NAME: u64 = 5;
    /// `PsAttributeImageInfo`, emitted as `0x6` (**output**, size 0x40 =
    /// `SECTION_IMAGE_INFORMATION`).
    pub const IMAGE_INFO: u64 = 6;
    /// `PsAttributeHandleList`, emitted as `0x2000b` — only when
    /// `bInheritHandles` **and** an explicit `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
    /// was supplied.
    pub const HANDLE_LIST: u64 = 11;
    /// `PsAttributeJobList`, emitted as `0x20013`.
    pub const JOB_LIST: u64 = 19;
    /// `PsAttributeMachineType`, emitted as `0x6001c` (size 2).
    pub const MACHINE_TYPE: u64 = 28;

    /// Upper bound on the attribute count exemu will walk, so a corrupt
    /// `TotalLength` cannot drive an unbounded loop. kernelbase emits at most 9.
    pub const MAX_ENTRIES: u64 = 32;
}

/// `IMAGE_FILE_MACHINE_AMD64` — the only machine exemu hosts a child for today.
const IMAGE_FILE_MACHINE_AMD64: u64 = 0x8664;

// ---- RTL_USER_PROCESS_PARAMETERS (the fields this step reads) -------------

/// The `RTL_USER_PROCESS_PARAMETERS` offsets this module reads out of the block
/// Wine's `RtlCreateProcessParametersEx` built for the child.
///
/// These are **not re-derived here**: they are the offsets W3.6 recovered from
/// the pinned ntdll and that [`crate::dll::WinOs::build_process_parameters`]
/// already writes for the initial process. `params_reader_matches_the_w36_writer`
/// in this module's tests proves the two agree by round-tripping a real block
/// through both, and `process_abi` re-derives the std-handle trio from
/// kernelbase's own stores.
pub mod pp {
    /// `HANDLE ConsoleHandle`.
    pub const CONSOLE_HANDLE: u64 = 0x10;
    /// `HANDLE StandardInput` / `StandardOutput` / `StandardError`.
    pub const STD_INPUT: u64 = 0x20;
    pub const STD_OUTPUT: u64 = 0x28;
    pub const STD_ERROR: u64 = 0x30;
    /// `CURDIR CurrentDirectory` — its `DosPath` UNICODE_STRING starts here.
    pub const CURRENT_DIRECTORY: u64 = 0x38;
    /// `UNICODE_STRING ImagePathName`.
    pub const IMAGE_PATH_NAME: u64 = 0x60;
    /// `UNICODE_STRING CommandLine`.
    pub const COMMAND_LINE: u64 = 0x70;
    /// `PVOID Environment`.
    pub const ENVIRONMENT: u64 = 0x80;
    /// `SIZE_T EnvironmentSize`.
    pub const ENVIRONMENT_SIZE: u64 = 0x3F0;
}

/// Cap on the environment block exemu will decode out of guest memory (bytes).
/// A real block is a few kilobytes; the bound only stops a corrupt
/// `EnvironmentSize` from driving an unbounded read.
const MAX_ENVIRONMENT_BYTES: u64 = 0x0010_0000;

// ---- the child process object ---------------------------------------------

/// Lifecycle of a child process, as the parent's handles report it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ChildState {
    /// Created, initial thread suspended, nothing has run.
    NotStarted,
    /// Ran to completion (or was terminated); `exit_code` is final.
    Exited,
}

/// One child process: the handle pair the guest holds, the ids it reports, and
/// the snapshot needed to actually run it.
pub(crate) struct ChildProcess {
    pub pid: u32,
    pub tid: u32,
    pub process_handle: u64,
    pub thread_handle: u64,
    pub state: ChildState,
    pub exit_code: u32,
    /// Outstanding suspends on the initial thread. Starts at 1 — kernelbase
    /// creates every child with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED` — so the
    /// child starts on the resume that drops it to zero.
    pub suspend_count: u32,
    /// The create-time snapshot; taken by the run so it happens exactly once.
    pub request: Option<ChildProcessRequest>,
}

impl WinOs {
    // ---- install point ---------------------------------------------------

    /// Install the application layer's child-process runner (roadmap W3.5).
    /// Without one, `NtCreateUserProcess` refuses with `STATUS_NOT_SUPPORTED`.
    pub fn set_process_spawner(&mut self, spawner: Box<dyn ProcessSpawner>) {
        self.spawner = spawner;
    }

    /// How deep the *current* process is in the spawn chain. The app layer sets
    /// it so a spawner can bound recursion.
    pub fn set_spawn_depth(&mut self, depth: u32) {
        self.spawn_depth = depth;
    }

    // ---- lookups ---------------------------------------------------------

    fn child_by_process_handle(&self, handle: u64) -> Option<usize> {
        self.children.iter().position(|c| c.process_handle == handle)
    }

    fn child_by_thread_handle(&self, handle: u64) -> Option<usize> {
        self.children.iter().position(|c| c.thread_handle == handle)
    }

    /// Whether `handle` names a child process or its initial thread. Used by
    /// [`WinOs::close_handle`] to prune the table when the guest lets go.
    pub(crate) fn forget_child_handle(&mut self, handle: u64) {
        if let Some(i) = self.child_by_process_handle(handle) {
            self.children[i].process_handle = 0;
        }
        if let Some(i) = self.child_by_thread_handle(handle) {
            self.children[i].thread_handle = 0;
        }
        self.children.retain(|c| c.process_handle != 0 || c.thread_handle != 0);
    }

    /// Mint the next process/thread id pair for a child. Windows hands out ids
    /// that are multiples of four and never zero; matching that keeps a guest
    /// that sanity-checks a pid happy.
    fn next_child_ids(&mut self) -> (u32, u32) {
        let pid = self.next_pid;
        self.next_pid += 4;
        let tid = self.next_pid;
        self.next_pid += 4;
        (pid, tid)
    }

    // ---- NtCreateUserProcess ---------------------------------------------

    /// `NtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess,
    /// ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes,
    /// ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList)`
    /// — eleven arguments, so args 4..10 come off the guest stack.
    ///
    /// **`CreateInfo` is deliberately never read.** `create_nt_process` passes a
    /// pointer to a stack slot it never initialises (nothing in the function
    /// writes `rsp+0xe0`, the address it hands over), so the bytes there are
    /// garbage; a `PS_CREATE_INFO` reader would be reading noise. That is only
    /// possible because Wine's own unix side ignores it too, and it is asserted
    /// in the ABI test so a future pinned build that starts filling it in is
    /// caught rather than silently mis-read.
    pub(crate) fn nt_create_user_process(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let process_handle_out = self.syscall_arg(cpu, mem, 0)?;
        let thread_handle_out = self.syscall_arg(cpu, mem, 1)?;
        let process_flags = self.syscall_arg(cpu, mem, 6)?;
        let _thread_flags = self.syscall_arg(cpu, mem, 7)?;
        let params = self.syscall_arg(cpu, mem, 8)?;
        let attribute_list = self.syscall_arg(cpu, mem, 10)?;

        if process_handle_out == 0 || thread_handle_out == 0 || params == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }

        // --- 1. walk the attribute list --------------------------------------
        let attrs = match self.read_ps_attributes(mem, attribute_list)? {
            Ok(a) => a,
            Err(status) => return Ok(status),
        };

        // --- 2. snapshot the guest-built process parameters -------------------
        let inherit_handles = process_flags & PROCESS_CREATE_FLAGS_INHERIT_HANDLES != 0;
        let std_handles = [
            mem.read_u64(params + pp::STD_INPUT)?,
            mem.read_u64(params + pp::STD_OUTPUT)?,
            mem.read_u64(params + pp::STD_ERROR)?,
        ];
        // exemu's console bridge (W3.4) recognises exactly three sentinel
        // handles, and a child is a fresh address space with a fresh handle
        // table — so a *file* or pipe handle standing in for stdout could not be
        // honoured, and silently writing to the console instead would be the
        // plausible-looking success this project refuses. A NULL or
        // INVALID_HANDLE_VALUE entry is "no stream", which is representable.
        for h in std_handles {
            if h == 0 || h == u64::MAX {
                continue;
            }
            if !self.is_std_handle(h) {
                return Ok(STATUS_NOT_SUPPORTED);
            }
        }

        let command_line = crate::fs::read_unicode_string(mem, params + pp::COMMAND_LINE)
            .unwrap_or_default();
        let image_from_params =
            crate::fs::read_unicode_string(mem, params + pp::IMAGE_PATH_NAME).unwrap_or_default();
        let current_directory =
            crate::fs::read_unicode_string(mem, params + pp::CURRENT_DIRECTORY).unwrap_or_default();
        let environment = self.read_environment_block(mem, params)?;

        // The image NT path from `PsAttributeImageName` is authoritative (it is
        // what NT itself opens); the params' `ImagePathName` is the DOS-path
        // fallback for a caller that omits the attribute.
        let image_nt_path = attrs.image_name.clone().unwrap_or(image_from_params);
        if image_nt_path.is_empty() {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let image_guest_path = crate::fs::strip_nt_prefix(&image_nt_path);
        let Some(image_host_path) = self.host_path(&image_guest_path) else {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        if !image_host_path.is_file() {
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        // --- 3. mint the object pair ------------------------------------------
        let (pid, tid) = self.next_child_ids();
        let process_handle = self.alloc_khandle();
        let thread_handle = self.alloc_khandle();
        self.kobjects.insert(process_handle, KObject::Process { exited: false });
        self.kobjects.insert(thread_handle, KObject::Thread { exited: false });

        self.children_created += 1;
        self.children.push(ChildProcess {
            pid,
            tid,
            process_handle,
            thread_handle,
            state: ChildState::NotStarted,
            exit_code: STILL_ACTIVE,
            // kernelbase always creates suspended and resumes afterwards, so the
            // initial count is one regardless of `ThreadFlags`.
            suspend_count: 1,
            request: Some(ChildProcessRequest {
                image_guest_path,
                image_host_path,
                command_line,
                current_directory,
                environment,
                inherit_handles,
                depth: self.spawn_depth.saturating_add(1),
            }),
        });

        // --- 4. hand back the handles and the output attributes ----------------
        self.write_ptr(mem, process_handle_out, process_handle)?;
        self.write_ptr(mem, thread_handle_out, thread_handle)?;
        if let Some(client_id) = attrs.client_id_out {
            // CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; }
            mem.write_u64(client_id, pid as u64)?;
            mem.write_u64(client_id + 8, tid as u64)?;
        }
        if let Some((ptr, len)) = attrs.image_info_out {
            // SECTION_IMAGE_INFORMATION: left zeroed. kernelbase zeroes the whole
            // RTL_USER_PROCESS_INFORMATION before the call and never reads this
            // member back on the CreateProcess path, so zero is its own answer
            // rather than an invented one.
            for off in (0..len).step_by(8) {
                mem.write_u64(ptr + off, 0)?;
            }
        }
        for (ptr, value) in attrs.return_lengths {
            mem.write_u64(ptr, value)?;
        }
        Ok(STATUS_SUCCESS)
    }

    /// Decode the child's environment block (`Environment` + `EnvironmentSize`)
    /// into ordered `name=value` pairs. A malformed or absent block yields an
    /// empty vector, which the spawner reads as "use the default environment".
    fn read_environment_block(
        &self,
        mem: &dyn Memory,
        params: u64,
    ) -> Result<Vec<(String, String)>> {
        let base = mem.read_u64(params + pp::ENVIRONMENT)?;
        let size = mem.read_u64(params + pp::ENVIRONMENT_SIZE)?;
        if base == 0 || !(4..=MAX_ENVIRONMENT_BYTES).contains(&size) {
            return Ok(Vec::new());
        }
        let mut units = Vec::with_capacity((size / 2) as usize);
        for i in 0..size / 2 {
            units.push(mem.read_u16(base + i * 2)?);
        }
        let mut out = Vec::new();
        let mut cur: Vec<u16> = Vec::new();
        for u in units {
            if u == 0 {
                if cur.is_empty() {
                    break; // the double NUL terminator
                }
                let s = String::from_utf16_lossy(&cur);
                // Split at the first '=' **after** position 0: Windows keeps
                // per-drive current directories as `=C:=C:\dir` entries, whose
                // leading '=' is part of the name, and splitting on it would
                // produce an empty name for a real variable.
                if let Some(rel) = s.get(1..).and_then(|rest| rest.find('=')) {
                    let eq = rel + 1; // index of the separating '=' in `s`
                    out.push((s[..eq].to_string(), s[eq + 1..].to_string()));
                }
                cur.clear();
            } else {
                cur.push(u);
            }
        }
        Ok(out)
    }

    // ---- PS_ATTRIBUTE_LIST ----------------------------------------------

    /// Walk a `PS_ATTRIBUTE_LIST`, returning what exemu honours — or the
    /// NTSTATUS that refuses a request it cannot serve.
    fn read_ps_attributes(
        &self,
        mem: &dyn Memory,
        list: u64,
    ) -> Result<std::result::Result<PsAttributes, u32>> {
        let mut out = PsAttributes::default();
        if list == 0 {
            return Ok(Ok(out));
        }
        let total = mem.read_u64(list + ps_attr::TOTAL_LENGTH)?;
        if total < ps_attr::FIRST {
            return Ok(Err(STATUS_INVALID_PARAMETER));
        }
        let count = ((total - ps_attr::FIRST) / ps_attr::ENTRY_SIZE).min(ps_attr::MAX_ENTRIES);
        for i in 0..count {
            let e = list + ps_attr::FIRST + i * ps_attr::ENTRY_SIZE;
            let packed = mem.read_u64(e + ps_attr::ATTRIBUTE)?;
            let size = mem.read_u64(e + ps_attr::SIZE)?;
            let value = mem.read_u64(e + ps_attr::VALUE)?;
            let return_length = mem.read_u64(e + ps_attr::RETURN_LENGTH)?;
            let number = packed & ps_attr::NUMBER_MASK;
            match number {
                ps_attr::IMAGE_NAME => {
                    if value != 0 && (2..=0x1000).contains(&size) {
                        let mut units = Vec::with_capacity((size / 2) as usize);
                        for k in 0..size / 2 {
                            units.push(mem.read_u16(value + k * 2)?);
                        }
                        out.image_name = Some(String::from_utf16_lossy(&units));
                    }
                }
                ps_attr::CLIENT_ID => {
                    if value != 0 && size >= 16 {
                        out.client_id_out = Some(value);
                        if return_length != 0 {
                            out.return_lengths.push((return_length, 16));
                        }
                    }
                }
                ps_attr::IMAGE_INFO => {
                    if value != 0 && (8..=0x200).contains(&size) {
                        out.image_info_out = Some((value, size & !7));
                        if return_length != 0 {
                            out.return_lengths.push((return_length, size));
                        }
                    }
                }
                ps_attr::HANDLE_LIST => {
                    // An explicit PROC_THREAD_ATTRIBUTE_HANDLE_LIST names handles
                    // in the *parent's* table. A child is a fresh address space
                    // with a fresh table, so the values would name nothing there;
                    // exemu inherits only the console sentinels (checked at the
                    // params, above) and refuses to pretend about the rest.
                    if value != 0 && size != 0 {
                        return Ok(Err(STATUS_NOT_SUPPORTED));
                    }
                }
                ps_attr::DEBUG_PORT => {
                    if value != 0 {
                        return Ok(Err(STATUS_NOT_SUPPORTED)); // no debug objects
                    }
                }
                ps_attr::JOB_LIST => {
                    if value != 0 && size != 0 {
                        return Ok(Err(STATUS_NOT_SUPPORTED)); // no job objects
                    }
                }
                ps_attr::TOKEN => {
                    if value != 0 {
                        return Ok(Err(STATUS_NOT_SUPPORTED)); // no CreateProcessAsUser
                    }
                }
                ps_attr::PARENT_PROCESS => {
                    // Only "the caller" is a parent exemu can express.
                    if value != 0 && value != NT_CURRENT_PROCESS {
                        return Ok(Err(STATUS_NOT_SUPPORTED));
                    }
                }
                ps_attr::MACHINE_TYPE if value != 0 && value != IMAGE_FILE_MACHINE_AMD64 => {
                    return Ok(Err(STATUS_INVALID_IMAGE_FORMAT));
                }
                // Any other attribute is unknown to this implementation rather
                // than a feature it is declining: it is skipped, and the ABI test
                // pins the set the pinned kernelbase actually emits so a new one
                // shows up as a failing assertion instead of a silent skip.
                _ => {}
            }
        }
        Ok(Ok(out))
    }

    // ---- running a child --------------------------------------------------

    /// Drop one suspend from child `i`'s initial thread and, when the count
    /// reaches zero, run the child to completion. Returns the previous suspend
    /// count (what `NtResumeThread` reports).
    pub(crate) fn resume_child(&mut self, i: usize) -> u32 {
        let prev = self.children[i].suspend_count;
        if prev > 0 {
            self.children[i].suspend_count -= 1;
        }
        if self.children[i].suspend_count == 0 && self.children[i].state == ChildState::NotStarted {
            self.run_child(i);
        }
        prev
    }

    /// Run child `i` synchronously through the installed spawner and publish its
    /// result on both of its objects.
    fn run_child(&mut self, i: usize) {
        let Some(req) = self.children[i].request.take() else {
            return;
        };
        let outcome = self.spawner.spawn(&req);
        let exit_code = match outcome {
            Ok(ChildProcessOutcome { exit_code, stdout, stderr, .. }) => {
                // exemu hosts one console, and a child console app attaches to
                // it exactly as it would on Windows (no `DETACHED_PROCESS` or
                // `CREATE_NEW_CONSOLE` in this model), independently of
                // `bInheritHandles`. The child ran with echo off, so this is the
                // single point at which its output is emitted — through the
                // parent's own console policy.
                if !stdout.is_empty() {
                    self.emit_child(false, &stdout);
                }
                if !stderr.is_empty() {
                    self.emit_child(true, &stderr);
                }
                exit_code
            }
            Err(e) => {
                let note = match &e {
                    SpawnError::Unsupported => "no child-process runner is installed".to_string(),
                    SpawnError::ImageNotFound => "the child image disappeared".to_string(),
                    SpawnError::InvalidImage(m) => format!("the child image is not loadable: {m}"),
                    SpawnError::Faulted(m) => format!("exemu failed while running the child: {m}"),
                };
                // Never a fabricated exit code: the child gets a real NTSTATUS
                // failure, and the reason goes to the parent's stderr so a human
                // (and a test) can see that it was exemu, not the guest.
                self.emit_child(
                    true,
                    format!("exemu: child process {} failed — {note}\n", req.image_guest_path)
                        .as_bytes(),
                );
                self.child_failure = Some(note);
                STATUS_UNSUCCESSFUL
            }
        };
        self.children[i].state = ChildState::Exited;
        self.children[i].exit_code = exit_code;
        let (ph, th) = (self.children[i].process_handle, self.children[i].thread_handle);
        if let Some(KObject::Process { exited }) = self.kobjects.get_mut(&ph) {
            *exited = true;
        }
        if let Some(KObject::Thread { exited }) = self.kobjects.get_mut(&th) {
            *exited = true;
        }
    }

    /// Console output produced by a child, folded into this process's stream.
    fn emit_child(&mut self, is_err: bool, bytes: &[u8]) {
        self.emit_bytes(is_err, bytes);
    }

    /// The last child-run failure reason, for tests and diagnostics.
    pub fn child_failure(&self) -> Option<&str> {
        self.child_failure.as_deref()
    }

    // ---- the parent-visible queries --------------------------------------

    /// `NtResumeThread`'s child arm: if `handle` names a child's initial thread,
    /// resume (and therefore run) it. Returns `None` when the handle is not a
    /// child's, so the caller falls through to the in-process thread table.
    pub(crate) fn resume_child_thread(&mut self, handle: u64) -> Option<u32> {
        let i = self.child_by_thread_handle(handle)?;
        Some(self.resume_child(i))
    }

    /// `NtTerminateProcess`'s child arm: end a child that has not run yet (or
    /// re-report one that has). Returns `false` when the handle names no child.
    pub(crate) fn terminate_child(&mut self, handle: u64, code: u32) -> bool {
        let Some(i) = self.child_by_process_handle(handle) else {
            return false;
        };
        if self.children[i].state == ChildState::NotStarted {
            self.children[i].request = None; // it will never run
            self.children[i].state = ChildState::Exited;
            self.children[i].exit_code = code;
            let (ph, th) = (self.children[i].process_handle, self.children[i].thread_handle);
            if let Some(KObject::Process { exited }) = self.kobjects.get_mut(&ph) {
                *exited = true;
            }
            if let Some(KObject::Thread { exited }) = self.kobjects.get_mut(&th) {
                *exited = true;
            }
        }
        true
    }

    /// `NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
    /// ProcessInformation, ProcessInformationLength, *ReturnLength)`.
    ///
    /// Only `ProcessBasicInformation` (class 0) is served, because that is the
    /// whole of kernelbase's `GetExitCodeProcess` and `GetProcessId`. Every other
    /// class keeps the dispatcher's `STATUS_NOT_IMPLEMENTED`, so nothing that
    /// used to be unanswered starts receiving an invented answer.
    ///
    /// `PROCESS_BASIC_INFORMATION` (x64, 0x30 bytes — public winternl.h):
    /// `ExitStatus` @0x00, `PebBaseAddress` @0x08, `AffinityMask` @0x10,
    /// `BasePriority` @0x18, `UniqueProcessId` @0x20,
    /// `InheritedFromUniqueProcessId` @0x28. kernelbase reads only the first
    /// dword; the rest are filled because a guest is entitled to them.
    pub(crate) fn nt_query_information_process(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)? as u32;
        let buffer = self.syscall_arg(cpu, mem, 2)?;
        let length = self.syscall_arg(cpu, mem, 3)?;
        let return_length = self.syscall_arg(cpu, mem, 4)?;
        if class != PROCESS_BASIC_INFORMATION {
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
        let need: u64 = if self.cfg.is_64bit { 0x30 } else { 0x18 };
        if buffer == 0 || length < need {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        // The current process: 0 and `NtCurrentProcess` both name it.
        let (exit_status, peb, pid) = if handle == 0 || handle == NT_CURRENT_PROCESS {
            (STILL_ACTIVE, self.cfg.peb_addr, crate::CURRENT_PROCESS_ID)
        } else if let Some(i) = self.child_by_process_handle(handle) {
            let c = &self.children[i];
            (c.exit_code, 0, c.pid as u64)
        } else {
            return Ok(STATUS_INVALID_HANDLE);
        };
        if self.cfg.is_64bit {
            mem.write_u32(buffer, exit_status)?;
            mem.write_u32(buffer + 0x04, 0)?;
            mem.write_u64(buffer + 0x08, peb)?;
            mem.write_u64(buffer + 0x10, 1)?; // AffinityMask
            mem.write_u64(buffer + 0x18, 8)?; // BasePriority (NORMAL)
            mem.write_u64(buffer + 0x20, pid)?;
            mem.write_u64(buffer + 0x28, if pid == crate::CURRENT_PROCESS_ID { 0 } else { crate::CURRENT_PROCESS_ID })?;
        } else {
            mem.write_u32(buffer, exit_status)?;
            mem.write_u32(buffer + 0x04, peb as u32)?;
            mem.write_u32(buffer + 0x08, 1)?;
            mem.write_u32(buffer + 0x0C, 8)?;
            mem.write_u32(buffer + 0x10, pid as u32)?;
            mem.write_u32(buffer + 0x14, if pid == crate::CURRENT_PROCESS_ID { 0 } else { crate::CURRENT_PROCESS_ID as u32 })?;
        }
        if return_length != 0 {
            mem.write_u32(return_length, need as u32)?;
        }
        Ok(STATUS_SUCCESS)
    }

    // ---- the Win32 seam (emulated path) ----------------------------------

    /// Create a child from an already-resolved guest image path and command
    /// line, minting the same handle pair `NtCreateUserProcess` does. Shared by
    /// the NT syscall above and the emulated-path `CreateProcessW`
    /// ([`crate::api`]), so both produce identical, real process objects.
    ///
    /// Returns `(process_handle, thread_handle, pid, tid)` or the NTSTATUS-shaped
    /// reason it refused.
    pub(crate) fn create_child_process(
        &mut self,
        image_guest_path: &str,
        command_line: &str,
        current_directory: &str,
        inherit_handles: bool,
    ) -> std::result::Result<(u64, u64, u32, u32), u32> {
        let Some(image_host_path) = self.host_path(image_guest_path) else {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        if !image_host_path.is_file() {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let environment = self.env.clone();
        let (pid, tid) = self.next_child_ids();
        let process_handle = self.alloc_khandle();
        let thread_handle = self.alloc_khandle();
        self.kobjects.insert(process_handle, KObject::Process { exited: false });
        self.kobjects.insert(thread_handle, KObject::Thread { exited: false });
        self.children_created += 1;
        self.children.push(ChildProcess {
            pid,
            tid,
            process_handle,
            thread_handle,
            state: ChildState::NotStarted,
            exit_code: STILL_ACTIVE,
            suspend_count: 1,
            request: Some(ChildProcessRequest {
                image_guest_path: image_guest_path.to_string(),
                image_host_path,
                command_line: command_line.to_string(),
                current_directory: current_directory.to_string(),
                environment,
                inherit_handles,
                depth: self.spawn_depth.saturating_add(1),
            }),
        });
        let c = self.children.last().expect("just pushed");
        Ok((c.process_handle, c.thread_handle, c.pid, c.tid))
    }

    /// The exit code a child process handle reports, or `None` when the handle
    /// names no child. Backs the emulated `GetExitCodeProcess`.
    pub(crate) fn child_exit_code(&self, handle: u64) -> Option<u32> {
        self.child_by_process_handle(handle).map(|i| self.children[i].exit_code)
    }

    /// `CreateProcessA/W(lpApplicationName, lpCommandLine, lpProcessAttributes,
    /// lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
    /// lpCurrentDirectory, lpStartupInfo, lpProcessInformation)` on the
    /// **emulated** path — the corpus binaries (NSIS, Total Commander) run
    /// exemu's own kernel32, not Wine's, so without this they would see
    /// `CreateProcess` fail no matter what the NT layer can do.
    ///
    /// The two paths meet in [`WinOs::create_child_process`], so a child is the
    /// same object with the same handle semantics whichever door it came in.
    /// `CREATE_SUSPENDED` is honoured here directly (the guest's flag is visible
    /// at this layer, where under the Wine boot only kernelbase sees it).
    pub(crate) fn win32_create_process(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
        wide: bool,
    ) -> Result<crate::api::Outcome> {
        let app_name = self.arg(cpu, mem, 0)?;
        let cmd_line = self.arg(cpu, mem, 1)?;
        let inherit = self.arg(cpu, mem, 4)? != 0;
        let flags = self.arg(cpu, mem, 5)?;
        let cur_dir = self.arg(cpu, mem, 7)?;
        let info = self.arg(cpu, mem, 9)?;

        let read = |mem: &dyn Memory, p: u64| -> Result<String> {
            if p == 0 {
                return Ok(String::new());
            }
            if wide {
                crate::api::read_wstr(mem, p)
            } else {
                Ok(String::from_utf8_lossy(&mem.read_cstr(p, 0x1000)?).into_owned())
            }
        };
        let app = read(mem, app_name)?;
        let cmd = read(mem, cmd_line)?;
        let dir = read(mem, cur_dir)?;

        // Windows takes the image from lpApplicationName when it is given, and
        // otherwise from the first (possibly quoted) token of the command line.
        let image = if !app.is_empty() { app.clone() } else { first_token(&cmd) };
        if image.is_empty() {
            self.set_last_error(ERROR_INVALID_PARAMETER);
            return Ok(crate::api::Outcome::Return(0));
        }
        let image = self.full_path_name(&image);
        let command_line = if cmd.is_empty() { image.clone() } else { cmd };
        let cwd = if dir.is_empty() { "C:\\".to_string() } else { self.full_path_name(&dir) };

        let (hprocess, hthread, pid, tid) =
            match self.create_child_process(&image, &command_line, &cwd, inherit) {
                Ok(v) => v,
                Err(STATUS_OBJECT_NAME_NOT_FOUND) => {
                    self.set_last_error(ERROR_FILE_NOT_FOUND);
                    return Ok(crate::api::Outcome::Return(0));
                }
                Err(_) => {
                    self.set_last_error(ERROR_NOT_SUPPORTED);
                    return Ok(crate::api::Outcome::Return(0));
                }
            };

        // CREATE_SUSPENDED leaves the initial thread suspended; anything else
        // starts the child now, exactly as kernelbase's own NtResumeThread does.
        if flags & CREATE_SUSPENDED == 0 {
            if let Some(i) = self.child_by_thread_handle(hthread) {
                self.resume_child(i);
            }
        }

        // PROCESS_INFORMATION { HANDLE hProcess; HANDLE hThread; DWORD
        // dwProcessId; DWORD dwThreadId; } — pointer-sized handles, then two
        // DWORDs (public processthreadsapi.h).
        if info != 0 {
            let ptr = if self.cfg.is_64bit { 8u64 } else { 4 };
            self.write_ptr(mem, info, hprocess)?;
            self.write_ptr(mem, info + ptr, hthread)?;
            mem.write_u32(info + ptr * 2, pid)?;
            mem.write_u32(info + ptr * 2 + 4, tid)?;
        }
        Ok(crate::api::Outcome::Return(1))
    }

    /// `GetExitCodeProcess(hProcess, lpExitCode)` on the emulated path. The
    /// current-process pseudo-handle reports `STILL_ACTIVE` (it is, by
    /// definition, still running); a child reports its real code; anything else
    /// fails rather than inventing one.
    pub(crate) fn win32_get_exit_code_process(
        &mut self,
        cpu: &mut CpuState,
        mem: &mut dyn Memory,
    ) -> Result<crate::api::Outcome> {
        let handle = self.arg(cpu, mem, 0)?;
        let out = self.arg(cpu, mem, 1)?;
        // `GetCurrentProcess` hands back the `(HANDLE)-1` pseudo-handle; in
        // 32-bit mode the guest holds it as 0xFFFFFFFF.
        let current = handle == 0 || handle == NT_CURRENT_PROCESS || handle == 0xFFFF_FFFF;
        let code = if current {
            Some(STILL_ACTIVE)
        } else {
            self.child_exit_code(handle)
        };
        let Some(code) = code else {
            self.set_last_error(ERROR_INVALID_HANDLE);
            return Ok(crate::api::Outcome::Return(0));
        };
        if out != 0 {
            mem.write_u32(out, code)?;
        }
        Ok(crate::api::Outcome::Return(1))
    }

    /// Test/diagnostic view: how many child processes this process has created
    /// that the guest still holds a handle to.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// How many child processes this process has successfully created, ever —
    /// monotonic, so closing a handle does not erase the fact. This is what lets
    /// a per-exe probe say "this binary never reached child creation" as a
    /// measurement instead of inferring it from an instruction count.
    pub fn children_created(&self) -> u32 {
        self.children_created
    }
}

/// `ProcessBasicInformation` — `PROCESSINFOCLASS` value 0.
const PROCESS_BASIC_INFORMATION: u32 = 0;

/// `CREATE_SUSPENDED` (public winbase.h) — the Win32 flag whose kernelbase
/// translation into `ProcessFlags` bit 9 is pinned by
/// [`PROCESS_CREATE_FLAGS_SUSPENDED`].
const CREATE_SUSPENDED: u64 = 0x0000_0004;

// Win32 error codes (public winerror.h) for the emulated seam.
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_NOT_SUPPORTED: u32 = 50;

/// The first token of a Windows command line, honouring one level of quoting —
/// what `CreateProcess` uses as the image when `lpApplicationName` is NULL.
fn first_token(cmd: &str) -> String {
    let cmd = cmd.trim_start();
    if let Some(rest) = cmd.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    cmd.split_whitespace().next().unwrap_or("").to_string()
}

/// What [`WinOs::read_ps_attributes`] extracts from a `PS_ATTRIBUTE_LIST`.
#[derive(Default)]
struct PsAttributes {
    /// `PsAttributeImageName`: the child image's NT path.
    image_name: Option<String>,
    /// `PsAttributeClientId`: where to write the child's `CLIENT_ID`.
    client_id_out: Option<u64>,
    /// `PsAttributeImageInfo`: `(buffer, byte length rounded down to 8)`.
    image_info_out: Option<(u64, u64)>,
    /// `(ReturnLength pointer, bytes written)` for each output attribute that
    /// asked for one.
    return_lengths: Vec<(u64, u64)>,
}

// ---- SSDT thunks ----------------------------------------------------------

pub(crate) fn ssdt_nt_create_user_process(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_create_user_process(cpu, mem)
}

pub(crate) fn ssdt_nt_query_information_process(
    os: &mut WinOs,
    cpu: &mut CpuState,
    mem: &mut dyn Memory,
) -> Result<u32> {
    os.nt_query_information_process(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WinConfig, HANDLE_STDERR, HANDLE_STDIN, HANDLE_STDOUT};
    use exemu_core::{Perm, Reg};
    use exemu_memory::VirtualMemory;

    /// A spawner that records what it was asked for and answers with a fixed
    /// exit code, so the object/handle semantics can be tested without a second
    /// emulator instance.
    struct FakeSpawner {
        exit_code: u32,
        stdout: Vec<u8>,
        seen: std::rc::Rc<std::cell::RefCell<Vec<ChildProcessRequest>>>,
    }

    impl ProcessSpawner for FakeSpawner {
        fn spawn(
            &mut self,
            req: &ChildProcessRequest,
        ) -> std::result::Result<ChildProcessOutcome, SpawnError> {
            self.seen.borrow_mut().push(req.clone());
            Ok(ChildProcessOutcome {
                exit_code: self.exit_code,
                steps: 1234,
                stdout: self.stdout.clone(),
                stderr: Vec::new(),
            })
        }
    }

    const PARAMS: u64 = 0x9_0000;
    const ATTRS: u64 = 0x9_1000;
    const SCRATCH: u64 = 0x9_2000;
    const GUEST_RSP: u64 = 0x9_3000;

    fn os64(sandbox: &std::path::Path) -> WinOs {
        WinOs::new(WinConfig {
            is_64bit: true,
            echo: false,
            sandbox: sandbox.to_string_lossy().into_owned(),
            peb_addr: 0x7000_0000,
            ..WinConfig::default()
        })
    }

    /// Lay down a `RTL_USER_PROCESS_PARAMETERS`-shaped block and a
    /// `PS_ATTRIBUTE_LIST` naming `image`, then drive `NtCreateUserProcess`.
    #[allow(clippy::too_many_arguments)]
    fn drive_create(
        os: &mut WinOs,
        mem: &mut VirtualMemory,
        image_nt_path: &str,
        command_line: &str,
        process_flags: u64,
        std_handles: [u64; 3],
        extra_attr: Option<(u64, u64, u64)>,
    ) -> u32 {
        // Params block.
        for off in (0..0x420u64).step_by(8) {
            mem.write_u64(PARAMS + off, 0).unwrap();
        }
        mem.write_u64(PARAMS + pp::STD_INPUT, std_handles[0]).unwrap();
        mem.write_u64(PARAMS + pp::STD_OUTPUT, std_handles[1]).unwrap();
        mem.write_u64(PARAMS + pp::STD_ERROR, std_handles[2]).unwrap();
        let cmd_buf = SCRATCH + 0x200;
        write_wstr(mem, cmd_buf, command_line);
        write_unicode_string(mem, PARAMS + pp::COMMAND_LINE, cmd_buf, command_line.len() * 2);
        let cwd_buf = SCRATCH + 0x400;
        write_wstr(mem, cwd_buf, "C:\\");
        write_unicode_string(mem, PARAMS + pp::CURRENT_DIRECTORY, cwd_buf, 6);

        // Attribute list: ImageName (in), ClientId (out), ImageInfo (out).
        let name_buf = SCRATCH + 0x600;
        write_wstr(mem, name_buf, image_nt_path);
        let client_id = SCRATCH + 0x800;
        let image_info = SCRATCH + 0x900;
        let mut entries: Vec<(u64, u64, u64)> = vec![
            (ps_attr::INPUT | ps_attr::IMAGE_NAME, (image_nt_path.len() * 2) as u64, name_buf),
            (ps_attr::THREAD | ps_attr::CLIENT_ID, 0x10, client_id),
            (ps_attr::IMAGE_INFO, 0x40, image_info),
        ];
        if let Some(e) = extra_attr {
            entries.push(e);
        }
        mem.write_u64(ATTRS + ps_attr::TOTAL_LENGTH, ps_attr::FIRST + entries.len() as u64 * ps_attr::ENTRY_SIZE)
            .unwrap();
        for (i, (packed, size, value)) in entries.iter().enumerate() {
            let e = ATTRS + ps_attr::FIRST + i as u64 * ps_attr::ENTRY_SIZE;
            mem.write_u64(e + ps_attr::ATTRIBUTE, *packed).unwrap();
            mem.write_u64(e + ps_attr::SIZE, *size).unwrap();
            mem.write_u64(e + ps_attr::VALUE, *value).unwrap();
            mem.write_u64(e + ps_attr::RETURN_LENGTH, 0).unwrap();
        }

        // Syscall ABI: arg0=R10, arg1=RDX, arg2=R8, arg3=R9, 4.. on the stack.
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, SCRATCH); // &ProcessHandle
        cpu.set_reg(Reg::Rdx, SCRATCH + 8); // &ThreadHandle
        os.set_syscall_guest_rsp_for_test(GUEST_RSP);
        let stack = |mem: &mut VirtualMemory, n: u64, v: u64| {
            mem.write_u64(GUEST_RSP + 0x28 + (n - 4) * 8, v).unwrap();
        };
        stack(mem, 4, 0); // ProcessObjectAttributes
        stack(mem, 5, 0); // ThreadObjectAttributes
        stack(mem, 6, process_flags);
        stack(mem, 7, THREAD_CREATE_FLAGS_CREATE_SUSPENDED);
        stack(mem, 8, PARAMS);
        stack(mem, 9, 0xDEAD_BEEF); // CreateInfo — never read
        stack(mem, 10, ATTRS);
        os.nt_create_user_process(&mut cpu, mem).unwrap()
    }

    fn write_wstr(mem: &mut VirtualMemory, at: u64, s: &str) {
        let mut i = 0;
        for u in s.encode_utf16() {
            mem.write_u16(at + i, u).unwrap();
            i += 2;
        }
        mem.write_u16(at + i, 0).unwrap();
    }

    fn write_unicode_string(mem: &mut VirtualMemory, at: u64, buf: u64, len: usize) {
        mem.write_u16(at, len as u16).unwrap();
        mem.write_u16(at + 2, (len + 2) as u16).unwrap();
        mem.write_u64(at + 8, buf).unwrap();
    }

    fn fixture() -> (VirtualMemory, std::path::PathBuf) {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x9_0000, 0x8000, Perm::RW, "scratch").unwrap();
        let dir = std::env::temp_dir().join(format!(
            "exemu-w35-unit-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("C")).unwrap();
        std::fs::write(dir.join("C").join("child.exe"), b"MZ not really a PE").unwrap();
        (mem, dir)
    }

    /// The create+resume+wait+exit-code round trip: `NtCreateUserProcess` mints a
    /// handle pair and a CLIENT_ID, nothing runs until the thread is resumed, and
    /// then the exit code is readable through `ProcessBasicInformation`.
    #[test]
    fn create_resume_and_read_the_exit_code() {
        let (mut mem, dir) = fixture();
        let mut os = os64(&dir);
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        os.set_process_spawner(Box::new(FakeSpawner {
            exit_code: 74,
            stdout: b"child said hello\n".to_vec(),
            seen: seen.clone(),
        }));

        let status = drive_create(
            &mut os,
            &mut mem,
            "\\??\\C:\\child.exe",
            "C:\\child.exe --flag",
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            [HANDLE_STDIN, HANDLE_STDOUT, HANDLE_STDERR],
            None,
        );
        assert_eq!(status, STATUS_SUCCESS);

        let hprocess = mem.read_u64(SCRATCH).unwrap();
        let hthread = mem.read_u64(SCRATCH + 8).unwrap();
        assert!(hprocess != 0 && hthread != 0 && hprocess != hthread);
        let pid = mem.read_u64(SCRATCH + 0x800).unwrap();
        let tid = mem.read_u64(SCRATCH + 0x808).unwrap();
        assert!(pid != 0 && tid != 0 && pid % 4 == 0 && tid % 4 == 0, "pid {pid} tid {tid}");

        // Nothing has run: the spawner was not called, and both objects are
        // unsignaled, so a wait would block rather than report a phantom exit.
        assert!(seen.borrow().is_empty(), "a suspended child must not run");
        assert!(!os.kobject_is_signaled_for_test(hprocess));
        assert!(!os.kobject_is_signaled_for_test(hthread));
        assert_eq!(query_exit_status(&mut os, &mut mem, hprocess), STILL_ACTIVE);

        // Resume — kernelbase's own final step — runs it.
        assert_eq!(os.resume_child_thread(hthread), Some(1));
        assert_eq!(seen.borrow().len(), 1, "resume runs the child exactly once");
        let req = seen.borrow()[0].clone();
        assert_eq!(req.image_guest_path, "C:\\child.exe");
        assert_eq!(req.command_line, "C:\\child.exe --flag");
        assert!(req.inherit_handles);

        // Both objects are now signaled and the exit code is the child's.
        assert!(os.kobject_is_signaled_for_test(hprocess));
        assert!(os.kobject_is_signaled_for_test(hthread));
        assert_eq!(query_exit_status(&mut os, &mut mem, hprocess), 74);
        // …and the child's console output landed in the parent's stream.
        assert_eq!(
            String::from_utf8_lossy(os.captured_stdout()),
            "child said hello\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn query_exit_status(os: &mut WinOs, mem: &mut VirtualMemory, handle: u64) -> u32 {
        let buf = SCRATCH + 0xA00;
        let mut cpu = CpuState::default();
        cpu.set_reg(Reg::R10, handle);
        cpu.set_reg(Reg::Rdx, PROCESS_BASIC_INFORMATION as u64);
        cpu.set_reg(Reg::R8, buf);
        cpu.set_reg(Reg::R9, 0x30);
        os.set_syscall_guest_rsp_for_test(GUEST_RSP);
        mem.write_u64(GUEST_RSP + 0x28, 0).unwrap(); // ReturnLength
        assert_eq!(os.nt_query_information_process(&mut cpu, mem).unwrap(), STATUS_SUCCESS);
        mem.read_u32(buf).unwrap()
    }

    /// A missing image is refused with the status kernelbase turns into
    /// ERROR_FILE_NOT_FOUND — not a handle to a process that will never exist.
    #[test]
    fn a_missing_image_is_refused() {
        let (mut mem, dir) = fixture();
        let mut os = os64(&dir);
        os.set_process_spawner(Box::new(FakeSpawner {
            exit_code: 0,
            stdout: Vec::new(),
            seen: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
        }));
        let status = drive_create(
            &mut os,
            &mut mem,
            "\\??\\C:\\nothing-here.exe",
            "C:\\nothing-here.exe",
            0,
            [0, 0, 0],
            None,
        );
        assert_eq!(status, STATUS_OBJECT_NAME_NOT_FOUND);
        assert_eq!(os.child_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a spawner installed there is no way to run a child, and the
    /// refusal reaches the guest as a failed process rather than a silent zero
    /// exit code.
    #[test]
    fn without_a_spawner_the_child_fails_loudly() {
        let (mut mem, dir) = fixture();
        let mut os = os64(&dir);
        let status = drive_create(
            &mut os,
            &mut mem,
            "\\??\\C:\\child.exe",
            "C:\\child.exe",
            0,
            [0, 0, 0],
            None,
        );
        assert_eq!(status, STATUS_SUCCESS, "creation itself is fine");
        let hthread = mem.read_u64(SCRATCH + 8).unwrap();
        let hprocess = mem.read_u64(SCRATCH).unwrap();
        os.resume_child_thread(hthread);
        assert_eq!(query_exit_status(&mut os, &mut mem, hprocess), STATUS_UNSUCCESSFUL);
        assert!(os.child_failure().unwrap().contains("no child-process runner"));
        assert!(String::from_utf8_lossy(os.captured_stderr()).contains("exemu: child process"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The named refusals: each returns a real NTSTATUS and creates nothing.
    #[test]
    fn out_of_scope_requests_are_refused_with_a_real_status() {
        let cases: [(u64, u64, u64, u32); 5] = [
            // (packed attribute, size, value, expected status)
            (ps_attr::INPUT | ps_attr::ADDITIVE | ps_attr::DEBUG_PORT, 8, 0x4000, STATUS_NOT_SUPPORTED),
            (ps_attr::INPUT | ps_attr::JOB_LIST, 8, 0x4000, STATUS_NOT_SUPPORTED),
            (ps_attr::INPUT | ps_attr::ADDITIVE | ps_attr::TOKEN, 8, 0x4000, STATUS_NOT_SUPPORTED),
            (ps_attr::INPUT | ps_attr::HANDLE_LIST, 8, 0x4000, STATUS_NOT_SUPPORTED),
            (
                ps_attr::INPUT | ps_attr::ADDITIVE | ps_attr::MACHINE_TYPE,
                2,
                0x014C, // IMAGE_FILE_MACHINE_I386
                STATUS_INVALID_IMAGE_FORMAT,
            ),
        ];
        for (packed, size, value, want) in cases {
            let (mut mem, dir) = fixture();
            let mut os = os64(&dir);
            let status = drive_create(
                &mut os,
                &mut mem,
                "\\??\\C:\\child.exe",
                "C:\\child.exe",
                0,
                [0, 0, 0],
                Some((packed, size, value)),
            );
            assert_eq!(status, want, "attribute {packed:#x} must be refused");
            assert_eq!(os.child_count(), 0, "a refused create leaves no object behind");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A std handle that is not one of the console sentinels cannot be inherited
    /// into a fresh address space, so the create is refused rather than silently
    /// redirecting the child's output to the console.
    #[test]
    fn a_redirected_std_handle_is_refused() {
        let (mut mem, dir) = fixture();
        let mut os = os64(&dir);
        let status = drive_create(
            &mut os,
            &mut mem,
            "\\??\\C:\\child.exe",
            "C:\\child.exe",
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            [HANDLE_STDIN, 0x1000 /* a file handle */, HANDLE_STDERR],
            None,
        );
        assert_eq!(status, STATUS_NOT_SUPPORTED);
        assert_eq!(os.child_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The reader used here and the W3.6 writer in `dll.rs` agree: a params block
    /// built by `build_process_parameters` is read back correctly through
    /// [`pp`], which is what "reuse it rather than re-derive it" has to mean.
    #[test]
    fn params_reader_matches_the_w36_writer() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x10_0000, Perm::RW, "arena").unwrap();
        let mut os = WinOs::new(WinConfig {
            is_64bit: true,
            echo: false,
            module_path_w: "C:\\parent.exe".into(),
            dll_base: 0x2_0000,
            dll_size: 0x10_0000,
            ..WinConfig::default()
        });
        let params = os.build_process_parameters_for_test(&mut mem).unwrap();

        assert_eq!(mem.read_u64(params + pp::STD_INPUT).unwrap(), HANDLE_STDIN);
        assert_eq!(mem.read_u64(params + pp::STD_OUTPUT).unwrap(), HANDLE_STDOUT);
        assert_eq!(mem.read_u64(params + pp::STD_ERROR).unwrap(), HANDLE_STDERR);
        assert_eq!(mem.read_u64(params + pp::CONSOLE_HANDLE).unwrap(), 0);
        assert_eq!(
            crate::fs::read_unicode_string(&mem, params + pp::IMAGE_PATH_NAME).unwrap(),
            "C:\\parent.exe"
        );
        assert_eq!(
            crate::fs::read_unicode_string(&mem, params + pp::CURRENT_DIRECTORY).unwrap(),
            "C:\\"
        );
        // The environment round-trips through the same decoder the child gets:
        // the block this writer laid down decodes back to the pairs it was made
        // from, name and value both.
        let env = os.read_environment_block(&mem, params).unwrap();
        let system_root = env
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("SystemRoot"))
            .unwrap_or_else(|| panic!("the decoded environment carries SystemRoot: {env:?}"));
        assert!(
            system_root.1.starts_with("C:"),
            "SystemRoot decoded as {:?} — a leading '=' here means the name/value \
             split ate the separator",
            system_root.1
        );
        assert!(env.iter().all(|(k, _)| !k.is_empty()), "no empty names: {env:?}");
        assert!(
            env.iter().all(|(_, v)| !v.starts_with('=')),
            "no value keeps the separator: {env:?}"
        );
    }
}

//! Generates the **WoW64** proof binary — a **PE32** console program that calls
//! `ntdll!NtAllocateVirtualMemory` and `ntdll!NtTerminateProcess` through a
//! *static* import of `ntdll.dll` (roadmap W5.5).
//!
//! Why a static import matters: it forces the boot to bind the guest's IAT to
//! the **32-bit** `ntdll.dll` from the pinned `i386-windows` prefix, so the
//! `call [IAT]` runs Wine's own syscall stub —
//! `mov eax,<index>; mov edx,<helper>; call edx; ret <argbytes>` — rather than
//! anything exemu hand-assembled. From there the whole chain is Wine's:
//!
//! ```text
//!   ntdll32!NtAllocateVirtualMemory  (Wine's 32-bit stub, index 0x18)
//!     → jmp [ntdll32!__wine_syscall_dispatcher]      (its rva-0xe0c4 helper)
//!     → the wow64cpu BOP  (FF 2D far jmp, CS 0x33)   (built by BTCpuProcessInit)
//!     → wow64cpu's 64-bit return handler
//!     → wow64.dll!Wow64SystemServiceEx → its per-service marshalling thunk
//!     → ntdll.dll (64-bit) NtAllocateVirtualMemory → exemu's SSDT
//! ```
//!
//! What the guest does, and why each step is load-bearing:
//!
//! 1. `NtAllocateVirtualMemory(-1, &base, 0, &size, MEM_COMMIT|RESERVE,
//!    PAGE_READWRITE)` with `base = NULL` — six 32-bit stdcall arguments, so
//!    `wow64.dll`'s ~200-instruction marshalling thunk (sign-extending the
//!    pseudo-handle, widening the IN/OUT cells, substituting its own `ZeroBits`)
//!    really runs.
//! 2. **Writes a sentinel through the returned pointer.** A base that came back
//!    truncated out of exemu's 64-bit arena would fault here instead of quietly
//!    passing a status check.
//! 3. Reads the sentinel back and compares.
//! 4. `NtTerminateProcess(-1, <exit code>)` — itself a second trip through the
//!    whole chain, so the process's own exit status is evidence the round trip
//!    survived.
//!
//! The exit code is [`WOW64_OK_EXIT`] only when every check held; otherwise it
//! encodes which one failed, so a partial run is diagnosable without a debugger.

const IMAGE_BASE: u32 = 0x0040_0000;
const SECTION_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;
const TEXT_RVA: u32 = 0x1000;
const RDATA_RVA: u32 = 0x2000;
const DATA_RVA: u32 = 0x3000;
const PE_OFF: usize = 0x40;
/// PE32 optional header: 96 bytes of fixed fields + 16 data directories.
const OPT_HEADER_SIZE: usize = 96 + 16 * 8;

/// Exit code when the allocation round-tripped and the memory was writable.
pub const WOW64_OK_EXIT: i32 = 91;
/// Exit code when `NtAllocateVirtualMemory` returned a non-zero NTSTATUS.
pub const WOW64_FAIL_STATUS_EXIT: i32 = 92;
/// Exit code when the status was success but no base was written back.
pub const WOW64_FAIL_BASE_EXIT: i32 = 93;
/// Exit code when the sentinel did not read back through the returned pointer.
pub const WOW64_FAIL_SENTINEL_EXIT: i32 = 94;

/// The sentinel the guest stores through the freshly allocated pointer.
pub const WOW64_SENTINEL: u32 = 0xCAFE_BABE;
/// Bytes the guest asks `NtAllocateVirtualMemory` for.
pub const WOW64_ALLOC_SIZE: u32 = 0x2000;

/// Exit code when the 32-bit SEH round trip completed: the guest's own handler
/// ran, saw an access violation, and execution resumed where it asked.
pub const WOW64_SEH_OK_EXIT: i32 = 81;
/// Exit code when execution resumed but the handler never ran.
pub const WOW64_SEH_FAIL_NOT_HANDLED_EXIT: i32 = 82;
/// Exit code when the handler ran but saw the wrong `ExceptionCode`.
pub const WOW64_SEH_FAIL_CODE_EXIT: i32 = 83;
/// Exit code when the handler ran but the record did not name the faulting
/// address in `ExceptionInformation[1]`.
pub const WOW64_SEH_FAIL_INFO_EXIT: i32 = 84;

/// The marker the guest's SEH handler writes so the gate can tell "it ran" from
/// "the fault was silently swallowed".
pub const WOW64_SEH_HANDLED: u32 = 0x5E_48_00_01;
/// The marker written after the handler's requested resume point is reached.
pub const WOW64_SEH_RESUMED: u32 = 0x5E_48_00_02;
/// `STATUS_ACCESS_VIOLATION` — what the handler must see.
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// The address the SEH guest deliberately reads through. Deliberately *not*
/// zero: a NULL deref is the one address every layer special-cases, and this
/// must exercise the ordinary unmapped-read path.
pub const WOW64_SEH_FAULT_ADDR: u32 = 0x0000_DEAD;

/// `.data` offsets (from [`DATA_RVA`]) the gate reads back out of guest memory.
pub mod data {
    /// `PVOID BaseAddress` — the IN/OUT cell `NtAllocateVirtualMemory` fills.
    pub const BASE: u32 = 0x00;
    /// `SIZE_T RegionSize` — the other IN/OUT cell.
    pub const SIZE: u32 = 0x04;
    /// The NTSTATUS the 32-bit guest received back in `eax`.
    pub const STATUS: u32 = 0x08;
    /// The value read back through the returned pointer.
    pub const READBACK: u32 = 0x0c;
    /// `esp` after the call, so the gate can prove the stdcall unwound cleanly.
    pub const ESP_AFTER: u32 = 0x10;
    /// SEH guest: the marker its handler writes.
    pub const SEH_HANDLED: u32 = 0x20;
    /// SEH guest: `EXCEPTION_RECORD32.ExceptionCode` as the handler saw it.
    pub const SEH_CODE: u32 = 0x24;
    /// SEH guest: `EXCEPTION_RECORD32.ExceptionFlags`.
    pub const SEH_FLAGS: u32 = 0x28;
    /// SEH guest: `EXCEPTION_RECORD32.ExceptionAddress` (a 32-bit field — proof
    /// that `wow64.dll` narrowed the 64-bit record rather than exemu building a
    /// 32-bit one).
    pub const SEH_ADDR: u32 = 0x2c;
    /// SEH guest: `ExceptionInformation[1]`, the faulting data address.
    pub const SEH_INFO1: u32 = 0x30;
    /// SEH guest: `ExceptionInformation[0]`, the access kind (0 = read).
    pub const SEH_INFO0: u32 = 0x34;
    /// SEH guest: the marker written at the resume point.
    pub const SEH_RESUMED: u32 = 0x38;
    /// Total bytes of `.data`.
    pub const LEN: u32 = 0x40;
}

/// Absolute VA of a `.data` cell in the built image.
pub const fn data_va(off: u32) -> u64 {
    (IMAGE_BASE + DATA_RVA + off) as u64
}

/// Absolute VA of the guest's `ntdll!NtAllocateVirtualMemory` IAT slot — what a
/// gate reads to prove the boot bound it to the **32-bit** ntdll.
pub fn iat_alloc_va() -> u64 {
    (IMAGE_BASE + RDATA_RVA + iat_off()) as u64
}

/// Offset of the IAT within `.rdata` (one descriptor + terminator, then the ILT).
fn iat_off() -> u32 {
    const IMPORT_DIR_SIZE: u32 = 2 * 20;
    const N: u32 = 2; // NtAllocateVirtualMemory, NtTerminateProcess
    IMPORT_DIR_SIZE + (N + 1) * 4
}

/// Which of the two PE32 WoW64 proof binaries to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Program {
    /// The W5.5 allocator: one `NtAllocateVirtualMemory` round trip through
    /// Wine's whole 32→64 chain, then `NtTerminateProcess`.
    #[default]
    Alloc,
    /// The W5.9 exception guest: install a 32-bit `fs:[0]` SEH frame, read
    /// through an unmapped address, and let the handler resume execution.
    Seh,
}

/// Build the PE32 WoW64 sample ([`Program::Alloc`]).
pub fn build() -> Vec<u8> {
    build_program(Program::Alloc)
}

/// Build the PE32 WoW64 **exception** sample ([`Program::Seh`], roadmap W5.9).
pub fn build_seh() -> Vec<u8> {
    build_program(Program::Seh)
}

/// Build one of the PE32 WoW64 proof binaries. Both share every byte of the PE
/// scaffolding — same import table, same sections — so a difference in outcome
/// is a difference in the *program*, not in how it was loaded.
pub fn build_program(program: Program) -> Vec<u8> {
    let names = ["NtAllocateVirtualMemory", "NtTerminateProcess"];

    // --- .rdata: import descriptor + ILT/IAT + name blobs -----------------
    let import_dir_off = 0u32;
    let import_dir_size = 2 * 20; // one descriptor + the null terminator
    let ilt_off = import_dir_off + import_dir_size;
    let ilt_size = (names.len() as u32 + 1) * 4; // PE32: 4-byte thunks
    let iat_off = ilt_off + ilt_size;
    debug_assert_eq!(iat_off, self::iat_off(), "iat_off() must match the emitted layout");
    let iat_size = ilt_size;

    let mut pos = iat_off + iat_size;
    let mut ibn_rva = Vec::new();
    for n in &names {
        pos = align_up_u32(pos, 2);
        ibn_rva.push(RDATA_RVA + pos);
        pos += 2 + n.len() as u32 + 1;
    }
    pos = align_up_u32(pos, 2);
    let dllname_rva = RDATA_RVA + pos;
    let dllname = b"ntdll.dll\0";
    pos += dllname.len() as u32;

    let mut rd = vec![0u8; pos as usize];
    put_u32(&mut rd, import_dir_off as usize, RDATA_RVA + ilt_off); // OriginalFirstThunk
    put_u32(&mut rd, import_dir_off as usize + 12, dllname_rva); // Name
    put_u32(&mut rd, import_dir_off as usize + 16, RDATA_RVA + iat_off); // FirstThunk
    for (i, &rva) in ibn_rva.iter().enumerate() {
        put_u32(&mut rd, ilt_off as usize + i * 4, rva);
        put_u32(&mut rd, iat_off as usize + i * 4, rva);
    }
    for (i, n) in names.iter().enumerate() {
        let off = (ibn_rva[i] - RDATA_RVA) as usize;
        rd[off + 2..off + 2 + n.len()].copy_from_slice(n.as_bytes());
    }
    let doff = (dllname_rva - RDATA_RVA) as usize;
    rd[doff..doff + dllname.len()].copy_from_slice(dllname);

    let iat = |i: u32| IMAGE_BASE + RDATA_RVA + iat_off + i * 4;
    let text = match program {
        Program::Alloc => build_text(iat(0), iat(1)),
        Program::Seh => build_text_seh(iat(1)),
    };

    // --- assemble the file ------------------------------------------------
    let headers_raw = FILE_ALIGN as usize;
    let text_ptr = headers_raw;
    let text_raw = align_up(text.len(), FILE_ALIGN as usize);
    let rdata_ptr = text_ptr + text_raw;
    let rdata_raw = align_up(rd.len(), FILE_ALIGN as usize);
    let file_len = rdata_ptr + rdata_raw;

    let mut f = vec![0u8; file_len];
    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32);
    put_u32(&mut f, PE_OFF, 0x0000_4550);
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x014C); // IMAGE_FILE_MACHINE_I386
    put_u16(&mut f, coff + 2, 3); // 3 sections
    put_u16(&mut f, coff + 16, OPT_HEADER_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x0102); // EXECUTABLE_IMAGE | 32BIT_MACHINE

    let opt = coff + 20;
    let image_size = align_up_u32(DATA_RVA + data::LEN, SECTION_ALIGN);
    put_u16(&mut f, opt, 0x10B); // PE32
    f[opt + 2] = 14;
    put_u32(&mut f, opt + 4, text_raw as u32); // SizeOfCode
    put_u32(&mut f, opt + 8, rdata_raw as u32); // SizeOfInitializedData
    put_u32(&mut f, opt + 16, TEXT_RVA); // AddressOfEntryPoint
    put_u32(&mut f, opt + 20, TEXT_RVA); // BaseOfCode
    put_u32(&mut f, opt + 24, RDATA_RVA); // BaseOfData (PE32 only)
    put_u32(&mut f, opt + 28, IMAGE_BASE); // ImageBase (PE32: 4 bytes @28)
    put_u32(&mut f, opt + 32, SECTION_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6); // MajorOperatingSystemVersion
    put_u16(&mut f, opt + 48, 6); // MajorSubsystemVersion
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw as u32);
    put_u16(&mut f, opt + 68, 3); // CONSOLE
    put_u32(&mut f, opt + 72, 0x10_0000); // SizeOfStackReserve
    put_u32(&mut f, opt + 76, 0x1000); // SizeOfStackCommit
    put_u32(&mut f, opt + 80, 0x10_0000); // SizeOfHeapReserve
    put_u32(&mut f, opt + 84, 0x1000); // SizeOfHeapCommit
    put_u32(&mut f, opt + 92, 16); // NumberOfRvaAndSizes

    let dir = |i: usize| opt + 96 + i * 8;
    put_u32(&mut f, dir(1), RDATA_RVA + import_dir_off);
    put_u32(&mut f, dir(1) + 4, import_dir_size);
    put_u32(&mut f, dir(12), RDATA_RVA + iat_off);
    put_u32(&mut f, dir(12) + 4, iat_size);

    let sec = opt + OPT_HEADER_SIZE;
    write_section(&mut f, sec, b".text", text.len() as u32, TEXT_RVA, text_raw as u32, text_ptr as u32, 0x6000_0020);
    write_section(&mut f, sec + 40, b".rdata", rd.len() as u32, RDATA_RVA, rdata_raw as u32, rdata_ptr as u32, 0x4000_0040);
    // `.data` is BSS-style: VirtualSize only, zero-filled by the loader.
    write_section(&mut f, sec + 80, b".data", data::LEN, DATA_RVA, 0, 0, 0xC000_0080);

    f[text_ptr..text_ptr + text.len()].copy_from_slice(&text);
    f[rdata_ptr..rdata_ptr + rd.len()].copy_from_slice(&rd);
    f
}

/// The 32-bit `.text`. Hand-assembled stdcall: arguments pushed right-to-left,
/// the callee (Wine's own `ret <argbytes>`) pops them.
fn build_text(iat_alloc: u32, iat_terminate: u32) -> Vec<u8> {
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const PAGE_READWRITE: u32 = 0x04;
    let base_cell = IMAGE_BASE + DATA_RVA + data::BASE;
    let size_cell = IMAGE_BASE + DATA_RVA + data::SIZE;
    let status_cell = IMAGE_BASE + DATA_RVA + data::STATUS;
    let read_cell = IMAGE_BASE + DATA_RVA + data::READBACK;
    let esp_cell = IMAGE_BASE + DATA_RVA + data::ESP_AFTER;

    let mut c: Vec<u8> = Vec::new();
    // *BaseAddress = NULL  (mov dword [base_cell], 0)
    c.extend_from_slice(&[0xC7, 0x05]);
    c.extend_from_slice(&base_cell.to_le_bytes());
    c.extend_from_slice(&0u32.to_le_bytes());
    // *RegionSize = WOW64_ALLOC_SIZE
    c.extend_from_slice(&[0xC7, 0x05]);
    c.extend_from_slice(&size_cell.to_le_bytes());
    c.extend_from_slice(&WOW64_ALLOC_SIZE.to_le_bytes());

    // NtAllocateVirtualMemory(ProcessHandle=-1, &Base, ZeroBits=0, &Size,
    //                         AllocationType, Protect) — pushed right to left.
    for imm in [
        PAGE_READWRITE,
        MEM_COMMIT_RESERVE,
        size_cell,
        0, // ZeroBits — wow64.dll substitutes its own 0x7fffffff
        base_cell,
        0xFFFF_FFFF, // NtCurrentProcess, sign-extended by wow64.dll's thunk
    ] {
        c.push(0x68); // push imm32
        c.extend_from_slice(&imm.to_le_bytes());
    }
    c.extend_from_slice(&[0xFF, 0x15]); // call dword ptr [iat_alloc]
    c.extend_from_slice(&iat_alloc.to_le_bytes());

    // Record the NTSTATUS and the post-call esp (a stdcall that unwound cleanly
    // returns esp to where it was before the six pushes).
    c.extend_from_slice(&[0xA3]); // mov [status_cell], eax
    c.extend_from_slice(&status_cell.to_le_bytes());
    c.extend_from_slice(&[0x89, 0x25]); // mov [esp_cell], esp
    c.extend_from_slice(&esp_cell.to_le_bytes());

    // if (status != 0) exit(WOW64_FAIL_STATUS_EXIT)
    c.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    let jz_status = c.len();
    c.extend_from_slice(&[0x74, 0x00]); // jz +?
    emit_exit(&mut c, iat_terminate, WOW64_FAIL_STATUS_EXIT as u32);
    patch_rel8(&mut c, jz_status);

    // ecx = *BaseAddress; if (ecx == 0) exit(WOW64_FAIL_BASE_EXIT)
    c.extend_from_slice(&[0x8B, 0x0D]); // mov ecx, [base_cell]
    c.extend_from_slice(&base_cell.to_le_bytes());
    c.extend_from_slice(&[0x85, 0xC9]); // test ecx, ecx
    let jnz_base = c.len();
    c.extend_from_slice(&[0x75, 0x00]); // jnz +?
    emit_exit(&mut c, iat_terminate, WOW64_FAIL_BASE_EXIT as u32);
    patch_rel8(&mut c, jnz_base);

    // *(u32*)base = WOW64_SENTINEL ; read it back
    c.extend_from_slice(&[0xC7, 0x01]); // mov dword [ecx], imm32
    c.extend_from_slice(&WOW64_SENTINEL.to_le_bytes());
    c.extend_from_slice(&[0x8B, 0x11]); // mov edx, [ecx]
    c.extend_from_slice(&[0x89, 0x15]); // mov [read_cell], edx
    c.extend_from_slice(&read_cell.to_le_bytes());
    c.extend_from_slice(&[0x81, 0xFA]); // cmp edx, imm32
    c.extend_from_slice(&WOW64_SENTINEL.to_le_bytes());
    let je_ok = c.len();
    c.extend_from_slice(&[0x74, 0x00]); // je +?
    emit_exit(&mut c, iat_terminate, WOW64_FAIL_SENTINEL_EXIT as u32);
    patch_rel8(&mut c, je_ok);

    emit_exit(&mut c, iat_terminate, WOW64_OK_EXIT as u32);
    c.push(0xF4); // hlt — NtTerminateProcess does not return
    c
}

/// The 32-bit `.text` of the **exception** guest (roadmap W5.9).
///
/// Nothing here is WoW64-aware: it is the ordinary i386 SEH prologue any 1990s
/// MSVC binary emits — push a handler, chain it through `fs:[0]`, fault, and
/// let the handler point the `CONTEXT` at a recovery label and return
/// `ExceptionContinueExecution`. That is the point: if this runs, a *32-bit
/// program's own* exception handling works, and every step between the fault and
/// the handler was Wine's code.
///
/// ```text
///   push  <handler>
///   push  dword ptr fs:[0]
///   mov   fs:[0], esp             ; EXCEPTION_REGISTRATION_RECORD{prev,handler}
///   mov   eax, WOW64_SEH_FAULT_ADDR
///   mov   eax, [eax]              ; ← access violation, unmapped read
/// resume:                          ; the handler re-seats CONTEXT.Eip here
///   mov   [SEH_RESUMED], marker
///   mov   eax, [esp]              ; unlink the frame
///   mov   fs:[0], eax
///   add   esp, 8
///   …checks…  → NtTerminateProcess(-1, code)
///
/// handler:                         ; (rec, frame, ctx, disp) — cdecl, no ret pop
///   record rec->ExceptionCode / Flags / Address / Information[0..1]
///   ctx->Eip = resume
///   [SEH_HANDLED] = marker
///   xor eax, eax                  ; ExceptionContinueExecution
///   ret
/// ```
///
/// The record fields it copies out are the 32-bit ones
/// `wow64.dll!Wow64PassExceptionToGuest` narrows from the 64-bit record exemu
/// hands the kernel-side dispatcher, so reading them back in the gate re-derives
/// that narrowing from the guest's side of the boundary.
fn build_text_seh(iat_terminate: u32) -> Vec<u8> {
    let cell = |off: u32| IMAGE_BASE + DATA_RVA + off;
    let text_va = IMAGE_BASE + TEXT_RVA;
    let mut c: Vec<u8> = Vec::new();

    // push <handler>   (address patched once the handler is emitted)
    c.push(0x68);
    let handler_imm = c.len();
    c.extend_from_slice(&0u32.to_le_bytes());
    // push dword ptr fs:[0]
    c.extend_from_slice(&[0x64, 0xFF, 0x35, 0, 0, 0, 0]);
    // mov fs:[0], esp
    c.extend_from_slice(&[0x64, 0x89, 0x25, 0, 0, 0, 0]);

    // mov eax, WOW64_SEH_FAULT_ADDR ; mov eax, [eax]  ← the access violation
    c.push(0xB8);
    c.extend_from_slice(&WOW64_SEH_FAULT_ADDR.to_le_bytes());
    c.extend_from_slice(&[0x8B, 0x00]);

    // --- resume point -----------------------------------------------------
    let resume_off = c.len();
    emit_store_imm(&mut c, cell(data::SEH_RESUMED), WOW64_SEH_RESUMED);
    // Unlink the registration record: mov eax,[esp]; mov fs:[0],eax; add esp,8
    c.extend_from_slice(&[0x8B, 0x04, 0x24]);
    c.extend_from_slice(&[0x64, 0xA3, 0, 0, 0, 0]);
    c.extend_from_slice(&[0x83, 0xC4, 0x08]);

    // if ([SEH_HANDLED] != marker) exit(NOT_HANDLED)
    emit_cmp_cell(&mut c, cell(data::SEH_HANDLED), WOW64_SEH_HANDLED);
    let j1 = c.len();
    c.extend_from_slice(&[0x74, 0x00]); // je +?
    emit_exit(&mut c, iat_terminate, WOW64_SEH_FAIL_NOT_HANDLED_EXIT as u32);
    patch_rel8(&mut c, j1);

    // if ([SEH_CODE] != STATUS_ACCESS_VIOLATION) exit(CODE)
    emit_cmp_cell(&mut c, cell(data::SEH_CODE), STATUS_ACCESS_VIOLATION);
    let j2 = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    emit_exit(&mut c, iat_terminate, WOW64_SEH_FAIL_CODE_EXIT as u32);
    patch_rel8(&mut c, j2);

    // if ([SEH_INFO1] != WOW64_SEH_FAULT_ADDR) exit(INFO)
    emit_cmp_cell(&mut c, cell(data::SEH_INFO1), WOW64_SEH_FAULT_ADDR);
    let j3 = c.len();
    c.extend_from_slice(&[0x74, 0x00]);
    emit_exit(&mut c, iat_terminate, WOW64_SEH_FAIL_INFO_EXIT as u32);
    patch_rel8(&mut c, j3);

    emit_exit(&mut c, iat_terminate, WOW64_SEH_OK_EXIT as u32);
    c.push(0xF4); // hlt — NtTerminateProcess does not return

    // --- the handler ------------------------------------------------------
    let handler_off = c.len();
    c[handler_imm..handler_imm + 4].copy_from_slice(&(text_va + handler_off as u32).to_le_bytes());
    // ecx = ExceptionRecord (arg 0, at [esp+4] — the dispatcher calls this cdecl)
    c.extend_from_slice(&[0x8B, 0x4C, 0x24, 0x04]);
    for (rec_off, dst) in [
        (0x00u8, data::SEH_CODE),
        (0x04, data::SEH_FLAGS),
        (0x0c, data::SEH_ADDR),
        (0x14, data::SEH_INFO0),
        (0x18, data::SEH_INFO1),
    ] {
        if rec_off == 0 {
            c.extend_from_slice(&[0x8B, 0x01]); // mov eax, [ecx]
        } else {
            c.extend_from_slice(&[0x8B, 0x41, rec_off]); // mov eax, [ecx+off]
        }
        c.push(0xA3); // mov [dst], eax
        c.extend_from_slice(&cell(dst).to_le_bytes());
    }
    // eax = ContextRecord (arg 2, at [esp+0xc]); ctx->Eip = resume
    c.extend_from_slice(&[0x8B, 0x44, 0x24, 0x0C]);
    c.extend_from_slice(&[0xC7, 0x80]);
    c.extend_from_slice(&(exemu_os::wow64::CTX_EIP as u32).to_le_bytes());
    c.extend_from_slice(&(text_va + resume_off as u32).to_le_bytes());
    emit_store_imm(&mut c, cell(data::SEH_HANDLED), WOW64_SEH_HANDLED);
    c.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax → ExceptionContinueExecution
    c.push(0xC3); // ret
    c
}

/// `mov dword ptr [abs32], imm32`.
fn emit_store_imm(c: &mut Vec<u8>, at: u32, v: u32) {
    c.extend_from_slice(&[0xC7, 0x05]);
    c.extend_from_slice(&at.to_le_bytes());
    c.extend_from_slice(&v.to_le_bytes());
}

/// `mov eax,[abs32]; cmp eax, imm32` — leaves ZF set when they match.
fn emit_cmp_cell(c: &mut Vec<u8>, at: u32, v: u32) {
    c.push(0xA1); // mov eax, [abs32]
    c.extend_from_slice(&at.to_le_bytes());
    c.extend_from_slice(&[0x3D]); // cmp eax, imm32
    c.extend_from_slice(&v.to_le_bytes());
}

/// `NtTerminateProcess(NtCurrentProcess, code)` — stdcall, 2 arguments.
fn emit_exit(c: &mut Vec<u8>, iat_terminate: u32, code: u32) {
    c.push(0x68);
    c.extend_from_slice(&code.to_le_bytes()); // push code
    c.push(0x68);
    c.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // push -1
    c.extend_from_slice(&[0xFF, 0x15]);
    c.extend_from_slice(&iat_terminate.to_le_bytes());
}

/// Patch a `jcc rel8` whose displacement byte sits at `at + 1` to jump to the
/// current end of `c`.
fn patch_rel8(c: &mut [u8], at: usize) {
    let target = c.len();
    let disp = target - (at + 2);
    assert!(disp < 128, "wow64 sample: rel8 branch out of range ({disp})");
    c[at + 1] = disp as u8;
}

#[allow(clippy::too_many_arguments)]
fn write_section(f: &mut [u8], at: usize, name: &[u8], vsize: u32, vaddr: u32, raw_size: u32, raw_ptr: u32, chars: u32) {
    f[at..at + name.len()].copy_from_slice(name);
    put_u32(f, at + 8, vsize);
    put_u32(f, at + 12, vaddr);
    put_u32(f, at + 16, raw_size);
    put_u32(f, at + 20, raw_ptr);
    put_u32(f, at + 36, chars);
}

fn put_u16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn align_up_u32(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

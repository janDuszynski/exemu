//! W3.5 — **the child-process boundary, re-derived from the pinned binaries**.
//!
//! Every offset, index and flag bit that `exemu_os::process` relies on is
//! recovered here from the bytes of
//! `example_exe/wine-dlls/x86_64-windows/{kernelbase,ntdll}.dll` on every run
//! and asserted against the constants the implementation uses. A guessed
//! structure offset, a drifted SSDT index or a mis-read flag fails **here**,
//! loudly, instead of turning into a child process that quietly does the wrong
//! thing — which is the classic failure mode for a boundary nobody re-derived.
//!
//! What it establishes, all from the binary:
//!
//! 1. `NtCreateUserProcess`'s and `NtQueryInformationProcess`'s SSDT indices,
//!    read from ntdll's own `mov r10,rcx; mov eax,N` stubs.
//! 2. `CreateProcessW` reaches `NtCreateUserProcess` from exactly one place —
//!    kernelbase's `create_nt_process` — and always with
//!    `ThreadFlags = THREAD_CREATE_FLAGS_CREATE_SUSPENDED`, which is why
//!    exemu starts a child on `NtResumeThread` and not before.
//! 3. The `ProcessFlags` bits kernelbase composes: bit 2 from `bInheritHandles`
//!    and bit 9 from `CREATE_SUSPENDED`.
//! 4. The `PS_ATTRIBUTE_LIST` shape and the exact set of attribute numbers this
//!    kernelbase emits — so a future pinned build that adds one fails a
//!    named assertion instead of being silently skipped.
//! 5. **`PS_CREATE_INFO` is never initialised**: the stack slot whose address
//!    `create_nt_process` passes as `CreateInfo` is referenced exactly once in
//!    the whole function — by the `lea` that takes its address. Reading it would
//!    be reading uninitialised stack.
//! 6. The `RTL_USER_PROCESS_PARAMETERS` std-handle trio at +0x20/+0x28/+0x30 —
//!    the same offsets W3.6 already writes — and that they come either from
//!    `STARTUPINFOW` (+0x50/+0x58/+0x60, under `STARTF_USESTDHANDLES`) or from
//!    the **parent's own** `PEB->ProcessParameters`.
//! 7. `PROCESS_INFORMATION.dwProcessId/dwThreadId` come from the *output*
//!    `PsAttributeClientId`, not from a return value.
//! 8. `GetExitCodeProcess` is exactly one
//!    `NtQueryInformationProcess(ProcessBasicInformation)` and reads
//!    `ExitStatus` from the first dword of a 0x30-byte buffer.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use exemu_core::ImportSymbol;
use exemu_os::process::{
    pp, ps_attr, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, PROCESS_CREATE_FLAGS_SUSPENDED,
    SSDT_NT_CREATE_USER_PROCESS, SSDT_NT_QUERY_INFORMATION_PROCESS,
    THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

// ---------------------------------------------------------------------------
// Byte-level recovery
// ---------------------------------------------------------------------------

/// One pinned DLL's `.text` plus the lookups the assertions need.
struct Dll {
    code: Vec<u8>,
    text_rva: u32,
    /// Sorted `.pdata` function ranges.
    funcs: Vec<(u32, u32)>,
    exports: std::collections::BTreeMap<String, u32>,
    /// Imported symbol → its IAT slot RVA.
    imports: std::collections::BTreeMap<String, u32>,
}

impl Dll {
    fn open(file: &str) -> Option<Dll> {
        let bytes = std::fs::read(std::path::Path::new(WINE_DLLS).join(file)).ok()?;
        let image = exemu_loader::parse(&bytes).unwrap_or_else(|e| panic!("{file} parses: {e}"));
        assert!(image.is_64bit, "the pinned {file} must be PE32+");
        let text = image
            .sections
            .iter()
            .find(|s| s.name == ".text" && s.executable)
            .unwrap_or_else(|| panic!("{file} has an executable .text"));
        let mut funcs: Vec<(u32, u32)> =
            image.function_table.iter().map(|f| (f.begin_rva, f.end_rva)).collect();
        funcs.sort_unstable();
        let exports = image
            .exports
            .iter()
            .filter(|e| e.forwarder.is_none())
            .filter_map(|e| e.name.clone().map(|n| (n, e.rva)))
            .collect();
        let imports = image
            .imports
            .iter()
            .filter_map(|i| match &i.symbol {
                ImportSymbol::Named(n) => Some((n.clone(), i.iat_rva)),
                _ => None,
            })
            .collect();
        Some(Dll { code: text.data.clone(), text_rva: text.rva, funcs, exports, imports })
    }

    fn export(&self, name: &str) -> u32 {
        *self.exports.get(name).unwrap_or_else(|| panic!("the pinned DLL exports {name}"))
    }

    fn import(&self, name: &str) -> u32 {
        *self.imports.get(name).unwrap_or_else(|| panic!("the pinned DLL imports {name}"))
    }

    /// The `.pdata` range containing `rva`.
    fn func_of(&self, rva: u32) -> (u32, u32) {
        *self
            .funcs
            .iter()
            .find(|(b, e)| rva >= *b && rva < *e)
            .unwrap_or_else(|| panic!("{rva:#x} lies in a .pdata function"))
    }

    /// The `.text` bytes of the function containing `rva`.
    fn body(&self, rva: u32) -> &[u8] {
        let (b, e) = self.func_of(rva);
        let lo = (b - self.text_rva) as usize;
        let hi = ((e - self.text_rva) as usize).min(self.code.len());
        &self.code[lo..hi]
    }

    /// How many times `needle` occurs in the whole `.text`.
    fn count(&self, needle: &[u8]) -> usize {
        count_in(&self.code, needle)
    }

    /// RVAs of every `call qword ptr [rip+disp32]` in `.text` that resolves to
    /// `iat_rva`.
    fn call_sites(&self, iat_rva: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 6 <= self.code.len() {
            if self.code[i] == 0xFF && self.code[i + 1] == 0x15 {
                let disp = i32::from_le_bytes(self.code[i + 2..i + 6].try_into().unwrap());
                let next = self.text_rva as i64 + i as i64 + 6;
                if u32::try_from(next + disp as i64) == Ok(iat_rva) {
                    out.push(self.text_rva + i as u32);
                }
            }
            i += 1;
        }
        out
    }

    /// The SSDT index in an `Nt*` stub: `4C 8B D1  B8 <imm32>`
    /// (`mov r10,rcx; mov eax,N`).
    fn ssdt_index(&self, name: &str) -> u32 {
        let rva = self.export(name);
        let off = (rva - self.text_rva) as usize;
        let stub = &self.code[off..off + 16];
        assert_eq!(&stub[..3], &[0x4C, 0x8B, 0xD1], "{name} opens with mov r10,rcx");
        assert_eq!(stub[3], 0xB8, "{name} then loads the index into eax");
        u32::from_le_bytes(stub[4..8].try_into().unwrap())
    }
}

fn count_in(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// The pinned DLL set is git-ignored; skip cleanly when it is absent.
fn dlls() -> Option<(Dll, Dll)> {
    match (Dll::open("kernelbase.dll"), Dll::open("ntdll.dll")) {
        (Some(kb), Some(nt)) => Some((kb, nt)),
        _ => {
            eprintln!("SKIP: {WINE_DLLS}/{{kernelbase,ntdll}}.dll not present (git-ignored)");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// 1. The syscalls
// ---------------------------------------------------------------------------

/// The two SSDT indices the child-process path rides on, read out of the pinned
/// ntdll's own stubs. A drift in either silently routes child creation — or
/// `GetExitCodeProcess` — to `STATUS_NOT_IMPLEMENTED`.
#[test]
fn the_ssdt_indices_come_from_the_pinned_ntdll() {
    let Some((_, nt)) = dlls() else { return };
    assert_eq!(
        nt.ssdt_index("NtCreateUserProcess"),
        SSDT_NT_CREATE_USER_PROCESS,
        "NtCreateUserProcess SSDT index"
    );
    assert_eq!(
        nt.ssdt_index("NtQueryInformationProcess"),
        SSDT_NT_QUERY_INFORMATION_PROCESS,
        "NtQueryInformationProcess SSDT index"
    );
    // The resume that actually starts a child is the same slot W2.9 pinned.
    assert_eq!(nt.ssdt_index("NtResumeThread"), 0x52, "NtResumeThread SSDT index");
}

/// `CreateProcessW` reaches `NtCreateUserProcess` from exactly one place, and
/// that place always asks for a **suspended** initial thread. This is the whole
/// justification for exemu's run-on-resume model: a child that ran at create
/// time would run before the guest could ever have asked it not to.
#[test]
fn kernelbase_creates_every_child_suspended() {
    let Some((kb, _)) = dlls() else { return };
    let iat = kb.import("NtCreateUserProcess");
    let sites = kb.call_sites(iat);
    assert_eq!(sites.len(), 1, "exactly one NtCreateUserProcess call site: {sites:#x?}");
    let body = kb.body(sites[0]);

    // ThreadFlags is argument 8 (0-based 7), i.e. the outgoing slot [rsp+0x38]:
    //   C7 44 24 38 01 00 00 00   movl $0x1, 0x38(%rsp)
    let mut thread_flags = [0xC7u8, 0x44, 0x24, 0x38, 0, 0, 0, 0];
    thread_flags[4..].copy_from_slice(&(THREAD_CREATE_FLAGS_CREATE_SUSPENDED as u32).to_le_bytes());
    assert_eq!(
        count_in(body, &thread_flags),
        1,
        "create_nt_process stores ThreadFlags = THREAD_CREATE_FLAGS_CREATE_SUSPENDED"
    );

    // Both desired-access masks are PROCESS/THREAD_ALL_ACCESS (0x1FFFFF), loaded
    // back to back into r9d and r8d.
    assert_eq!(
        count_in(body, &[0x41, 0xB9, 0xFF, 0xFF, 0x1F, 0x00, 0x41, 0xB8, 0xFF, 0xFF, 0x1F, 0x00]),
        1,
        "ProcessDesiredAccess and ThreadDesiredAccess are both 0x1FFFFF"
    );
}

/// The `ProcessFlags` bits, recovered from how `CreateProcessInternalW` composes
/// them out of its own arguments.
#[test]
fn the_process_flags_bits_are_the_ones_kernelbase_composes() {
    let Some((kb, _)) = dlls() else { return };
    let cpiw = kb.body(kb.export("CreateProcessInternalW"));

    // `esi` holds `bInheritHandles != 0`; the flag word starts as `esi << 2`,
    // and `edi` is then loaded with dwCreationFlags (arg6, home slot 0x630):
    //   C1 E6 02              shll $0x2, %esi
    //   89 F0                 movl %esi, %eax
    //   8B BC 24 30 06 00 00  movl 0x630(%rsp), %edi
    assert_eq!(
        count_in(cpiw, &[0xC1, 0xE6, 0x02, 0x89, 0xF0, 0x8B, 0xBC, 0x24, 0x30, 0x06, 0x00, 0x00]),
        1,
        "the inherit-handles bit is bInheritHandles shifted left by 2"
    );
    assert_eq!(
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 1 << 2,
        "…so PROCESS_CREATE_FLAGS_INHERIT_HANDLES is bit 2"
    );

    // …and the suspend bit is `|= 0x200` guarded by dwCreationFlags & 4
    // (CREATE_SUSPENDED):
    //   80 CC 02     orb $0x2, %ah        (eax |= 0x200)
    //   83 E7 04     andl $0x4, %edi      (CREATE_SUSPENDED)
    //   0F 45 F0     cmovnel %eax, %esi
    assert_eq!(
        count_in(cpiw, &[0x80, 0xCC, 0x02, 0x83, 0xE7, 0x04, 0x0F, 0x45, 0xF0]),
        1,
        "CREATE_SUSPENDED sets ProcessFlags bit 9"
    );
    assert_eq!(PROCESS_CREATE_FLAGS_SUSPENDED, 0x200);

    // The receiving end: create_nt_process reads that word from its argument
    // home slot (0x2e0) into NtCreateUserProcess's ProcessFlags argument
    // ([rsp+0x30]) and separately tests bit 2 before emitting the handle list.
    let cnp = kb.body(kb.call_sites(kb.import("NtCreateUserProcess"))[0]);
    assert_eq!(
        count_in(cnp, &[0x8B, 0x84, 0x24, 0xE0, 0x02, 0x00, 0x00]),
        1,
        "create_nt_process forwards its flags argument as ProcessFlags"
    );
    let mut inherit_test = [0xF6u8, 0x84, 0x24, 0xE0, 0x02, 0x00, 0x00, 0];
    inherit_test[7] = PROCESS_CREATE_FLAGS_INHERIT_HANDLES as u8;
    assert_eq!(
        count_in(cnp, &inherit_test),
        1,
        "the handle-list attribute is guarded by ProcessFlags bit 2"
    );
}

// ---------------------------------------------------------------------------
// 2. PS_ATTRIBUTE_LIST
// ---------------------------------------------------------------------------

/// The attribute-list shape and the exact set of attribute numbers this
/// kernelbase emits. exemu honours ImageName / ClientId / ImageInfo, refuses
/// DebugPort / JobList / Token / a foreign ParentProcess / a foreign
/// MachineType / an explicit HandleList, and skips nothing else — which is only
/// safe as long as *nothing else* is emitted.
#[test]
fn the_attribute_list_shape_and_set_are_the_ones_kernelbase_emits() {
    let Some((kb, _)) = dlls() else { return };
    let site = kb.call_sites(kb.import("NtCreateUserProcess"))[0];
    let (fn_begin, _) = kb.func_of(site);
    let body = kb.body(site);

    // TotalLength = 8 + count * 32 — `shlq $0x5` then `addq $0x8` on the count.
    assert_eq!(count_in(body, &[0x48, 0xC1, 0xE0, 0x05]), 1, "entries are 32 bytes apart");
    assert_eq!(count_in(body, &[0x48, 0x83, 0xC0, 0x08]), 1, "the list header is 8 bytes");
    assert_eq!(ps_attr::ENTRY_SIZE, 0x20);
    assert_eq!(ps_attr::FIRST, 0x08);
    assert_eq!(ps_attr::TOTAL_LENGTH, 0x00);

    // Collect every attribute number kernelbase writes. Three are inline
    // immediates (`mov qword [rsp+disp32], imm32`) and the rest are 16-byte
    // `{Attribute, Size}` pairs loaded from `.rdata` with `movdqu`.
    let mut numbers: std::collections::BTreeSet<u64> = Default::default();
    let mut sizes: std::collections::BTreeMap<u64, u64> = Default::default();

    let mut i = 0usize;
    while i + 12 <= body.len() {
        // 48 C7 84 {24|14} <disp32> <imm32> — the SIB byte is 0x24 for a plain
        // [rsp+disp32] and 0x14 when the entry index is carried in rdx.
        if body[i] == 0x48 && body[i + 1] == 0xC7 && body[i + 2] == 0x84 && (body[i + 3] == 0x24 || body[i + 3] == 0x14) {
            let disp = u32::from_le_bytes(body[i + 4..i + 8].try_into().unwrap()) as u64;
            let imm = u32::from_le_bytes(body[i + 8..i + 12].try_into().unwrap()) as u64;
            // Only the `Attribute` slot of an entry matters — the list starts at
            // rsp+0x140, so its first entry's Attribute is at rsp+0x148 and the
            // indexed stores use the same displacement plus rdx.
            if disp == 0x148 && imm != 0 {
                numbers.insert(imm & ps_attr::NUMBER_MASK);
            }
            i += 12;
            continue;
        }
        i += 1;
    }
    let mut i = 0usize;
    while i + 8 <= body.len() {
        // F3 0F 6F 05 <disp32> — movdqu xmm0, [rip+disp32]
        if body[i..i + 4] == [0xF3, 0x0F, 0x6F, 0x05] {
            let disp = i32::from_le_bytes(body[i + 4..i + 8].try_into().unwrap());
            let target = (fn_begin as i64 + i as i64 + 8 + disp as i64) as u32;
            let pair = read_rdata16(target);
            numbers.insert(pair.0 & ps_attr::NUMBER_MASK);
            sizes.insert(pair.0 & ps_attr::NUMBER_MASK, pair.1);
            i += 8;
            continue;
        }
        i += 1;
    }

    let expected: std::collections::BTreeSet<u64> = [
        ps_attr::PARENT_PROCESS,
        ps_attr::DEBUG_PORT,
        ps_attr::TOKEN,
        ps_attr::CLIENT_ID,
        ps_attr::IMAGE_NAME,
        ps_attr::IMAGE_INFO,
        ps_attr::HANDLE_LIST,
        ps_attr::JOB_LIST,
        ps_attr::MACHINE_TYPE,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        numbers, expected,
        "the pinned kernelbase emits exactly the attribute numbers exemu accounts for; \
         a new one here means exemu is silently skipping something"
    );

    // The two output attributes' declared sizes are the structures exemu writes.
    assert_eq!(sizes.get(&ps_attr::CLIENT_ID), Some(&0x10), "CLIENT_ID is 16 bytes");
    assert_eq!(
        sizes.get(&ps_attr::IMAGE_INFO),
        Some(&0x40),
        "SECTION_IMAGE_INFORMATION is 0x40 bytes"
    );
    // …and they are written into `RTL_USER_PROCESS_INFORMATION` at +0x18/+0x28,
    // right after the two handles the syscall's own out-parameters fill.
    assert_eq!(count_in(body, &[0x49, 0x8D, 0x44, 0x24, 0x18]), 1, "ClientId at rpi+0x18");
    assert_eq!(count_in(body, &[0x49, 0x8D, 0x44, 0x24, 0x28]), 1, "ImageInformation at rpi+0x28");
}

/// Read the 16-byte `{Attribute, Size}` pair at a `.rdata` RVA of kernelbase.
fn read_rdata16(rva: u32) -> (u64, u64) {
    let bytes = std::fs::read(std::path::Path::new(WINE_DLLS).join("kernelbase.dll")).unwrap();
    let image = exemu_loader::parse(&bytes).unwrap();
    for s in &image.sections {
        let end = s.rva + s.virtual_size.max(s.data.len() as u32);
        if rva >= s.rva && rva + 16 <= end {
            let off = (rva - s.rva) as usize;
            let a = u64::from_le_bytes(s.data[off..off + 8].try_into().unwrap());
            let b = u64::from_le_bytes(s.data[off + 8..off + 16].try_into().unwrap());
            return (a, b);
        }
    }
    panic!("{rva:#x} is not inside a kernelbase section");
}

/// **`PS_CREATE_INFO` is uninitialised stack.** `create_nt_process` passes the
/// address of `rsp+0xe0` as `CreateInfo`, and that displacement appears in the
/// whole function exactly once — in the `lea` that takes the address. Nothing
/// writes `Size`, nothing writes `State`. exemu must therefore never read it,
/// and this assertion is what will notice if a future pinned build starts
/// filling it in.
#[test]
fn ps_create_info_is_never_initialised() {
    let Some((kb, _)) = dlls() else { return };
    let body = kb.body(kb.call_sites(kb.import("NtCreateUserProcess"))[0]);
    // Every `[rsp+0xe0]` reference, whatever the register: ModRM mod=10, rm=100
    // (SIB), SIB = 0x24 (base rsp, no index), disp32 = 0xe0. The ModRM `reg`
    // field varies with the register, so all eight encodings are counted.
    let refs: usize = [0x84u8, 0x8C, 0x94, 0x9C, 0xA4, 0xAC, 0xB4, 0xBC]
        .iter()
        .map(|&modrm| count_in(body, &[modrm, 0x24, 0xE0, 0x00, 0x00, 0x00]))
        .sum();
    assert_eq!(
        refs, 1,
        "create_nt_process touches its PS_CREATE_INFO slot exactly once — to take \
         its address. If this is ever more than one, exemu's decision to ignore \
         CreateInfo is no longer safe."
    );
}

// ---------------------------------------------------------------------------
// 3. RTL_USER_PROCESS_PARAMETERS
// ---------------------------------------------------------------------------

/// The std-handle trio, and where the values come from. This is the offset set
/// `exemu_os::process::pp` reads and `exemu_os::dll` (W3.6) writes; recovering
/// it from kernelbase's own stores is what makes "reuse it rather than
/// re-derive it" checkable rather than a claim.
#[test]
fn the_std_handles_land_at_the_w36_offsets() {
    let Some((kb, _)) = dlls() else { return };
    let cpiw = kb.body(kb.export("CreateProcessInternalW"));

    // STARTF_USESTDHANDLES is bit 8 of STARTUPINFOW.dwFlags (@0x3c), tested as
    // `testb $1, 0x3d(%rsi)`.
    assert!(
        count_in(cpiw, &[0xF6, 0x46, 0x3D, 0x01]) > 0,
        "STARTF_USESTDHANDLES (0x100) is tested at STARTUPINFOW+0x3d"
    );

    // With it set, hStdInput/hStdOutput/hStdError (STARTUPINFOW +0x50/+0x58/
    // +0x60) are copied straight into the params at +0x20/+0x28/+0x30. The six
    // instructions are contiguous, so one exact sequence pins all three pairs.
    let mut want: Vec<u8> = Vec::new();
    for (si, ppo) in [
        (0x50u8, pp::STD_INPUT as u8),
        (0x58, pp::STD_OUTPUT as u8),
        (0x60, pp::STD_ERROR as u8),
    ] {
        want.extend_from_slice(&[0x48, 0x8B, 0x46, si]); // mov rax, [rsi+si]
        want.extend_from_slice(&[0x49, 0x89, 0x44, 0x24, ppo]); // mov [r12+ppo], rax
    }
    assert_eq!(
        kb.count(&want),
        1,
        "STARTUPINFOW +0x50/+0x58/+0x60 → RTL_USER_PROCESS_PARAMETERS +{:#x}/+{:#x}/+{:#x}",
        pp::STD_INPUT,
        pp::STD_OUTPUT,
        pp::STD_ERROR
    );

    // Without it, the child inherits the PARENT's own std handles — read through
    // `gs:[0x30]` → PEB (+0x60) → ProcessParameters (+0x20) → StandardInput
    // (+0x20). The doubled `movq 0x20(%rdx), %rdx` is that two-step walk, and it
    // is why a Wine-boot parent whose params carry exemu's console sentinels
    // hands them to its child for free (roadmap W3.4).
    assert_eq!(
        count_in(cpiw, &[0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x52, 0x20]),
        1,
        "the default is the parent's PEB->ProcessParameters->StandardInput"
    );
    assert_eq!(pp::STD_INPUT, 0x20, "…which is also the ProcessParameters offset in the PEB");
}

/// The deep params offsets exemu reads out of the block Wine's ntdll built:
/// `EnvironmentSize` at +0x3f0 and the 0x410-byte header. Both were recovered
/// the hard way in W3.6; re-deriving them here keeps the child-process reader
/// honest about using the *same* struct rather than a lookalike.
#[test]
fn the_environment_size_offset_is_the_one_ntdll_reads() {
    let Some((_, nt)) = dlls() else { return };
    // init_user_process_params: `movq 0x3f0(%rdx), %rsi` — the EnvironmentSize
    // read that was the original W3.6 boot blocker.
    assert_eq!(
        nt.count(&[0x48, 0x8B, 0xB2, 0xF0, 0x03, 0x00, 0x00]),
        1,
        "ntdll reads EnvironmentSize at +{:#x}",
        pp::ENVIRONMENT_SIZE
    );
    assert_eq!(pp::ENVIRONMENT_SIZE, 0x3F0);
    // alloc_process_params lays the buffer area at +0x410 — the header size.
    assert_eq!(
        nt.count(&[0x48, 0x8D, 0x88, 0x10, 0x04, 0x00, 0x00]),
        1,
        "the RTL_USER_PROCESS_PARAMETERS header is 0x410 bytes"
    );
}

// ---------------------------------------------------------------------------
// 4. What the parent reads back
// ---------------------------------------------------------------------------

/// `PROCESS_INFORMATION.dwProcessId`/`dwThreadId` are the **output**
/// `PsAttributeClientId`, copied out of `RTL_USER_PROCESS_INFORMATION.ClientId`
/// (+0x18/+0x20). If exemu did not fill that attribute, every child would report
/// pid 0 — with `CreateProcessW` still returning TRUE.
#[test]
fn the_reported_ids_come_from_the_client_id_attribute() {
    let Some((kb, _)) = dlls() else { return };
    let cpiw = kb.body(kb.export("CreateProcessInternalW"));
    // rpi lives at rsp+0x120, so ClientId.UniqueProcess is rsp+0x138 and
    // UniqueThread rsp+0x140; both are narrowed into PROCESS_INFORMATION +0x10
    // and +0x14.
    assert_eq!(
        count_in(
            cpiw,
            &[
                0x48, 0x8B, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00, // mov rax, [rsp+0x138]
                0x89, 0x43, 0x10, // mov [rbx+0x10], eax   (dwProcessId)
                0x48, 0x8B, 0x84, 0x24, 0x40, 0x01, 0x00, 0x00, // mov rax, [rsp+0x140]
                0x89, 0x43, 0x14, // mov [rbx+0x14], eax   (dwThreadId)
            ]
        ),
        1,
        "dwProcessId/dwThreadId at PROCESS_INFORMATION +0x10/+0x14 come from ClientId"
    );
    // The handle pair is copied together as one 16-byte move into +0x00/+0x08.
    assert_eq!(
        count_in(cpiw, &[0xF3, 0x0F, 0x6F, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00, 0x0F, 0x11, 0x00]),
        1,
        "hProcess/hThread at PROCESS_INFORMATION +0x00/+0x08"
    );
}

/// `GetExitCodeProcess` is *only* a
/// `NtQueryInformationProcess(ProcessBasicInformation)` into a 0x30-byte buffer,
/// whose first dword it returns. That is why exemu implements exactly that class
/// and leaves every other one unimplemented.
#[test]
fn get_exit_code_process_is_one_process_basic_information_query() {
    let Some((kb, _)) = dlls() else { return };
    let gec = kb.export("GetExitCodeProcess");
    let (begin, end) = kb.func_of(gec);
    assert_eq!(begin, gec, "GetExitCodeProcess starts its own .pdata function");
    let body = kb.body(gec);

    // Exactly one call, and it goes to NtQueryInformationProcess.
    let iat = kb.import("NtQueryInformationProcess");
    let calls: Vec<u32> = kb.call_sites(iat).into_iter().filter(|r| *r >= begin && *r < end).collect();
    assert_eq!(calls.len(), 1, "one NtQueryInformationProcess call: {calls:#x?}");

    // ProcessInformationLength = 0x30 (r9d), ProcessInformationClass = 0 (edx).
    assert_eq!(
        count_in(body, &[0x41, 0xB9, 0x30, 0x00, 0x00, 0x00]),
        1,
        "PROCESS_BASIC_INFORMATION is 0x30 bytes"
    );
    assert_eq!(count_in(body, &[0x31, 0xD2]), 1, "ProcessBasicInformation is class 0");
    // …and `ExitStatus` is the first dword of that buffer.
    assert_eq!(
        count_in(body, &[0x8B, 0x44, 0x24, 0x30, 0x89, 0x06]),
        1,
        "the exit code is PROCESS_BASIC_INFORMATION.ExitStatus at +0x00"
    );
}

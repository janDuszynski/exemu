use exemu_core::ImportSymbol;
use exemu_os::process::{
    pp, ps_attr, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, PROCESS_CREATE_FLAGS_SUSPENDED,
    SSDT_NT_CREATE_USER_PROCESS, SSDT_NT_QUERY_INFORMATION_PROCESS,
    THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
};

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

struct Dll {
    code: Vec<u8>,
    text_rva: u32,
    funcs: Vec<(u32, u32)>,
    exports: std::collections::BTreeMap<String, u32>,
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

    fn func_of(&self, rva: u32) -> (u32, u32) {
        *self
            .funcs
            .iter()
            .find(|(b, e)| rva >= *b && rva < *e)
            .unwrap_or_else(|| panic!("{rva:#x} lies in a .pdata function"))
    }

    fn body(&self, rva: u32) -> &[u8] {
        let (b, e) = self.func_of(rva);
        let lo = (b - self.text_rva) as usize;
        let hi = ((e - self.text_rva) as usize).min(self.code.len());
        &self.code[lo..hi]
    }

    fn count(&self, needle: &[u8]) -> usize {
        count_in(&self.code, needle)
    }

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

fn dlls() -> Option<(Dll, Dll)> {
    match (Dll::open("kernelbase.dll"), Dll::open("ntdll.dll")) {
        (Some(kb), Some(nt)) => Some((kb, nt)),
        _ => {
            eprintln!("SKIP: {WINE_DLLS}/{{kernelbase,ntdll}}.dll not present (git-ignored)");
            None
        }
    }
}

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
    assert_eq!(nt.ssdt_index("NtResumeThread"), 0x52, "NtResumeThread SSDT index");
}

#[test]
fn kernelbase_creates_every_child_suspended() {
    let Some((kb, _)) = dlls() else { return };
    let iat = kb.import("NtCreateUserProcess");
    let sites = kb.call_sites(iat);
    assert_eq!(sites.len(), 1, "exactly one NtCreateUserProcess call site: {sites:#x?}");
    let body = kb.body(sites[0]);

    let mut thread_flags = [0xC7u8, 0x44, 0x24, 0x38, 0, 0, 0, 0];
    thread_flags[4..].copy_from_slice(&(THREAD_CREATE_FLAGS_CREATE_SUSPENDED as u32).to_le_bytes());
    assert_eq!(
        count_in(body, &thread_flags),
        1,
        "create_nt_process stores ThreadFlags = THREAD_CREATE_FLAGS_CREATE_SUSPENDED"
    );

    assert_eq!(
        count_in(body, &[0x41, 0xB9, 0xFF, 0xFF, 0x1F, 0x00, 0x41, 0xB8, 0xFF, 0xFF, 0x1F, 0x00]),
        1,
        "ProcessDesiredAccess and ThreadDesiredAccess are both 0x1FFFFF"
    );
}

#[test]
fn the_process_flags_bits_are_the_ones_kernelbase_composes() {
    let Some((kb, _)) = dlls() else { return };
    let cpiw = kb.body(kb.export("CreateProcessInternalW"));

    assert_eq!(
        count_in(cpiw, &[0xC1, 0xE6, 0x02, 0x89, 0xF0, 0x8B, 0xBC, 0x24, 0x30, 0x06, 0x00, 0x00]),
        1,
        "the inherit-handles bit is bInheritHandles shifted left by 2"
    );
    assert_eq!(
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 1 << 2,
        "…so PROCESS_CREATE_FLAGS_INHERIT_HANDLES is bit 2"
    );

    assert_eq!(
        count_in(cpiw, &[0x80, 0xCC, 0x02, 0x83, 0xE7, 0x04, 0x0F, 0x45, 0xF0]),
        1,
        "CREATE_SUSPENDED sets ProcessFlags bit 9"
    );
    assert_eq!(PROCESS_CREATE_FLAGS_SUSPENDED, 0x200);

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

#[test]
fn the_attribute_list_shape_and_set_are_the_ones_kernelbase_emits() {
    let Some((kb, _)) = dlls() else { return };
    let site = kb.call_sites(kb.import("NtCreateUserProcess"))[0];
    let (fn_begin, _) = kb.func_of(site);
    let body = kb.body(site);

    assert_eq!(count_in(body, &[0x48, 0xC1, 0xE0, 0x05]), 1, "entries are 32 bytes apart");
    assert_eq!(count_in(body, &[0x48, 0x83, 0xC0, 0x08]), 1, "the list header is 8 bytes");
    assert_eq!(ps_attr::ENTRY_SIZE, 0x20);
    assert_eq!(ps_attr::FIRST, 0x08);
    assert_eq!(ps_attr::TOTAL_LENGTH, 0x00);

    let mut numbers: std::collections::BTreeSet<u64> = Default::default();
    let mut sizes: std::collections::BTreeMap<u64, u64> = Default::default();

    let mut i = 0usize;
    while i + 12 <= body.len() {
        if body[i] == 0x48 && body[i + 1] == 0xC7 && body[i + 2] == 0x84 && (body[i + 3] == 0x24 || body[i + 3] == 0x14) {
            let disp = u32::from_le_bytes(body[i + 4..i + 8].try_into().unwrap()) as u64;
            let imm = u32::from_le_bytes(body[i + 8..i + 12].try_into().unwrap()) as u64;
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

    assert_eq!(sizes.get(&ps_attr::CLIENT_ID), Some(&0x10), "CLIENT_ID is 16 bytes");
    assert_eq!(
        sizes.get(&ps_attr::IMAGE_INFO),
        Some(&0x40),
        "SECTION_IMAGE_INFORMATION is 0x40 bytes"
    );
    assert_eq!(count_in(body, &[0x49, 0x8D, 0x44, 0x24, 0x18]), 1, "ClientId at rpi+0x18");
    assert_eq!(count_in(body, &[0x49, 0x8D, 0x44, 0x24, 0x28]), 1, "ImageInformation at rpi+0x28");
}

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

#[test]
fn ps_create_info_is_never_initialised() {
    let Some((kb, _)) = dlls() else { return };
    let body = kb.body(kb.call_sites(kb.import("NtCreateUserProcess"))[0]);
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

#[test]
fn the_std_handles_land_at_the_w36_offsets() {
    let Some((kb, _)) = dlls() else { return };
    let cpiw = kb.body(kb.export("CreateProcessInternalW"));

    assert!(
        count_in(cpiw, &[0xF6, 0x46, 0x3D, 0x01]) > 0,
        "STARTF_USESTDHANDLES (0x100) is tested at STARTUPINFOW+0x3d"
    );

    let mut want: Vec<u8> = Vec::new();
    for (si, ppo) in [
        (0x50u8, pp::STD_INPUT as u8),
        (0x58, pp::STD_OUTPUT as u8),
        (0x60, pp::STD_ERROR as u8),
    ] {
        want.extend_from_slice(&[0x48, 0x8B, 0x46, si]);
        want.extend_from_slice(&[0x49, 0x89, 0x44, 0x24, ppo]);
    }
    assert_eq!(
        kb.count(&want),
        1,
        "STARTUPINFOW +0x50/+0x58/+0x60 → RTL_USER_PROCESS_PARAMETERS +{:#x}/+{:#x}/+{:#x}",
        pp::STD_INPUT,
        pp::STD_OUTPUT,
        pp::STD_ERROR
    );

    assert_eq!(
        count_in(cpiw, &[0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x52, 0x20]),
        1,
        "the default is the parent's PEB->ProcessParameters->StandardInput"
    );
    assert_eq!(pp::STD_INPUT, 0x20, "…which is also the ProcessParameters offset in the PEB");
}

#[test]
fn the_environment_size_offset_is_the_one_ntdll_reads() {
    let Some((_, nt)) = dlls() else { return };
    assert_eq!(
        nt.count(&[0x48, 0x8B, 0xB2, 0xF0, 0x03, 0x00, 0x00]),
        1,
        "ntdll reads EnvironmentSize at +{:#x}",
        pp::ENVIRONMENT_SIZE
    );
    assert_eq!(pp::ENVIRONMENT_SIZE, 0x3F0);
    assert_eq!(
        nt.count(&[0x48, 0x8D, 0x88, 0x10, 0x04, 0x00, 0x00]),
        1,
        "the RTL_USER_PROCESS_PARAMETERS header is 0x410 bytes"
    );
}

#[test]
fn the_reported_ids_come_from_the_client_id_attribute() {
    let Some((kb, _)) = dlls() else { return };
    let cpiw = kb.body(kb.export("CreateProcessInternalW"));
    assert_eq!(
        count_in(
            cpiw,
            &[
                0x48, 0x8B, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00,
                0x89, 0x43, 0x10,
                0x48, 0x8B, 0x84, 0x24, 0x40, 0x01, 0x00, 0x00,
                0x89, 0x43, 0x14,
            ]
        ),
        1,
        "dwProcessId/dwThreadId at PROCESS_INFORMATION +0x10/+0x14 come from ClientId"
    );
    assert_eq!(
        count_in(cpiw, &[0xF3, 0x0F, 0x6F, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00, 0x0F, 0x11, 0x00]),
        1,
        "hProcess/hThread at PROCESS_INFORMATION +0x00/+0x08"
    );
}

#[test]
fn get_exit_code_process_is_one_process_basic_information_query() {
    let Some((kb, _)) = dlls() else { return };
    let gec = kb.export("GetExitCodeProcess");
    let (begin, end) = kb.func_of(gec);
    assert_eq!(begin, gec, "GetExitCodeProcess starts its own .pdata function");
    let body = kb.body(gec);

    let iat = kb.import("NtQueryInformationProcess");
    let calls: Vec<u32> = kb.call_sites(iat).into_iter().filter(|r| *r >= begin && *r < end).collect();
    assert_eq!(calls.len(), 1, "one NtQueryInformationProcess call: {calls:#x?}");

    assert_eq!(
        count_in(body, &[0x41, 0xB9, 0x30, 0x00, 0x00, 0x00]),
        1,
        "PROCESS_BASIC_INFORMATION is 0x30 bytes"
    );
    assert_eq!(count_in(body, &[0x31, 0xD2]), 1, "ProcessBasicInformation is class 0");
    assert_eq!(
        count_in(body, &[0x8B, 0x44, 0x24, 0x30, 0x89, 0x06]),
        1,
        "the exit code is PROCESS_BASIC_INFORMATION.ExitStatus at +0x00"
    );
}

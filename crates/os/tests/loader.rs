//! Two-DLL dependency-order load + `PEB.Ldr` materialization (roadmap W0.6).
//!
//! The de-risk fixture: an exe `LoadLibrary`s **A.dll**, which *imports* a
//! function from **B.dll**. The real in-process loader must
//!
//!   1. recursively load B (the dependency) before A resolves its imports, so
//!      A's IAT slot binds to B's **real guest code address** (not a thunk);
//!   2. record both modules in the module table and thread each onto the three
//!      `PEB.Ldr` doubly-linked lists (InLoadOrder / InMemoryOrder /
//!      InInitializationOrder) with correct public field offsets;
//!   3. return a real guest export address from `GetProcAddress`.
//!
//! Everything is driven through the public `WinOs` surface exactly as the
//! interpreter/app would, then the loader lists are walked out of guest memory
//! and their contents asserted.

use exemu_core::{CpuState, Hooks, ImportSymbol, Memory, Perm, Region};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

// ---- tiny byte helpers -----------------------------------------------------

fn put_u16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(f: &mut [u8], at: usize, v: u64) {
    f[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

const IMAGE_BASE: u64 = 0x1_8000_0000;
const PE_OFF: usize = 0x80;
const OPT_HDR_SIZE: usize = 112 + 16 * 8;
const SEC_ALIGN: u32 = 0x1000;
const FILE_ALIGN: u32 = 0x200;

struct Sec<'a> {
    name: &'a [u8],
    rva: u32,
    data: &'a [u8],
    chars: u32,
}

fn align_up(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

/// Assemble a minimal PE32+ file from sections + optional export/import dirs +
/// an entry RVA. Adapted from the loader crate's fixture builder.
fn assemble_pe(
    is_dll: bool,
    secs: &[Sec],
    export_dir: Option<(u32, u32)>,
    import_dir: Option<(u32, u32)>,
    entry_rva: u32,
) -> Vec<u8> {
    // Headers must hold the DOS+PE+optional header and the whole section table;
    // round up to a file-alignment boundary so section raw data never collides
    // with the section table (matters once there are 4+ sections).
    let sec_tbl_end = (PE_OFF + 4 + 20 + OPT_HDR_SIZE + secs.len() * 40) as u32;
    let headers_raw = align_up(sec_tbl_end, FILE_ALIGN);
    let mut raw_ptr = headers_raw;
    let mut placed: Vec<(u32, u32)> = Vec::new();
    for s in secs {
        let raw_size = align_up(s.data.len() as u32, FILE_ALIGN);
        placed.push((raw_ptr, raw_size));
        raw_ptr += raw_size;
    }
    let mut f = vec![0u8; raw_ptr as usize];

    f[0] = b'M';
    f[1] = b'Z';
    put_u32(&mut f, 0x3C, PE_OFF as u32);
    put_u32(&mut f, PE_OFF, 0x0000_4550);
    let coff = PE_OFF + 4;
    put_u16(&mut f, coff, 0x8664); // AMD64
    put_u16(&mut f, coff + 2, secs.len() as u16);
    put_u16(&mut f, coff + 16, OPT_HDR_SIZE as u16);
    let chars = if is_dll { 0x2022 } else { 0x0022 };
    put_u16(&mut f, coff + 18, chars);

    let opt = coff + 20;
    let last = secs.last().unwrap();
    let image_size = align_up(last.rva + last.data.len() as u32, SEC_ALIGN);
    put_u16(&mut f, opt, 0x20B); // PE32+
    put_u32(&mut f, opt + 16, entry_rva);
    put_u64(&mut f, opt + 24, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SEC_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw);
    put_u16(&mut f, opt + 68, 3); // CONSOLE
    put_u32(&mut f, opt + 108, 16); // NumberOfRvaAndSizes

    let dir = |i: usize| opt + 112 + i * 8;
    if let Some((rva, size)) = export_dir {
        put_u32(&mut f, dir(0), rva);
        put_u32(&mut f, dir(0) + 4, size);
    }
    if let Some((rva, size)) = import_dir {
        put_u32(&mut f, dir(1), rva);
        put_u32(&mut f, dir(1) + 4, size);
    }

    let sec_tbl = opt + OPT_HDR_SIZE;
    for (i, s) in secs.iter().enumerate() {
        let at = sec_tbl + i * 40;
        f[at..at + s.name.len()].copy_from_slice(s.name);
        put_u32(&mut f, at + 8, s.data.len() as u32);
        put_u32(&mut f, at + 12, s.rva);
        let (rp, rs) = placed[i];
        put_u32(&mut f, at + 16, rs);
        put_u32(&mut f, at + 20, rp);
        put_u32(&mut f, at + 36, s.chars);
        f[rp as usize..rp as usize + s.data.len()].copy_from_slice(s.data);
    }
    f
}

/// A DLL exporting one function `sym` as real code (RVA 0x2000), with a
/// trivial `ret`-only entry point at RVA 0x3000.
fn build_exporting_dll(dll_name: &str, sym: &str) -> Vec<u8> {
    const EDATA_RVA: u32 = 0x1000;
    const CODE_RVA: u32 = 0x2000;
    const ENTRY_RVA: u32 = 0x3000;

    // Export directory: 1 name, code RVA at CODE_RVA.
    let dir_off = 0u32;
    let eat_off = dir_off + 40;
    let names_off = eat_off + 4;
    let ords_off = names_off + 4;
    let mut pos = ords_off + 2;
    let sym_rva = EDATA_RVA + pos;
    pos += sym.len() as u32 + 1;
    let dllname_rva = EDATA_RVA + pos;
    pos += dll_name.len() as u32 + 1;
    let edata_len = pos;

    let mut ed = vec![0u8; edata_len as usize];
    put_u32(&mut ed, dir_off as usize + 12, dllname_rva);
    put_u32(&mut ed, dir_off as usize + 16, 1); // ordinal base
    put_u32(&mut ed, dir_off as usize + 20, 1); // NumberOfFunctions
    put_u32(&mut ed, dir_off as usize + 24, 1); // NumberOfNames
    put_u32(&mut ed, dir_off as usize + 28, EDATA_RVA + eat_off);
    put_u32(&mut ed, dir_off as usize + 32, EDATA_RVA + names_off);
    put_u32(&mut ed, dir_off as usize + 36, EDATA_RVA + ords_off);
    put_u32(&mut ed, eat_off as usize, CODE_RVA); // code, outside the dir
    put_u32(&mut ed, names_off as usize, sym_rva);
    put_u16(&mut ed, ords_off as usize, 0);
    let so = (sym_rva - EDATA_RVA) as usize;
    ed[so..so + sym.len()].copy_from_slice(sym.as_bytes());
    let dn = (dllname_rva - EDATA_RVA) as usize;
    ed[dn..dn + dll_name.len()].copy_from_slice(dll_name.as_bytes());

    // A .text with the exported function (`ret`, 0xC3) and DllMain (`ret`).
    let text = vec![0xC3u8]; // at CODE_RVA
    let entry = vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]; // mov eax,1; ret (DllMain → TRUE)

    assemble_pe(
        true,
        &[
            Sec { name: b".edata", rva: EDATA_RVA, data: &ed, chars: 0x4000_0040 },
            Sec { name: b".text", rva: CODE_RVA, data: &text, chars: 0x6000_0020 },
            Sec { name: b".init", rva: ENTRY_RVA, data: &entry, chars: 0x6000_0020 },
        ],
        Some((EDATA_RVA, edata_len)),
        None,
        ENTRY_RVA,
    )
}

/// A DLL that imports `sym` from `dep_dll` and exports its own `own_sym` as
/// real code. This is "A.dll" in the fixture: it depends on B.dll.
fn build_importing_dll(dll_name: &str, own_sym: &str, dep_dll: &str, dep_sym: &str) -> Vec<u8> {
    const IDATA_RVA: u32 = 0x1000;
    const EDATA_RVA: u32 = 0x2000;
    const CODE_RVA: u32 = 0x3000;
    const ENTRY_RVA: u32 = 0x4000;

    // --- .idata: import dep_dll!dep_sym ---
    let desc_off = 0u32;
    let ilt_off = 40u32;
    let iat_off = ilt_off + 16;
    let mut pos = iat_off + 16;
    let ibn_off = pos;
    pos += 2 + dep_sym.len() as u32 + 1;
    let dep_name_off = pos;
    pos += dep_dll.len() as u32 + 1;
    let idata_len = pos;
    let mut idata = vec![0u8; idata_len as usize];
    put_u32(&mut idata, desc_off as usize, IDATA_RVA + ilt_off);
    put_u32(&mut idata, desc_off as usize + 12, IDATA_RVA + dep_name_off);
    put_u32(&mut idata, desc_off as usize + 16, IDATA_RVA + iat_off);
    put_u64(&mut idata, ilt_off as usize, (IDATA_RVA + ibn_off) as u64);
    put_u64(&mut idata, iat_off as usize, (IDATA_RVA + ibn_off) as u64);
    let ibn = ibn_off as usize;
    idata[ibn + 2..ibn + 2 + dep_sym.len()].copy_from_slice(dep_sym.as_bytes());
    let dn = dep_name_off as usize;
    idata[dn..dn + dep_dll.len()].copy_from_slice(dep_dll.as_bytes());
    let import_dir_size = 40u32; // one descriptor + null terminator
    let iat_slot_rva = IDATA_RVA + iat_off;

    // --- .edata: export own_sym at CODE_RVA ---
    let dir_off = 0u32;
    let eat_off = dir_off + 40;
    let names_off = eat_off + 4;
    let ords_off = names_off + 4;
    let mut epos = ords_off + 2;
    let sym_rva = EDATA_RVA + epos;
    epos += own_sym.len() as u32 + 1;
    let dllname_rva = EDATA_RVA + epos;
    epos += dll_name.len() as u32 + 1;
    let edata_len = epos;
    let mut ed = vec![0u8; edata_len as usize];
    put_u32(&mut ed, dir_off as usize + 12, dllname_rva);
    put_u32(&mut ed, dir_off as usize + 16, 1);
    put_u32(&mut ed, dir_off as usize + 20, 1);
    put_u32(&mut ed, dir_off as usize + 24, 1);
    put_u32(&mut ed, dir_off as usize + 28, EDATA_RVA + eat_off);
    put_u32(&mut ed, dir_off as usize + 32, EDATA_RVA + names_off);
    put_u32(&mut ed, dir_off as usize + 36, EDATA_RVA + ords_off);
    put_u32(&mut ed, eat_off as usize, CODE_RVA);
    put_u32(&mut ed, names_off as usize, sym_rva);
    put_u16(&mut ed, ords_off as usize, 0);
    let so = (sym_rva - EDATA_RVA) as usize;
    ed[so..so + own_sym.len()].copy_from_slice(own_sym.as_bytes());
    let dnn = (dllname_rva - EDATA_RVA) as usize;
    ed[dnn..dnn + dll_name.len()].copy_from_slice(dll_name.as_bytes());

    let text = vec![0xC3u8];
    let entry = vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];

    let pe = assemble_pe(
        true,
        &[
            Sec { name: b".idata", rva: IDATA_RVA, data: &idata, chars: 0xC000_0040 },
            Sec { name: b".edata", rva: EDATA_RVA, data: &ed, chars: 0x4000_0040 },
            Sec { name: b".text", rva: CODE_RVA, data: &text, chars: 0x6000_0020 },
            Sec { name: b".init", rva: ENTRY_RVA, data: &entry, chars: 0x6000_0020 },
        ],
        Some((EDATA_RVA, edata_len)),
        Some((IDATA_RVA + desc_off, import_dir_size)),
        ENTRY_RVA,
    );
    let _ = iat_slot_rva;
    pe
}

// ---- guest-memory Ldr walk -------------------------------------------------

// PEB_LDR_DATA list-head offsets (64-bit): InLoad 0x10, InMemory 0x20, InInit 0x30.
// LDR_DATA_TABLE_ENTRY link offsets (64-bit): 0x00 / 0x10 / 0x20.
// Field offsets: DllBase 0x30, EntryPoint 0x38, SizeOfImage 0x40,
//                FullDllName 0x48, BaseDllName 0x58.

/// Walk one Ldr list (given head offset in PEB_LDR_DATA and link offset in the
/// entry) and return the DllBase of each threaded module, in list order.
fn walk_bases(mem: &VirtualMemory, ldr: u64, head_off: u64, link_off: u64) -> Vec<u64> {
    let head = ldr + head_off;
    let mut bases = Vec::new();
    let mut cur = mem.read_u64(head).unwrap(); // head.Flink
    let mut guard = 0;
    while cur != head && guard < 64 {
        let entry = cur - link_off;
        bases.push(mem.read_u64(entry + 0x30).unwrap()); // DllBase
        cur = mem.read_u64(cur).unwrap(); // link.Flink
        guard += 1;
    }
    bases
}

/// Read a UNICODE_STRING at `at` into a Rust String (64-bit layout).
fn read_unicode_string(mem: &VirtualMemory, at: u64) -> String {
    let len = mem.read_u16(at).unwrap() as u64;
    let buf = mem.read_u64(at + 8).unwrap();
    let mut s = String::new();
    let mut i = 0;
    while i < len {
        let u = mem.read_u16(buf + i).unwrap();
        s.push(char::from_u32(u as u32).unwrap_or('?'));
        i += 2;
    }
    s
}

fn setup_os() -> (WinOs, VirtualMemory, u64, tempdir::Guard, std::path::PathBuf) {
    let sandbox = tempdir::make();
    let sandbox_root = sandbox.path.clone();
    // Guest C: drive maps to <sandbox>/C.
    std::fs::create_dir_all(sandbox.path.join("C")).unwrap();

    let mut mem = VirtualMemory::new();
    // Regions the OS + fixture touch. dll arena is RWX; peb + heap RW.
    let dll_base = 0x0000_0006_0000_0000u64;
    let dll_size = 0x0080_0000u64;
    let peb_addr = 0x0000_7FFF_0000_2000u64;
    mem.map(Region::new("dlls", dll_base, dll_size, Perm::RWX)).unwrap();
    mem.map(Region::new("peb", peb_addr, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("heap", 0x2_0000_0000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x0000_7EFF_0000_0000, 0x10000, Perm::RW)).unwrap();
    // Fixture stack (STACK sits inside this region).
    mem.map(Region::new("stack", 0x0F_FFF0_0000, 0x0020_0000, Perm::RW)).unwrap();

    let cfg = WinConfig {
        heap_base: 0x2_0000_0000,
        heap_size: 0x10000,
        echo: false,
        is_64bit: true,
        sandbox: sandbox.path.to_string_lossy().into_owned(),
        image_base: IMAGE_BASE,
        image_size: 0x1000,
        image_entry: IMAGE_BASE + 0x1000,
        image_name: "program.exe".into(),
        module_path_w: "C:\\program.exe".into(),
        dll_base,
        dll_size,
        peb_addr,
        peb_ldr_off: 0x18,
        ..WinConfig::default()
    };
    let mut os = WinOs::new(cfg);
    os.init_ldr(&mut mem).unwrap();
    (os, mem, peb_addr, sandbox, sandbox_root)
}

const STACK: u64 = 0x10_0000_0000; // fixture stack
const RET: u64 = 0x1_2345;

/// Drive a kernel32 API through the public `Hooks::intercept` surface exactly
/// as the interpreter would (64-bit register args in Rcx/Rdx/R8), pumping the
/// callback driver so any `DllMain` a `LoadLibrary` triggers runs to
/// completion. `DllMain` bodies (`mov eax,1; ret`) execute as real guest code,
/// surfacing to us as `intercept -> None`; we finish them by popping the return
/// address (mirroring the `ret` the interpreter would run).
fn call_api(os: &mut WinOs, mem: &mut VirtualMemory, cpu: &mut CpuState, api: &str, args: &[u64]) -> u64 {
    use exemu_core::Reg;
    cpu.set_rsp(STACK);
    mem.write_u64(STACK, RET).unwrap();
    let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
    for (i, &a) in args.iter().enumerate() {
        if i < 4 {
            cpu.set_reg(regs[i], a);
        }
    }
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named(api.into()));
    cpu.rip = thunk;
    let mut guard = 0;
    loop {
        let exit = os.intercept(cpu.rip, cpu, mem).unwrap();
        guard += 1;
        assert!(guard < 200, "{api} did not settle");
        match exit {
            Some(exemu_core::Exit::Continue) => {
                if cpu.rip == RET {
                    return cpu.reg(Reg::Rax);
                }
            }
            None => {
                // A guest-code body (a DLL's DllMain) ran; emulate its `ret`.
                let ra = mem.read_u64(cpu.rsp()).unwrap();
                cpu.set_rsp(cpu.rsp() + 8);
                cpu.set_reg(Reg::Rax, 1);
                cpu.rip = ra;
            }
            other => panic!("unexpected exit {other:?}"),
        }
    }
}

/// Write an ASCII string to guest memory and return its pointer.
fn put_str(mem: &mut VirtualMemory, ptr: u64, s: &str) -> u64 {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    mem.write(ptr, &bytes).unwrap();
    ptr
}

#[test]
fn two_dll_dependency_order_load_and_ldr_lists() {
    let (mut os, mut mem, peb_addr, _sandbox, root) = setup_os();

    // Write A.dll (imports B.dll!b_func) and B.dll (exports b_func) into the
    // guest C: drive.
    let a = build_importing_dll("a.dll", "a_func", "b.dll", "b_func");
    let b = build_exporting_dll("b.dll", "b_func");
    // Sanity: both parse and A imports b.dll!b_func.
    let ai = exemu_loader::parse(&a).expect("a.dll parses");
    assert_eq!(ai.imports.len(), 1, "a.dll import count");
    assert_eq!(ai.imports[0].dll, "b.dll");
    assert_eq!(ai.exports.len(), 1, "a.dll export count");
    let bi = exemu_loader::parse(&b).expect("b.dll parses");
    assert_eq!(bi.exports.len(), 1, "b.dll export count");
    std::fs::write(root.join("C").join("a.dll"), &a).unwrap();
    std::fs::write(root.join("C").join("b.dll"), &b).unwrap();

    let mut cpu = CpuState::new();
    // A scratch region for API string arguments.
    let name_ptr = 0x2_0000_0100u64;

    // The exe LoadLibrary("a.dll").
    put_str(&mut mem, name_ptr, "a.dll");
    let a_handle = call_api(&mut os, &mut mem, &mut cpu, "LoadLibraryA", &[name_ptr]);
    assert_ne!(a_handle, 0, "LoadLibrary(a.dll) failed");

    // Ldr = *(PEB + 0x18).
    let ldr = mem.read_u64(peb_addr + 0x18).unwrap();
    assert_ne!(ldr, 0, "PEB.Ldr not published");

    // The three loader lists: InLoad (link 0x00), InMemory (0x10), InInit (0x20).
    let in_load = walk_bases(&mem, ldr, 0x10, 0x00);
    let in_mem = walk_bases(&mem, ldr, 0x20, 0x10);
    let in_init = walk_bases(&mem, ldr, 0x30, 0x20);

    // b.dll must resolve to a real base (a plugin base in the DLL arena).
    put_str(&mut mem, name_ptr, "b.dll");
    let b_handle = call_api(&mut os, &mut mem, &mut cpu, "GetModuleHandleA", &[name_ptr]);
    assert_ne!(b_handle, 0, "b.dll not in module table");
    assert_ne!(a_handle, b_handle);

    // All three lists carry all three modules.
    for (name, list) in [("InLoad", &in_load), ("InMemory", &in_mem), ("InInit", &in_init)] {
        assert!(list.contains(&IMAGE_BASE), "{name} missing main image: {list:#x?}");
        assert!(list.contains(&a_handle), "{name} missing a.dll: {list:#x?}");
        assert!(list.contains(&b_handle), "{name} missing b.dll: {list:#x?}");
    }

    // Load order: the main image is first; B (a dependency) is loaded *before*
    // A, so it precedes A in the InLoadOrder list.
    assert_eq!(in_load[0], IMAGE_BASE, "main image must head InLoadOrder");
    let b_pos = in_load.iter().position(|&x| x == b_handle).unwrap();
    let a_pos = in_load.iter().position(|&x| x == a_handle).unwrap();
    assert!(b_pos < a_pos, "dependency B must load before A: {in_load:#x?}");

    // GetProcAddress against B returns a real guest code address (b_func at
    // RVA 0x2000).
    put_str(&mut mem, name_ptr, "b_func");
    let proc = call_api(&mut os, &mut mem, &mut cpu, "GetProcAddress", &[b_handle, name_ptr]);
    assert_eq!(proc, b_handle + 0x2000, "GetProcAddress(b.dll, b_func)");

    // A's IAT slot for b_func was bound to B's real export (not a thunk): the
    // slot value must equal B's guest code address in the DLL arena.
    // (Bound at IDATA_RVA + iat_off = 0x1000 + 40 + 16 = 0x1038 within A.)
    let iat = a_handle + 0x1000 + 40 + 16;
    let bound = mem.read_u64(iat).unwrap();
    assert_eq!(bound, b_handle + 0x2000, "A.b_func IAT not bound to B's real code");

    // The BaseDllName of A's Ldr entry reads back correctly.
    let head = ldr + 0x10; // InLoadOrder head
    let mut cur = mem.read_u64(head).unwrap();
    let mut a_entry = 0;
    while cur != head {
        if mem.read_u64(cur + 0x30).unwrap() == a_handle {
            a_entry = cur; // InLoad link at offset 0x00 == entry base
            break;
        }
        cur = mem.read_u64(cur).unwrap();
    }
    assert_ne!(a_entry, 0);
    let base_name = read_unicode_string(&mem, a_entry + 0x58);
    assert_eq!(base_name, "a.dll");
    // SizeOfImage and EntryPoint are populated.
    assert_ne!(mem.read_u64(a_entry + 0x40).unwrap(), 0, "SizeOfImage populated");
    assert_eq!(mem.read_u64(a_entry + 0x38).unwrap(), a_handle + 0x4000, "EntryPoint");
}

#[test]
fn load_library_ref_count_and_free() {
    let (mut os, mut mem, _peb, _sandbox, root) = setup_os();
    let b = build_exporting_dll("b.dll", "b_func");
    std::fs::write(root.join("C").join("b.dll"), &b).unwrap();

    let mut cpu = CpuState::new();
    let name_ptr = 0x2_0000_0100u64;
    put_str(&mut mem, name_ptr, "b.dll");
    let h1 = call_api(&mut os, &mut mem, &mut cpu, "LoadLibraryA", &[name_ptr]);
    assert_ne!(h1, 0);
    // A second LoadLibrary of the same DLL returns the same handle (ref bumped,
    // not remapped).
    let h2 = call_api(&mut os, &mut mem, &mut cpu, "LoadLibraryA", &[name_ptr]);
    assert_eq!(h1, h2, "second LoadLibrary must reuse the handle");
    // FreeLibrary three times all succeed (the handle stays recognized; we
    // never unmap the arena).
    assert_eq!(call_api(&mut os, &mut mem, &mut cpu, "FreeLibrary", &[h1]), 1);
    assert_eq!(call_api(&mut os, &mut mem, &mut cpu, "FreeLibrary", &[h1]), 1);
    assert_eq!(call_api(&mut os, &mut mem, &mut cpu, "FreeLibrary", &[h1]), 1);
}

mod tempdir {
    use std::path::PathBuf;
    pub struct Guard {
        pub path: PathBuf,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    pub fn make() -> Guard {
        use std::sync::atomic::{AtomicU32, Ordering};
        // Process id + a static counter guarantee a distinct sandbox per test,
        // even when tests run in parallel and land on the same nanosecond (a
        // bare timestamp collides and one test's Drop guard would wipe the
        // other's fixture mid-run). Mirrors fs.rs::unique_sandbox.
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "exemu-loader-test-{}-{:04}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&p).unwrap();
        Guard { path: p }
    }
}

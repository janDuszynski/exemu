use exemu_core::{Cpu, Exit, ImportSymbol, Memory, Perm, Reg, Region};
use exemu_cpu::{Bits, Interpreter};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

mod support;

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

const SCRATCH: u64 = 0x3_0000_0000;

struct Sec<'a> {
    name: &'a [u8],
    rva: u32,
    data: &'a [u8],
    chars: u32,
}

fn align_up(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

fn assemble_pe(
    secs: &[Sec],
    export_dir: Option<(u32, u32)>,
    import_dir: Option<(u32, u32)>,
    entry_rva: u32,
) -> Vec<u8> {
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
    put_u16(&mut f, coff, 0x8664);
    put_u16(&mut f, coff + 2, secs.len() as u16);
    put_u16(&mut f, coff + 16, OPT_HDR_SIZE as u16);
    put_u16(&mut f, coff + 18, 0x2022);

    let opt = coff + 20;
    let last = secs.last().unwrap();
    let image_size = align_up(last.rva + last.data.len() as u32, SEC_ALIGN);
    put_u16(&mut f, opt, 0x20B);
    put_u32(&mut f, opt + 16, entry_rva);
    put_u64(&mut f, opt + 24, IMAGE_BASE);
    put_u32(&mut f, opt + 32, SEC_ALIGN);
    put_u32(&mut f, opt + 36, FILE_ALIGN);
    put_u16(&mut f, opt + 40, 6);
    put_u16(&mut f, opt + 48, 6);
    put_u32(&mut f, opt + 56, image_size);
    put_u32(&mut f, opt + 60, headers_raw);
    put_u16(&mut f, opt + 68, 3);
    put_u32(&mut f, opt + 108, 16);

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

fn build_edata(dll_name: &str, sym: &str, edata_rva: u32, code_rva: u32) -> Vec<u8> {
    let dir_off = 0u32;
    let eat_off = dir_off + 40;
    let names_off = eat_off + 4;
    let ords_off = names_off + 4;
    let mut pos = ords_off + 2;
    let sym_rva = edata_rva + pos;
    pos += sym.len() as u32 + 1;
    let dllname_rva = edata_rva + pos;
    pos += dll_name.len() as u32 + 1;
    let edata_len = pos;
    let mut ed = vec![0u8; edata_len as usize];
    put_u32(&mut ed, dir_off as usize + 12, dllname_rva);
    put_u32(&mut ed, dir_off as usize + 16, 1);
    put_u32(&mut ed, dir_off as usize + 20, 1);
    put_u32(&mut ed, dir_off as usize + 24, 1);
    put_u32(&mut ed, dir_off as usize + 28, edata_rva + eat_off);
    put_u32(&mut ed, dir_off as usize + 32, edata_rva + names_off);
    put_u32(&mut ed, dir_off as usize + 36, edata_rva + ords_off);
    put_u32(&mut ed, eat_off as usize, code_rva);
    put_u32(&mut ed, names_off as usize, sym_rva);
    put_u16(&mut ed, ords_off as usize, 0);
    let so = (sym_rva - edata_rva) as usize;
    ed[so..so + sym.len()].copy_from_slice(sym.as_bytes());
    let dn = (dllname_rva - edata_rva) as usize;
    ed[dn..dn + dll_name.len()].copy_from_slice(dll_name.as_bytes());
    ed
}

fn build_a_dll() -> Vec<u8> {
    const EDATA_RVA: u32 = 0x1000;
    const CODE_RVA: u32 = 0x2000;
    const ENTRY_RVA: u32 = 0x3000;
    let ed = build_edata("a.dll", "a_func", EDATA_RVA, CODE_RVA);
    let text = vec![0xC3u8];
    let mut entry = Vec::new();
    entry.extend_from_slice(&[0x83, 0xFA, 0x01]);
    entry.extend_from_slice(&[0x75, 0x10]);
    entry.extend_from_slice(&[0x48, 0xB8]);
    entry.extend_from_slice(&SCRATCH.to_le_bytes());
    entry.extend_from_slice(&[0xC7, 0x00, 0xAA, 0xAA, 0x00, 0x00]);
    entry.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
    entry.push(0xC3);
    assemble_pe(
        &[
            Sec { name: b".edata", rva: EDATA_RVA, data: &ed, chars: 0x4000_0040 },
            Sec { name: b".text", rva: CODE_RVA, data: &text, chars: 0x6000_0020 },
            Sec { name: b".init", rva: ENTRY_RVA, data: &entry, chars: 0x6000_0020 },
        ],
        Some((EDATA_RVA, ed.len() as u32)),
        None,
        ENTRY_RVA,
    )
}

fn build_b_dll() -> Vec<u8> {
    const IDATA_RVA: u32 = 0x1000;
    const EDATA_RVA: u32 = 0x2000;
    const CODE_RVA: u32 = 0x3000;
    const ENTRY_RVA: u32 = 0x4000;

    let (dep_dll, dep_sym) = ("a.dll", "a_func");
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

    let ed = build_edata("b.dll", "b_func", EDATA_RVA, CODE_RVA);
    let text = vec![0xC3u8];

    let mut entry = Vec::new();
    entry.extend_from_slice(&[0x83, 0xFA, 0x01]);
    entry.extend_from_slice(&[0x75, 0x24]);
    entry.extend_from_slice(&[0x48, 0xB8]);
    entry.extend_from_slice(&SCRATCH.to_le_bytes());
    entry.extend_from_slice(&[0x8B, 0x08]);
    entry.extend_from_slice(&[0x81, 0xF9, 0xAA, 0xAA, 0x00, 0x00]);
    entry.extend_from_slice(&[0x75, 0x10]);
    entry.extend_from_slice(&[0x48, 0xB8]);
    entry.extend_from_slice(&(SCRATCH + 8).to_le_bytes());
    entry.extend_from_slice(&[0xC7, 0x00, 0xBB, 0xBB, 0x00, 0x00]);
    entry.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
    entry.push(0xC3);

    assemble_pe(
        &[
            Sec { name: b".idata", rva: IDATA_RVA, data: &idata, chars: 0xC000_0040 },
            Sec { name: b".edata", rva: EDATA_RVA, data: &ed, chars: 0x4000_0040 },
            Sec { name: b".text", rva: CODE_RVA, data: &text, chars: 0x6000_0020 },
            Sec { name: b".init", rva: ENTRY_RVA, data: &entry, chars: 0x6000_0020 },
        ],
        Some((EDATA_RVA, ed.len() as u32)),
        Some((IDATA_RVA + desc_off, 40)),
        ENTRY_RVA,
    )
}

fn setup_os() -> (WinOs, VirtualMemory, u64, tempdir::Guard, std::path::PathBuf) {
    let sandbox = tempdir::make();
    let sandbox_root = sandbox.path.clone();
    std::fs::create_dir_all(sandbox.path.join("C")).unwrap();

    let mut mem = VirtualMemory::new();
    let dll_base = 0x0000_0006_0000_0000u64;
    let dll_size = 0x0080_0000u64;
    let peb_addr = 0x0000_7FFF_0000_2000u64;
    mem.map(Region::new("dlls", dll_base, dll_size, Perm::RWX)).unwrap();
    mem.map(Region::new("peb", peb_addr, 0x1000, Perm::RW)).unwrap();
    mem.map(Region::new("heap", 0x2_0000_0000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("imports", 0x0000_7EFF_0000_0000, 0x10000, Perm::RW)).unwrap();
    mem.map(Region::new("stack", 0x0F_FFF0_0000, 0x0020_0000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x1000, Perm::RW)).unwrap();

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
        peb_loaderlock_off: 0x110,
        ..WinConfig::default()
    };
    let mut os = WinOs::new(cfg);
    os.set_image_loader(Box::new(support::LoaderImages));
    os.init_ldr(&mut mem).unwrap();
    (os, mem, peb_addr, sandbox, sandbox_root)
}

const STACK: u64 = 0x10_0000_0000;
const RET: u64 = 0x1_2345;

fn call_api(
    os: &mut WinOs,
    mem: &mut VirtualMemory,
    interp: &mut Interpreter,
    api: &str,
    args: &[u64],
) -> u64 {
    let st = interp.state_mut();
    st.set_rsp(STACK);
    mem.write_u64(STACK, RET).unwrap();
    let regs = [Reg::Rcx, Reg::Rdx, Reg::R8, Reg::R9];
    for (i, &a) in args.iter().enumerate() {
        if i < 4 {
            st.set_reg(regs[i], a);
        }
    }
    let thunk = os.resolve_import("kernel32.dll", &ImportSymbol::Named(api.into()));
    interp.state_mut().rip = thunk;
    let mut guard = 0;
    loop {
        guard += 1;
        assert!(guard < 100_000, "{api} did not settle");
        match interp.step(mem, os).unwrap() {
            Exit::Continue => {
                if interp.state().rip == RET {
                    return interp.state().reg(Reg::Rax);
                }
            }
            other => panic!("unexpected exit {other:?}"),
        }
    }
}

fn put_str(mem: &mut VirtualMemory, ptr: u64, s: &str) -> u64 {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    mem.write(ptr, &bytes).unwrap();
    ptr
}

#[test]
fn dllmain_process_attach_runs_leaves_first() {
    let (mut os, mut mem, peb_addr, _sandbox, root) = setup_os();
    let mut interp = Interpreter::with_bits(Bits::B64);
    std::fs::write(root.join("C").join("a.dll"), build_a_dll()).unwrap();
    std::fs::write(root.join("C").join("b.dll"), build_b_dll()).unwrap();

    let name_ptr = 0x2_0000_0100u64;
    put_str(&mut mem, name_ptr, "b.dll");
    let b_handle = call_api(&mut os, &mut mem, &mut interp, "LoadLibraryA", &[name_ptr]);
    assert_ne!(b_handle, 0, "LoadLibrary(b.dll) failed");

    assert_eq!(mem.read_u32(SCRATCH).unwrap(), 0xAAAA, "A DllMain did not run");
    assert_eq!(
        mem.read_u32(SCRATCH + 8).unwrap(),
        0xBBBB,
        "B DllMain did not observe A's global — leaves-first order violated"
    );

    let cs = mem.read_u64(peb_addr + 0x110).unwrap();
    assert_ne!(cs, 0, "PEB.LoaderLock not published");
    assert_eq!(mem.read_u32(cs + 8).unwrap() as i32, -1, "LoaderLock LockCount should be -1 (unlocked)");
    assert_eq!(mem.read_u32(cs + 12).unwrap(), 0, "LoaderLock RecursionCount should be 0");
    assert_eq!(mem.read_u64(cs + 16).unwrap(), 0, "LoaderLock OwningThread should be cleared");
}

#[test]
fn free_library_runs_process_detach() {
    let (mut os, mut mem, _peb, _sandbox, root) = setup_os();
    let mut interp = Interpreter::with_bits(Bits::B64);
    std::fs::write(root.join("C").join("a.dll"), build_a_dll()).unwrap();
    std::fs::write(root.join("C").join("b.dll"), build_b_dll()).unwrap();

    let name_ptr = 0x2_0000_0100u64;
    put_str(&mut mem, name_ptr, "b.dll");
    let b_handle = call_api(&mut os, &mut mem, &mut interp, "LoadLibraryA", &[name_ptr]);
    assert_ne!(b_handle, 0);
    assert_eq!(mem.read_u32(SCRATCH).unwrap(), 0xAAAA);

    mem.write_u32(SCRATCH + 8, 0).unwrap();
    let r = call_api(&mut os, &mut mem, &mut interp, "FreeLibrary", &[b_handle]);
    assert_eq!(r, 1, "FreeLibrary should return TRUE");
    assert_eq!(
        mem.read_u32(SCRATCH + 8).unwrap(),
        0,
        "DLL_PROCESS_DETACH must not re-run the ATTACH branch"
    );

    let r2 = call_api(&mut os, &mut mem, &mut interp, "FreeLibrary", &[b_handle]);
    assert_eq!(r2, 1);
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
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "exemu-dllmain-test-{}-{:04}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&p).unwrap();
        Guard { path: p }
    }
}

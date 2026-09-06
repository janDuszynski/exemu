use exemu_core::{Cpu, Exit, Memory, Perm, Region, Result};
use exemu_cpu::{Bits, Interpreter, GS_BASE};
use exemu_memory::VirtualMemory;
use exemu_os::{WinConfig, WinOs};

const NT_CREATE_KEY: u32 = 0x1d;
const NT_OPEN_KEY: u32 = 0x12;
const NT_QUERY_VALUE_KEY: u32 = 0x17;
const NT_SET_VALUE_KEY: u32 = 0x60;
const NT_ENUMERATE_KEY: u32 = 0x32;
const NT_QUERY_KEY: u32 = 0x16;
const NT_OPEN_KEY_EX: u32 = 0xb0;
const NT_ENUMERATE_VALUE_KEY: u32 = 0x13;
const NT_DELETE_KEY: u32 = 0x8e;
const NT_DELETE_VALUE_KEY: u32 = 0x8f;
const NT_FLUSH_KEY: u32 = 0x94;
const STATUS_CANNOT_DELETE: u64 = 0xC000_0121;

const STATUS_SUCCESS: u64 = 0x0000_0000;
const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001A;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xC000_0023;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xC000_0034;

const HKLM: u64 = 0x8000_0002;

const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const KEY_VALUE_FULL_INFORMATION: u64 = 1;
const KEY_VALUE_PARTIAL_INFORMATION: u64 = 2;
const KEY_BASIC_INFORMATION: u64 = 0;
const KEY_FULL_INFORMATION: u64 = 2;
const KEY_NAME_INFORMATION: u64 = 3;

const CODE: u64 = 0x0000_0000_0040_0000;
const STACK_TOP: u64 = 0x0000_0010_0000_1000;
const SCRATCH: u64 = 0x0000_0000_5000_0000;
const PEB: u64 = GS_BASE + 0x2000;
const TEB_SIZE: u64 = 0x2000;

fn setup() -> (WinOs, VirtualMemory) {
    let mut mem = VirtualMemory::new();
    mem.map(Region::new("code", CODE, 0x1000, Perm::RX)).unwrap();
    mem.map(Region::new("stack", STACK_TOP - 0x2000, 0x2000, Perm::RW)).unwrap();
    mem.map(Region::new("scratch", SCRATCH, 0x4000, Perm::RW)).unwrap();
    mem.map(Region::new("teb", GS_BASE, TEB_SIZE, Perm::RW)).unwrap();
    mem.map(Region::new("peb", PEB, 0x1000, Perm::RW)).unwrap();
    let os = WinOs::new(WinConfig {
        is_64bit: true,
        echo: false,
        teb_base: GS_BASE,
        peb_addr: PEB,
        ..WinConfig::default()
    });
    (os, mem)
}

fn syscall(os: &mut WinOs, mem: &mut VirtualMemory, index: u32, args: &[u64]) -> u64 {
    let mut asm: Vec<u8> = Vec::new();
    asm.extend_from_slice(&[0x48, 0xB9]);
    asm.extend_from_slice(&args.first().copied().unwrap_or(0).to_le_bytes());
    asm.extend_from_slice(&[0x49, 0x89, 0xCA]);
    asm.extend_from_slice(&[0xB8]);
    asm.extend_from_slice(&index.to_le_bytes());
    asm.extend_from_slice(&[0x0F, 0x05]);
    asm.push(0xF4);
    mem.poke(CODE, &asm).unwrap();

    let mut cpu = Interpreter::with_bits(Bits::B64);
    let rsp = STACK_TOP - 0x100;
    {
        let s = cpu.state_mut();
        s.rip = CODE;
        s.set_rsp(rsp);
        s.gs_base = GS_BASE;
        let regs = [exemu_core::Reg::Rdx, exemu_core::Reg::R8, exemu_core::Reg::R9];
        for (i, &a) in args.iter().skip(1).take(3).enumerate() {
            s.set_reg(regs[i], a);
        }
    }
    for (n, &a) in args.iter().enumerate().skip(4) {
        mem.write_u64(rsp + 0x28 + (n as u64 - 4) * 8, a).unwrap();
    }
    loop {
        match cpu.step(mem, os).expect("syscall faulted") {
            Exit::Continue => continue,
            Exit::Halted => break,
            other => panic!("unexpected exit: {other:?}"),
        }
    }
    cpu.state().reg(exemu_core::Reg::Rax)
}

fn put_ustr(mem: &mut VirtualMemory, addr: u64, s: &str) -> u64 {
    let buf = addr + 0x40;
    let units: Vec<u16> = s.encode_utf16().collect();
    for (i, u) in units.iter().enumerate() {
        mem.write_u16(buf + (i as u64) * 2, *u).unwrap();
    }
    let bytes = (units.len() * 2) as u16;
    mem.write_u16(addr, bytes).unwrap();
    mem.write_u16(addr + 2, bytes).unwrap();
    mem.write_u64(addr + 8, buf).unwrap();
    addr
}

fn put_objattr(mem: &mut VirtualMemory, addr: u64, root: u64, name: &str) -> u64 {
    let ustr = put_ustr(mem, addr + 0x100, name);
    mem.write_u32(addr, 0x30).unwrap();
    mem.write_u64(addr + 8, root).unwrap();
    mem.write_u64(addr + 0x10, ustr).unwrap();
    addr
}

fn read_utf16(mem: &VirtualMemory, addr: u64, bytes: u32) -> String {
    let units: Vec<u16> = (0..bytes / 2).map(|i| mem.read_u16(addr + (i as u64) * 2).unwrap()).collect();
    String::from_utf16_lossy(&units)
}

#[test]
fn nt_create_set_query_roundtrip() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let data = SCRATCH + 0x600;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    let oa = put_objattr(&mut mem, objattr, HKLM, "SOFTWARE\\ExemuW213Test");
    let disp = SCRATCH + 0xC40;
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, oa, 0, 0, 0, disp]), STATUS_SUCCESS);
    let key = mem.read_u64(h_out).unwrap();
    assert_ne!(key, 0);
    assert_eq!(mem.read_u32(disp).unwrap(), 1);

    let vn = put_ustr(&mut mem, vname, "Answer");
    mem.write_u32(data, 42).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_SET_VALUE_KEY, &[key, vn, 0, REG_DWORD as u64, data, 4]), STATUS_SUCCESS);

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x40, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 4).unwrap(), REG_DWORD);
    assert_eq!(mem.read_u32(out + 8).unwrap(), 4);
    assert_eq!(mem.read_u32(out + 12).unwrap(), 42);
    assert_eq!(mem.read_u32(rlen).unwrap(), 12 + 4);

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_FULL_INFORMATION, out, 0x40, rlen]),
        STATUS_SUCCESS
    );
    let name_len = mem.read_u32(out + 16).unwrap();
    assert_eq!(read_utf16(&mem, out + 20, name_len), "Answer");
    let data_off = mem.read_u32(out + 8).unwrap() as u64;
    assert_eq!(mem.read_u32(out + data_off).unwrap(), 42);

    let oa2 = put_objattr(&mut mem, objattr, 0, "\\Registry\\Machine\\SOFTWARE\\ExemuW213Test");
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa2]), STATUS_SUCCESS);
    let key2 = mem.read_u64(h_out).unwrap();
    assert_ne!(key2, 0);
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key2, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x40, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 12).unwrap(), 42);

    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, oa, 0, 0, 0, disp]), STATUS_SUCCESS);
    assert_eq!(mem.read_u32(disp).unwrap(), 2);
}

#[test]
fn nt_query_value_buffer_sizing_and_win32_seed_interop() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    let oa = put_objattr(
        &mut mem,
        objattr,
        0,
        "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    );
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa]), STATUS_SUCCESS);
    let key = mem.read_u64(h_out).unwrap();

    let vn = put_ustr(&mut mem, vname, "ProductName");
    let expect_data = 30u32;
    let expect_total = 12 + expect_data;

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 8, rlen]),
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(mem.read_u32(rlen).unwrap(), expect_total);

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 16, rlen]),
        STATUS_BUFFER_OVERFLOW
    );
    assert_eq!(mem.read_u32(rlen).unwrap(), expect_total);

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 4).unwrap(), REG_SZ);
    assert_eq!(mem.read_u32(out + 8).unwrap(), expect_data);
    assert_eq!(read_utf16(&mem, out + 12, expect_data - 2), "Windows 10 Pro");

    let missing = put_ustr(&mut mem, vname, "NoSuchValue");
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, missing, KEY_VALUE_PARTIAL_INFORMATION, out, 0x80, rlen]),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[test]
fn nt_enumerate_and_query_key() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    let parent_oa = put_objattr(&mut mem, objattr, HKLM, "SOFTWARE\\ExemuEnum");
    let noarg = SCRATCH + 0xC40;
    syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, parent_oa, 0, 0, 0, noarg]);
    for sub in ["Alpha", "Beta"] {
        let oa = put_objattr(&mut mem, objattr, HKLM, &format!("SOFTWARE\\ExemuEnum\\{sub}"));
        syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, oa, 0, 0, 0, noarg]);
    }

    let poa = put_objattr(&mut mem, objattr, HKLM, "SOFTWARE\\ExemuEnum");
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, poa]), STATUS_SUCCESS);
    let parent = mem.read_u64(h_out).unwrap();

    let mut names = Vec::new();
    for i in 0..2u64 {
        assert_eq!(
            syscall(&mut os, &mut mem, NT_ENUMERATE_KEY, &[parent, i, KEY_BASIC_INFORMATION, out, 0x80, rlen]),
            STATUS_SUCCESS
        );
        let nlen = mem.read_u32(out + 12).unwrap();
        names.push(read_utf16(&mem, out + 16, nlen));
    }
    assert_eq!(names, vec!["Alpha".to_string(), "Beta".to_string()]);

    assert_eq!(
        syscall(&mut os, &mut mem, NT_ENUMERATE_KEY, &[parent, 2, KEY_BASIC_INFORMATION, out, 0x80, rlen]),
        STATUS_NO_MORE_ENTRIES
    );

    assert_eq!(
        syscall(&mut os, &mut mem, NT_ENUMERATE_KEY, &[parent, 0, KEY_BASIC_INFORMATION, out, 8, rlen]),
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(mem.read_u32(rlen).unwrap(), 16 + 2 * 5);

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[parent, KEY_FULL_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 20).unwrap(), 2);
    assert_eq!(mem.read_u32(out + 32).unwrap(), 0);

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[parent, KEY_NAME_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    let nlen = mem.read_u32(out).unwrap();
    assert_eq!(read_utf16(&mem, out + 4, nlen), "HKLM\\SOFTWARE\\ExemuEnum");

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[parent, KEY_BASIC_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    let blen = mem.read_u32(out + 12).unwrap();
    assert_eq!(read_utf16(&mem, out + 16, blen), "ExemuEnum");
}

#[test]
fn nt_keys_and_values_are_case_insensitive_but_case_preserving() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let data = SCRATCH + 0x600;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;
    let disp = SCRATCH + 0xC40;

    let oa = put_objattr(&mut mem, objattr, HKLM, "Software\\CaseTest\\MixedCase");
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, oa, 0, 0, 0, disp]), STATUS_SUCCESS);
    let key = mem.read_u64(h_out).unwrap();
    let vn = put_ustr(&mut mem, vname, "ThreadingModel");
    mem.write_u32(data, 0xABCD).unwrap();
    assert_eq!(
        syscall(&mut os, &mut mem, NT_SET_VALUE_KEY, &[key, vn, 0, REG_DWORD as u64, data, 4]),
        STATUS_SUCCESS
    );

    let oa2 = put_objattr(&mut mem, objattr, 0, "\\Registry\\MACHINE\\SOFTWARE\\casetest\\MIXEDCASE");
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa2]), STATUS_SUCCESS);
    let key2 = mem.read_u64(h_out).unwrap();
    let vn2 = put_ustr(&mut mem, vname, "THREADINGMODEL");
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key2, vn2, KEY_VALUE_PARTIAL_INFORMATION, out, 0x40, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 12).unwrap(), 0xABCD, "same value through the other spelling");

    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[key2, KEY_BASIC_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    let nlen = mem.read_u32(out + 12).unwrap();
    assert_eq!(read_utf16(&mem, out + 16, nlen), "MixedCase");
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key2, vn2, KEY_VALUE_FULL_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    let name_len = mem.read_u32(out + 16).unwrap();
    assert_eq!(read_utf16(&mem, out + 20, name_len), "ThreadingModel");

    mem.write_u32(data, 0x1234).unwrap();
    assert_eq!(
        syscall(&mut os, &mut mem, NT_SET_VALUE_KEY, &[key2, vn2, 0, REG_DWORD as u64, data, 4]),
        STATUS_SUCCESS
    );
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[key2, KEY_FULL_INFORMATION, out, 0x80, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 32).unwrap(), 1, "still exactly one value");
}

#[test]
fn hkcr_clsid_inproc_server_resolves_through_the_nt_namespace() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    let clsid = "{00000303-0000-0000-C000-000000000046}";
    let oa = put_objattr(
        &mut mem,
        objattr,
        0,
        &format!("\\Registry\\Machine\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32"),
    );
    assert_eq!(
        syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa]),
        STATUS_SUCCESS,
        "the seeded InprocServer32 key opens through the NT namespace"
    );
    let key = mem.read_u64(h_out).unwrap();

    let default = put_ustr(&mut mem, vname, "");
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, default, KEY_VALUE_PARTIAL_INFORMATION, out, 0x100, rlen]),
        STATUS_SUCCESS
    );
    assert_eq!(mem.read_u32(out + 4).unwrap(), REG_SZ);
    let dlen = mem.read_u32(out + 8).unwrap();
    assert_eq!(read_utf16(&mem, out + 12, dlen - 2), "ole32.dll");

    let tm = put_ustr(&mut mem, vname, "ThreadingModel");
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, tm, KEY_VALUE_PARTIAL_INFORMATION, out, 0x100, rlen]),
        STATUS_SUCCESS
    );
    let dlen = mem.read_u32(out + 8).unwrap();
    assert_eq!(read_utf16(&mem, out + 12, dlen - 2), "Both");

    const HKCR: u64 = 0x8000_0000;
    let oa2 = put_objattr(&mut mem, objattr, HKCR, &format!("CLSID\\{clsid}\\InprocServer32"));
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa2]), STATUS_SUCCESS);
    let via_hkcr = mem.read_u64(h_out).unwrap();
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_KEY, &[via_hkcr, KEY_NAME_INFORMATION, out, 0x200, rlen]),
        STATUS_SUCCESS
    );
    let nlen = mem.read_u32(out).unwrap();
    assert_eq!(
        read_utf16(&mem, out + 4, nlen),
        format!("HKLM\\SOFTWARE\\Classes\\CLSID\\{clsid}\\InprocServer32")
    );
}

#[test]
fn nt_open_key_ex_enumerate_values_and_delete() {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let data = SCRATCH + 0x600;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;
    let disp = SCRATCH + 0xC40;

    let oa = put_objattr(&mut mem, objattr, HKLM, "Software\\ExemuW64");
    assert_eq!(syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, oa, 0, 0, 0, disp]), STATUS_SUCCESS);
    let key = mem.read_u64(h_out).unwrap();
    for (n, v) in [("Alpha", 1u32), ("Beta", 2), ("Gamma", 3)] {
        let vn = put_ustr(&mut mem, vname, n);
        mem.write_u32(data, v).unwrap();
        assert_eq!(
            syscall(&mut os, &mut mem, NT_SET_VALUE_KEY, &[key, vn, 0, REG_DWORD as u64, data, 4]),
            STATUS_SUCCESS
        );
    }

    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY_EX, &[h_out, 0, oa, 0]), STATUS_SUCCESS);
    let key_ex = mem.read_u64(h_out).unwrap();
    assert_ne!(key_ex, 0);

    let mut seen = Vec::new();
    for i in 0..3u64 {
        assert_eq!(
            syscall(&mut os, &mut mem, NT_ENUMERATE_VALUE_KEY, &[key_ex, i, KEY_VALUE_FULL_INFORMATION, out, 0x100, rlen]),
            STATUS_SUCCESS
        );
        let nlen = mem.read_u32(out + 16).unwrap();
        let doff = mem.read_u32(out + 8).unwrap() as u64;
        assert_eq!(mem.read_u32(out + 4).unwrap(), REG_DWORD);
        seen.push((read_utf16(&mem, out + 20, nlen), mem.read_u32(out + doff).unwrap()));
    }
    assert_eq!(
        seen,
        vec![("Alpha".to_string(), 1), ("Beta".to_string(), 2), ("Gamma".to_string(), 3)]
    );
    assert_eq!(
        syscall(&mut os, &mut mem, NT_ENUMERATE_VALUE_KEY, &[key_ex, 3, KEY_VALUE_FULL_INFORMATION, out, 0x100, rlen]),
        STATUS_NO_MORE_ENTRIES
    );
    assert_eq!(
        syscall(&mut os, &mut mem, NT_ENUMERATE_VALUE_KEY, &[key_ex, 0, KEY_VALUE_PARTIAL_INFORMATION, out, 8, rlen]),
        STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(mem.read_u32(rlen).unwrap(), 12 + 4);

    assert_eq!(syscall(&mut os, &mut mem, NT_FLUSH_KEY, &[key_ex]), STATUS_SUCCESS);
    assert_eq!(syscall(&mut os, &mut mem, NT_FLUSH_KEY, &[0xdead_beef]), STATUS_INVALID_HANDLE);

    let vn = put_ustr(&mut mem, vname, "beta");
    assert_eq!(syscall(&mut os, &mut mem, NT_DELETE_VALUE_KEY, &[key, vn]), STATUS_SUCCESS);
    assert_eq!(syscall(&mut os, &mut mem, NT_DELETE_VALUE_KEY, &[key, vn]), STATUS_OBJECT_NAME_NOT_FOUND);
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[key, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x40, rlen]),
        STATUS_OBJECT_NAME_NOT_FOUND
    );

    let child_oa = put_objattr(&mut mem, objattr, HKLM, "Software\\ExemuW64\\Leaf");
    syscall(&mut os, &mut mem, NT_CREATE_KEY, &[h_out, 0, child_oa, 0, 0, 0, disp]);
    let leaf = mem.read_u64(h_out).unwrap();
    assert_eq!(syscall(&mut os, &mut mem, NT_DELETE_KEY, &[key]), STATUS_CANNOT_DELETE);
    assert_eq!(syscall(&mut os, &mut mem, NT_DELETE_KEY, &[leaf]), STATUS_SUCCESS);
    assert_eq!(syscall(&mut os, &mut mem, NT_DELETE_KEY, &[key]), STATUS_SUCCESS);
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa]), STATUS_OBJECT_NAME_NOT_FOUND);
    assert_eq!(syscall(&mut os, &mut mem, NT_DELETE_KEY, &[0xdead_beef]), STATUS_INVALID_HANDLE);
}

#[test]
fn nt_error_paths() -> Result<()> {
    let (mut os, mut mem) = setup();
    let h_out = SCRATCH;
    let objattr = SCRATCH + 0x40;
    let vname = SCRATCH + 0x400;
    let out = SCRATCH + 0x800;
    let rlen = SCRATCH + 0xC00;

    let oa = put_objattr(&mut mem, objattr, HKLM, "SOFTWARE\\DoesNotExist\\Nope");
    assert_eq!(syscall(&mut os, &mut mem, NT_OPEN_KEY, &[h_out, 0, oa]), STATUS_OBJECT_NAME_NOT_FOUND);

    let vn = put_ustr(&mut mem, vname, "x");
    assert_eq!(
        syscall(&mut os, &mut mem, NT_QUERY_VALUE_KEY, &[0xdead_beef, vn, KEY_VALUE_PARTIAL_INFORMATION, out, 0x40, rlen]),
        STATUS_INVALID_HANDLE
    );
    Ok(())
}

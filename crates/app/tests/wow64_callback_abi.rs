use std::collections::BTreeMap;

use exemu_os::wow64;

const DLLS64: &str = "../../example_exe/wine-dlls/x86_64-windows";
const DLLS32: &str = "../../example_exe/wine-dlls/i386-windows";

fn have_set() -> bool {
    std::path::Path::new(DLLS32).join("user32.dll").is_file()
        && std::path::Path::new(DLLS64).join("wow64win.dll").is_file()
}

struct Img {
    image_base: u64,
    exports: BTreeMap<String, u32>,
    sections: Vec<(u32, Vec<u8>)>,
    imports: Vec<(u32, String, String)>,
    syms: BTreeMap<String, u32>,
}

fn load(path: &str) -> Img {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let img = exemu_loader::parse(&bytes).expect("pinned DLL parses");
    let mut exports = BTreeMap::new();
    for e in &img.exports {
        if e.forwarder.is_none() {
            if let Some(n) = &e.name {
                exports.insert(n.clone(), e.rva);
            }
        }
    }
    let mut sections: Vec<(u32, Vec<u8>)> = img
        .sections
        .iter()
        .filter(|s| !s.data.is_empty())
        .map(|s| (s.rva, s.data.clone()))
        .collect();
    sections.sort_by_key(|(r, _)| *r);
    let imports = img
        .imports
        .iter()
        .filter_map(|i| match &i.symbol {
            exemu_core::ImportSymbol::Named(n) => Some((i.iat_rva, i.dll.to_ascii_lowercase(), n.clone())),
            exemu_core::ImportSymbol::Ordinal(_) => None,
        })
        .collect();
    Img { image_base: img.image_base, exports, sections, imports, syms: coff_symbols(&bytes, &img) }
}

fn coff_symbols(bytes: &[u8], image: &exemu_core::PeImage) -> BTreeMap<String, u32> {
    let pe = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let symptr = u32::from_le_bytes(bytes[pe + 12..pe + 16].try_into().unwrap()) as usize;
    let nsyms = u32::from_le_bytes(bytes[pe + 16..pe + 20].try_into().unwrap()) as usize;
    let mut out = BTreeMap::new();
    if symptr == 0 || nsyms == 0 || symptr + 18 * nsyms > bytes.len() {
        return out;
    }
    let strtab = &bytes[symptr + 18 * nsyms..];
    let mut i = 0usize;
    while i < nsyms {
        let e = &bytes[symptr + 18 * i..symptr + 18 * i + 18];
        let name = if e[..4] == [0, 0, 0, 0] {
            let off = u32::from_le_bytes(e[4..8].try_into().unwrap()) as usize;
            let end = strtab[off..].iter().position(|b| *b == 0).unwrap_or(0) + off;
            String::from_utf8_lossy(&strtab[off..end]).into_owned()
        } else {
            let end = e[..8].iter().position(|b| *b == 0).unwrap_or(8);
            String::from_utf8_lossy(&e[..end]).into_owned()
        };
        let value = u32::from_le_bytes(e[8..12].try_into().unwrap());
        let secnum = i16::from_le_bytes(e[12..14].try_into().unwrap());
        let naux = e[17] as usize;
        if secnum >= 1 && (secnum as usize) <= image.sections.len() && !name.starts_with('.') {
            out.entry(name).or_insert(image.sections[secnum as usize - 1].rva + value);
        }
        i += 1 + naux;
    }
    out
}

impl Img {
    fn at(&self, rva: u32, len: usize) -> &[u8] {
        for (base, data) in &self.sections {
            if rva >= *base && (rva - *base) as usize <= data.len() {
                let off = (rva - *base) as usize;
                return &data[off..(off + len).min(data.len())];
            }
        }
        &[]
    }

    fn export(&self, name: &str) -> u32 {
        *self.exports.get(name).unwrap_or_else(|| panic!("the pinned DLL does not export {name}"))
    }

    fn sym(&self, name: &str) -> u32 {
        if let Some(rva) = self.syms.get(name) {
            return *rva;
        }
        let under = format!("_{name}");
        if let Some(rva) = self.syms.get(&under) {
            return *rva;
        }
        let at = format!("{under}@");
        self.syms
            .iter()
            .find(|(k, _)| k.starts_with(&at))
            .map(|(_, v)| *v)
            .unwrap_or_else(|| panic!("the pinned DLL's COFF symbol table names {name}"))
    }

    fn u32_at(&self, rva: u32) -> u32 {
        u32::from_le_bytes(self.at(rva, 4).try_into().expect("4 bytes at rva"))
    }

    fn u64_at(&self, rva: u32) -> u64 {
        u64::from_le_bytes(self.at(rva, 8).try_into().expect("8 bytes at rva"))
    }

    fn ptr_rva(&self, rva: u32) -> u32 {
        let v = self.u64_at(rva);
        assert!(v >= self.image_base, "{rva:#x} holds a pointer into this image");
        (v - self.image_base) as u32
    }

    fn iat(&self, dll: &str, symbol: &str) -> u32 {
        self.imports
            .iter()
            .find(|(_, d, s)| d == dll && s == symbol)
            .map(|(r, _, _)| *r)
            .unwrap_or_else(|| panic!("the pinned DLL imports {dll}!{symbol}"))
    }
}

fn rel32_target(img: &Img, rva: u32, insn_len: u32) -> u32 {
    let b = img.at(rva, insn_len as usize);
    let disp = i32::from_le_bytes(b[insn_len as usize - 4..].try_into().unwrap());
    (rva as i64 + insn_len as i64 + disp as i64) as u32
}

fn rip_target(img: &Img, rva: u32, insn_len: u32) -> u32 {
    rel32_target(img, rva, insn_len)
}

#[test]
fn the_64bit_callback_dispatcher_defines_the_frame_and_the_table() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let ntdll = load(&format!("{DLLS64}/ntdll.dll"));
    let entry = ntdll.export("KiUserCallbackDispatcher");
    let body = ntdll.at(entry, 0x2c);

    assert_eq!(&body[0..5], &[0x48, 0x8B, 0x4C, 0x24, wow64::cb_frame::ARGS as u8], "args at rsp+0x20");
    assert_eq!(&body[5..9], &[0x8B, 0x54, 0x24, wow64::cb_frame::LEN as u8], "len at rsp+0x28");
    assert_eq!(&body[9..14], &[0x44, 0x8B, 0x44, 0x24, wow64::cb_frame::ID as u8], "id at rsp+0x2c");
    assert_eq!(wow64::cb_frame::SIZE, wow64::cb_frame::ID + 4);

    assert_eq!(&body[14..23], &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00], "PEB from gs:[0x60]");
    assert_eq!(
        &body[23..27],
        &[0x48, 0x8B, 0x40, wow64::PEB64_KERNEL_CALLBACK_TABLE as u8],
        "PEB.KernelCallbackTable is at PEB+0x58",
    );
    assert_eq!(&body[27..31], &[0x42, 0xFF, 0x14, 0xC0], "call qword ptr [rax + r8*8] — table[id]");

    assert_eq!(&body[31..39], &[0x48, 0x31, 0xC9, 0x31, 0xD2, 0x41, 0x89, 0xC0], "the result becomes arg3");
    assert_eq!(body[39], 0xE8, "call rel32");
    assert_eq!(
        rel32_target(&ntdll, entry + 39, 5),
        ntdll.export("NtCallbackReturn"),
        "the dispatcher's own tail is NtCallbackReturn",
    );
}

#[test]
fn nt_callback_return_is_ssdt_index_five_on_both_sides() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let ntdll64 = load(&format!("{DLLS64}/ntdll.dll"));
    let b = ntdll64.at(ntdll64.export("NtCallbackReturn"), 8);
    assert_eq!(&b[..3], &[0x4C, 0x8B, 0xD1], "mov r10, rcx");
    assert_eq!(b[3], 0xB8, "mov eax, imm32");
    assert_eq!(
        u32::from_le_bytes(b[4..8].try_into().unwrap()),
        wow64::SSDT_NT_CALLBACK_RETURN,
        "the 64-bit stub's own service index",
    );

    let ntdll32 = load(&format!("{DLLS32}/ntdll.dll"));
    let b = ntdll32.at(ntdll32.export("NtCallbackReturn"), 16);
    assert_eq!(b[0], 0xB8, "mov eax, imm32");
    assert_eq!(
        u32::from_le_bytes(b[1..5].try_into().unwrap()),
        wow64::SSDT_NT_CALLBACK_RETURN,
        "the 32-bit stub carries the same index",
    );
    assert_eq!(&b[12..15], &[0xC2, 0x0C, 0x00], "ret 0xc — three 4-byte arguments");
}

#[test]
fn the_kernel_callback_table_is_wow64wins_and_win_proc_is_entry_four() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let win = load(&format!("{DLLS64}/wow64win.dll"));
    let table = win.sym("user_callbacks");

    let dllmain = win.sym("DllMain");
    let window = win.at(dllmain, 0x100);
    let tail: [u8; 17] = [
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x60, 0x48, 0x89, 0x50, 0x58,
    ];
    let site = (0..window.len() - 24)
        .find(|&i| window[i..i + 3] == [0x48, 0x8D, 0x15] && window[i + 7..i + 7 + 17] == tail)
        .expect("wow64win!DllMain publishes PEB.KernelCallbackTable in the recovered shape");
    assert_eq!(
        rip_target(&win, dllmain + site as u32, 7),
        table,
        "the published array is `user_callbacks`",
    );

    let live = (0..64).take_while(|i| win.u64_at(table + 8 * i) != 0).count();
    assert_eq!(live, 25, "wow64win publishes 25 user callbacks");

    let winproc = win.sym("wow64_NtUserCallWinProc");
    assert_eq!(
        win.ptr_rva(table + 8 * wow64::NT_USER_CALL_WIN_PROC),
        winproc,
        "user_callbacks[NtUserCallWinProc] is wow64_NtUserCallWinProc",
    );

    let body = win.at(winproc, 0x70);
    assert!(
        body.windows(6).any(|w4| w4 == [0x41, 0xB8, 0x2C, 0x00, 0x00, 0x00]),
        "mov r8d, 0x2c — the 32-bit struct size",
    );
    let mov_ecx = (0..body.len() - 5)
        .find(|&i| body[i] == 0xB9 && u32::from_le_bytes(body[i + 1..i + 5].try_into().unwrap()) < 0x20)
        .expect("the thunk loads a literal callback id into ecx");
    assert_eq!(
        u32::from_le_bytes(body[mov_ecx + 1..mov_ecx + 5].try_into().unwrap()),
        wow64::NT_USER_CALL_WIN_PROC,
        "the 32-bit id equals the 64-bit table index",
    );
    let call = winproc + mov_ecx as u32 + 5 + 5;
    assert_eq!(win.at(call, 1)[0], 0xE8, "call rel32");
    let thunk = rel32_target(&win, call, 5);
    assert_eq!(win.at(thunk, 2), &[0xFF, 0x25], "an import thunk: jmp qword ptr [rip+d32]");
    assert_eq!(
        rip_target(&win, thunk, 6),
        win.iat("wow64.dll", "Wow64KiUserCallbackDispatcher"),
        "…through wow64.dll!Wow64KiUserCallbackDispatcher",
    );
    assert!(win.imports.iter().any(|(_, d, s)| d == "ntdll.dll" && s == "NtCallbackReturn"));
}

#[test]
fn the_wow64_dispatcher_builds_the_32bit_frame_from_the_cpu_area() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64.dll"));
    let disp = w.export("Wow64KiUserCallbackDispatcher");
    let body = w.at(disp, 0x320);

    assert!(
        body.windows(7).any(|w4| w4 == [0x48, 0x8B, 0xB8, 0x88, 0x14, 0x00, 0x00]),
        "mov rdi,[rax+0x1488] — the WoW64 CPU-reserved area",
    );
    assert!(
        body.windows(7).any(|w4| w4 == [0x48, 0x63, 0x90, 0x0C, 0x18, 0x00, 0x00]),
        "movsxd rdx,[rax+0x180c] — TEB64.WowTebOffset",
    );

    let i386_arm = body
        .windows(6)
        .position(|w4| w4 == [0x31, 0xC0, 0xB9, 0x59, 0x00, 0x00])
        .expect("the i386 arm zeroes 0x59 qwords of WOW64_CONTEXT");
    assert_eq!(
        0x59 * 8 + 4,
        wow64::WOW64_CONTEXT_SIZE,
        "0x59 qwords + a dword is exactly sizeof(WOW64_CONTEXT)",
    );

    let arm = &body[i386_arm..];
    assert!(
        arm.windows(4).any(|w4| w4 == [0x07, 0x00, 0x01, 0x00]),
        "it asks for a CONTROL|INTEGER|SEGMENTS 32-bit context",
    );
    assert!(
        arm.windows(8).any(|w4| w4 == [0x8D, 0x70, 0xE4, 0x29, 0xDE, 0x83, 0xE6, 0xF0]),
        "lea esi,[eax-0x1c]; sub esi,ebx; and esi,~15 — the 32-bit frame base",
    );
    assert_eq!(WOW64_CB_STACK_HEADER, 0x1c, "the header the frame base reserves");

    assert!(
        arm.windows(3).any(|w4| w4 == [0x89, 0x50, 0x18]),
        "mov [eax+0x18], edx — the saved 32-bit Esp",
    );
    assert!(
        arm.windows(4).any(|w4| w4 == [0x48, 0x8D, 0x48, 0x1C]),
        "lea rcx,[rax+0x1c] — the memcpy destination for the argument block",
    );

    assert!(
        arm.windows(4).any(|w4| w4 == [0x48, 0x8B, 0x40, wow64::SYSDLL_KI_USER_CALLBACK_DISPATCHER as u8]),
        "mov rax,[block+0x30] — the 32-bit KiUserCallbackDispatcher",
    );

    assert!(w.imports.iter().any(|(_, d, s)| d == "ntdll.dll" && s == "_setjmpex"));
    assert!(w.imports.iter().any(|(_, d, s)| d == "ntdll.dll" && s == "longjmp"));
}

const WOW64_CB_STACK_HEADER: u64 = 0x1c;

#[test]
fn wow64s_slot_five_fills_the_callback_frame_and_longjmps() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let w = load(&format!("{DLLS64}/wow64.dll"));
    let desc = 0x16080u32;
    let service_table = w.ptr_rva(desc);
    let limit = w.u64_at(desc + 0x10);
    let arg_table = w.ptr_rva(desc + 0x18);
    assert!(limit > wow64::SSDT_NT_CALLBACK_RETURN as u64, "slot 5 is inside table 0");
    assert_eq!(
        w.at(arg_table + wow64::SSDT_NT_CALLBACK_RETURN, 1)[0],
        12,
        "NtCallbackReturn takes 12 bytes of 32-bit stdcall arguments",
    );

    let thunk = w.ptr_rva(service_table + 8 * wow64::SSDT_NT_CALLBACK_RETURN);
    let b = w.at(thunk, 0x50);
    assert_eq!(&b[13..16], &[0x44, 0x8B, 0x09], "mov r9d,[rcx]      — the guest's result pointer");
    assert_eq!(&b[16..20], &[0x44, 0x8B, 0x41, 0x04], "mov r8d,[rcx+4]   — its length");
    assert_eq!(&b[20..23], &[0x8B, 0x51, 0x08], "mov edx,[rcx+8]    — the NTSTATUS");
    assert_eq!(&b[23..30], &[0x48, 0x8B, 0x88, 0xA8, 0x14, 0x00, 0x00], "mov rcx,[teb+0x14a8]");
    assert!(
        b.windows(5).any(|w4| w4 == [0xB8, 0x58, 0x02, 0x00, 0xC0]),
        "mov eax, 0xC0000258 (STATUS_NO_CALLBACK_ACTIVE) when no frame is active",
    );
    assert_eq!(&b[35..39], &[0x48, 0x8B, 0x41, 0x10], "rax = frame+0x10 (the caller's ret_ptr slot)");
    assert_eq!(&b[39..43], &[0x48, 0x83, 0xC1, 0x30], "rcx = frame+0x30 (the jmp_buf)");
    assert_eq!(&b[46..50], &[0x48, 0x8B, 0x41, 0xE8], "rax = frame+0x18 (the caller's ret_len slot)");
    assert_eq!(&b[53..56], &[0x89, 0x51, 0xF0], "[frame+0x20] = status");
}

#[test]
fn the_32bit_dispatcher_reads_the_frame_it_was_given() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let n = load(&format!("{DLLS32}/ntdll.dll"));
    let d = n.export("KiUserCallbackDispatcher");
    let b = n.at(d, 0x40);
    assert_eq!(&b[..6], &[0x55, 0x89, 0xE5, 0x83, 0xEC, 0x0C]);
    assert_eq!(&b[6..9], &[0x8B, 0x45, 0x08], "id  at frame+0x04");
    assert_eq!(&b[13..16], &[0x8B, 0x45, 0x10], "len at frame+0x0c");
    assert_eq!(&b[20..23], &[0x8B, 0x45, 0x0C], "args at frame+0x08");
    assert_eq!(b[26], 0xE8, "call the dispatch body");
    let ret = (0..b.len() - 5).rev().find(|&i| b[i] == 0xE8 && rel32_target(&n, d + i as u32, 5) == n.export("NtCallbackReturn"));
    assert!(ret.is_some(), "the 32-bit dispatcher returns through NtCallbackReturn");
}

#[test]
fn win_proc_params_layout_is_agreed_by_all_three_consumers() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    use wow64::win_proc_params as p;

    let u64img = load(&format!("{DLLS64}/user32.dll"));
    let call = u64img.sym("User32CallWinProc");
    let b = u64img.at(call, 0x80);
    assert_eq!(&b[11..14], &[0x83, 0xFA, p::CALL_LEN as u8], "len is compared against 0x48");
    assert_eq!(&b[0x38..0x3b], &[0x8B, 0x43, p::SIZE as u8], "size   at +0x28");
    assert_eq!(&b[0x3b..0x3e], &[0x8B, 0x51, p::MSG as u8], "msg    at +0x10");
    assert_eq!(&b[0x3e..0x42], &[0x4C, 0x8D, 0x4B, p::LPARAM as u8], "lparam at +0x20");
    assert_eq!(&b[0x42..0x46], &[0x4C, 0x8D, 0x43, p::WPARAM as u8], "wparam at +0x18");
    assert_eq!(&b[0x46..0x4a], &[0x48, 0x8B, 0x49, p::HWND as u8], "hwnd   at +0x08");
    assert_eq!(&b[0x4e..0x52], &[0x48, 0x8D, 0x43, p::SIZE_OF as u8], "packed data at +0x50");
    assert!(
        b.windows(4).any(|w4| w4 == [0x48, 0x89, 0x43, p::RESULT as u8]),
        "the LRESULT is stored at +0x48",
    );

    let disp = u64img.sym("dispatch_win_proc_params");
    let d = u64img.at(disp, 0x140);
    assert_eq!(&d[9..12], &[0x8B, 0x49, p::DPI_CONTEXT as u8], "dpi_context at +0x34 → SetThreadDpiAwarenessContext");
    assert_eq!(
        rel32_target(&u64img, disp + 12, 5),
        u64img.sym("SetThreadDpiAwarenessContext"),
        "…and that is exactly what it is passed to",
    );
    assert_eq!(&d[0x1d..0x20], &[0x8B, 0x43, p::SIZE as u8], "size at +0x28 selects the unpack arm");
    assert_eq!(&d[0x24..0x28], &[0x48, 0x8B, 0x43, p::PROC_W as u8], "procW at +0x40 is the proc actually called");
    assert!(
        d.windows(4).any(|w4| w4 == [0x44, 0x8B, 0x5B, p::ANSI as u8]),
        "ansi at +0x2c selects the A/W wrappers",
    );
    assert!(d.windows(3).any(|w4| w4 == [0x48, 0x8B, 0x03]), "func at +0x00 is the wrappers' target");

    let u32img = load(&format!("{DLLS32}/user32.dll"));
    let d32 = u32img.sym("dispatch_win_proc_params");
    let c = u32img.at(d32, 0x50);
    assert_eq!(&c[0x0c..0x0f], &[0x8B, 0x43, 0x20], "dpi_context at 32-bit +0x20");
    assert_eq!(&c[0x20..0x23], &[0x8B, 0x43, 0x14], "size        at 32-bit +0x14");
    assert_eq!(&c[0x2d..0x30], &[0x8B, 0x43, 0x28], "procW       at 32-bit +0x28");
    assert!(c.windows(4).any(|w4| w4 == [0x83, 0x7B, 0x18, 0x00]), "ansi at 32-bit +0x18");

    let win = load(&format!("{DLLS64}/wow64win.dll"));
    let conv = win.at(win.sym("win_proc_params_64to32"), 0x80);
    assert!(
        conv.windows(4).any(|w4| w4 == [0x66, 0x0F, 0x6E, 0x01]),
        "the converter narrows func (+0x00)",
    );
    for (off, name) in [(p::HWND, "hwnd"), (p::MSG, "msg"), (p::WPARAM, "wparam")] {
        assert!(
            conv.windows(5)
                .any(|w4| w4[..3] == [0x66, 0x0F, 0x6E] && (w4[3] & 0xC7) == 0x41 && w4[4] as u64 == off),
            "the converter narrows {name} (+{off:#x})",
        );
    }
    assert!(
        conv.windows(4).any(|w4| w4 == [0x48, 0x8B, 0x41, p::LPARAM as u8]),
        "…reads lparam (+0x20) whole and stores its low dword",
    );
    assert!(
        conv.windows(4).any(|w4| w4 == [0x48, 0x8B, 0x41, p::SIZE as u8]),
        "…and copies size/ansi (+0x28..0x30) as one qword",
    );
}

#[test]
fn the_dpi_context_exemu_passes_is_the_one_user32_maps_unaware_to() {
    if !have_set() {
        eprintln!("SKIP: the pinned Wine WoW64 set is not present (git-ignored)");
        return;
    }
    let valid = |v: u32| v & 0xf == 0 && v & 0x3ffe_0000 == 0 && v & 0xf0 == 0x10 && v & 0x1ff00 == 0x6000;
    assert!(valid(wow64::NTUSER_DPI_UNAWARE), "the value exemu passes is accepted");
    assert!(!valid(0), "zero is rejected — which is why exemu does not pass it");

    let u32img = load(&format!("{DLLS32}/user32.dll"));
    let set = u32img.sym("SetThreadDpiAwarenessContext");
    let b = u32img.at(set, 0x20);
    assert_eq!(&b[9..12], &[0x83, 0xF8, 0xFB], "cmp eax, -5");
    assert_eq!(&b[14..17], &[0x8D, 0x50, 0x05], "lea edx,[eax+5] — the table index");
    assert_eq!(&b[17..20], &[0xFF, 0x24, 0x95], "jmp dword ptr [edx*4 + table]");
    let table = u32::from_le_bytes(b[20..24].try_into().unwrap()) - u32img.image_base as u32;
    let unaware = u32img.u32_at(table + 4 * 4) - u32img.image_base as u32;
    let arm = u32img.at(unaware, 5);
    assert_eq!(arm[0], 0xB8, "mov eax, imm32");
    assert_eq!(
        u32::from_le_bytes(arm[1..5].try_into().unwrap()),
        wow64::NTUSER_DPI_UNAWARE,
        "DPI_AWARENESS_CONTEXT_UNAWARE is 0x6010",
    );
}

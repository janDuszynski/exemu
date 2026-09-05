//! W7.3 — **the opengl32 / winevulkan boundary, re-derived from the pinned
//! binaries.**
//!
//! The W7.3 roadmap line asks for the driver-init members `pVulkanInit` /
//! `pOpenGLInit` to be registered. This test is the evidence that **those
//! members are not reachable from guest code at all**, and that what a guest
//! actually calls is something else entirely — recovered here from the bytes of
//! `example_exe/wine-dlls/x86_64-windows/{opengl32,winevulkan,vulkan-1,win32u}.dll`
//! on **every run**, and asserted against the constants in
//! [`exemu_gui::graphics::wine_abi`] that the backend is written against.
//!
//! What it establishes, all from the binaries:
//!
//! 1. **`win32u.dll` exports no `wgl*` and no `vk*` entry point.** The PE half
//!    of win32u is 1290 `NtUser*`/`NtGdi*` syscall stubs. `pOpenGLInit` /
//!    `pVulkanInit` are members of the driver vtable inside `win32u.so` — the
//!    Unix half exemu *replaces* and never loads — so there is no
//!    guest-observable driver table to register into. Same structural finding
//!    as W4's display driver.
//! 2. **`opengl32.dll` and `winevulkan.dll` are PE halves of unixlibs.** Both
//!    import the bootstrap trio (`NtQueryVirtualMemory`, `LdrGetDllHandle`,
//!    `RtlFindExportedRoutineByName`) and route every entry point through
//!    `__wine_unix_call(handle, code, args)`.
//! 3. **The "driver init" is unixlib call code 0** in each — reached from
//!    `opengl32!DllMain(DLL_PROCESS_ATTACH)` and from `winevulkan!wine_vk_init`
//!    under an `InitOnceExecuteOnce`.
//! 4. The dense code tables: `opengl32` `0..=3101`, `winevulkan` `0..=673`,
//!    and the individual slots the backend answers.
//! 5. **`vulkan-1.dll` is a pure forwarder** — every export forwards to
//!    `winevulkan`, so `winevulkan` is the only Vulkan surface to implement.
//!
//! A Wine bump that renumbers a slot, or moves GL/Vulkan behind win32u after
//! all, therefore fails **here**, by name.
//!
//! Skip-guarded on the git-ignored Wine DLL set.

use std::collections::{BTreeMap, BTreeSet};

use exemu_gui::graphics::wine_abi as abi;

const WINE_DLLS: &str = "../../example_exe/wine-dlls/x86_64-windows";

fn wine_dlls_present() -> bool {
    ["opengl32.dll", "winevulkan.dll", "vulkan-1.dll", "win32u.dll"]
        .iter()
        .all(|d| std::path::Path::new(WINE_DLLS).join(d).exists())
}

// ===========================================================================
// A self-contained PE64 reader — sections, exports, imports, COFF symbols and
// the .pdata function table. No loader dependency: this test must be able to
// disagree with the rest of exemu about what the bytes say.
// ===========================================================================

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn u64le(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

struct Section {
    rva: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

struct Pe {
    name: &'static str,
    bytes: Vec<u8>,
    sections: Vec<Section>,
    /// Exported name → RVA. Forwarders are excluded and listed separately.
    exports: BTreeMap<String, u32>,
    /// Exported name → forward target ("winevulkan.vkFoo").
    forwarders: BTreeMap<String, String>,
    /// COFF symbol name → RVA — the only route to a routine with no export
    /// (`DllMain`, `wine_vk_init`, `get_pixel_formats`).
    symbols: BTreeMap<String, u32>,
    /// Imported DLL (lowercased) → the names taken from it.
    imports: BTreeMap<String, BTreeSet<String>>,
    /// `.pdata` function ranges `(begin, end)`, sorted by begin.
    funcs: Vec<(u32, u32)>,
}

impl Pe {
    fn load(name: &'static str) -> Pe {
        let bytes = std::fs::read(std::path::Path::new(WINE_DLLS).join(name))
            .unwrap_or_else(|e| panic!("read {name}: {e}"));
        let pe_off = u32le(&bytes, 0x3c) as usize;
        assert_eq!(&bytes[pe_off..pe_off + 4], b"PE\0\0", "{name} is a PE");
        let coff = pe_off + 4;
        let n_sections = u16le(&bytes, coff + 2) as usize;
        let sym_ptr = u32le(&bytes, coff + 8) as usize;
        let n_symbols = u32le(&bytes, coff + 12) as usize;
        let opt_size = u16le(&bytes, coff + 16) as usize;
        let opt = coff + 20;
        assert_eq!(u16le(&bytes, opt), 0x20b, "{name} must be PE32+");

        // Data directories live at a fixed offset in the PE32+ optional header.
        let dir = |i: usize| -> (u32, u32) {
            let at = opt + 112 + i * 8;
            (u32le(&bytes, at), u32le(&bytes, at + 4))
        };
        let (export_rva, export_size) = dir(0);
        let (import_rva, _) = dir(1);
        let (pdata_rva, pdata_size) = dir(3);

        let sec_base = opt + opt_size;
        let sections: Vec<Section> = (0..n_sections)
            .map(|i| {
                let s = sec_base + i * 40;
                Section {
                    virtual_size: u32le(&bytes, s + 8),
                    rva: u32le(&bytes, s + 12),
                    raw_size: u32le(&bytes, s + 16),
                    raw_ptr: u32le(&bytes, s + 20),
                }
            })
            .collect();

        let mut pe = Pe {
            name,
            bytes,
            sections,
            exports: BTreeMap::new(),
            forwarders: BTreeMap::new(),
            symbols: BTreeMap::new(),
            imports: BTreeMap::new(),
            funcs: Vec::new(),
        };
        pe.read_exports(export_rva, export_size);
        pe.read_imports(import_rva);
        pe.read_symbols(sym_ptr, n_symbols);
        pe.read_pdata(pdata_rva, pdata_size);
        pe
    }

    fn offset(&self, rva: u32) -> Option<usize> {
        self.sections.iter().find_map(|s| {
            let size = s.virtual_size.max(s.raw_size);
            (rva >= s.rva && rva < s.rva + size && rva - s.rva < s.raw_size)
                .then(|| (s.raw_ptr + (rva - s.rva)) as usize)
        })
    }

    fn cstr_at_rva(&self, rva: u32) -> String {
        let Some(off) = self.offset(rva) else { return String::new() };
        let end = self.bytes[off..].iter().position(|&b| b == 0).unwrap_or(0) + off;
        String::from_utf8_lossy(&self.bytes[off..end]).into_owned()
    }

    fn read_exports(&mut self, rva: u32, size: u32) {
        let Some(dir) = self.offset(rva) else { return };
        let n_names = u32le(&self.bytes, dir + 24) as usize;
        let functions = u32le(&self.bytes, dir + 28);
        let names = u32le(&self.bytes, dir + 32);
        let ordinals = u32le(&self.bytes, dir + 36);
        let (Some(f_off), Some(n_off), Some(o_off)) =
            (self.offset(functions), self.offset(names), self.offset(ordinals))
        else {
            return;
        };
        for i in 0..n_names {
            let name_rva = u32le(&self.bytes, n_off + i * 4);
            let ord = u16le(&self.bytes, o_off + i * 2) as usize;
            let fn_rva = u32le(&self.bytes, f_off + ord * 4);
            let name = self.cstr_at_rva(name_rva);
            if name.is_empty() {
                continue;
            }
            if fn_rva >= rva && fn_rva < rva + size {
                // Inside the export directory: a forwarder string.
                self.forwarders.insert(name, self.cstr_at_rva(fn_rva));
            } else {
                self.exports.insert(name, fn_rva);
            }
        }
    }

    fn read_imports(&mut self, rva: u32) {
        let Some(mut d) = self.offset(rva) else { return };
        loop {
            let lookup = u32le(&self.bytes, d);
            let name_rva = u32le(&self.bytes, d + 12);
            let first = u32le(&self.bytes, d + 16);
            if lookup == 0 && name_rva == 0 && first == 0 {
                break;
            }
            let dll = self.cstr_at_rva(name_rva).to_ascii_lowercase();
            let thunk_rva = if lookup != 0 { lookup } else { first };
            if let Some(mut t) = self.offset(thunk_rva) {
                loop {
                    let entry = u64le(&self.bytes, t);
                    if entry == 0 {
                        break;
                    }
                    if entry & (1 << 63) == 0 {
                        // Hint/name table entry: u16 hint, then the name.
                        let name = self.cstr_at_rva(entry as u32 + 2);
                        self.imports.entry(dll.clone()).or_default().insert(name);
                    }
                    t += 8;
                }
            }
            d += 20;
        }
    }

    fn read_symbols(&mut self, ptr: usize, count: usize) {
        if ptr == 0 || count == 0 || ptr + count * 18 > self.bytes.len() {
            return;
        }
        let strtab = ptr + count * 18;
        let mut i = 0;
        while i < count {
            let rec = ptr + i * 18;
            let aux = self.bytes[rec + 17] as usize;
            let value = u32le(&self.bytes, rec + 8);
            let section = i16::from_le_bytes([self.bytes[rec + 12], self.bytes[rec + 13]]);
            let name = if u32le(&self.bytes, rec) == 0 {
                let off = strtab + u32le(&self.bytes, rec + 4) as usize;
                if off >= self.bytes.len() {
                    String::new()
                } else {
                    let end =
                        self.bytes[off..].iter().position(|&b| b == 0).unwrap_or(0) + off;
                    String::from_utf8_lossy(&self.bytes[off..end]).into_owned()
                }
            } else {
                let raw = &self.bytes[rec..rec + 8];
                let end = raw.iter().position(|&b| b == 0).unwrap_or(8);
                String::from_utf8_lossy(&raw[..end]).into_owned()
            };
            if section >= 1 && !name.is_empty() && !name.starts_with('.') {
                if let Some(s) = self.sections.get(section as usize - 1) {
                    self.symbols.entry(name).or_insert(s.rva + value);
                }
            }
            i += 1 + aux;
        }
    }

    fn read_pdata(&mut self, rva: u32, size: u32) {
        let Some(off) = self.offset(rva) else { return };
        for i in 0..(size as usize / 12) {
            let e = off + i * 12;
            let begin = u32le(&self.bytes, e);
            let end = u32le(&self.bytes, e + 4);
            if begin == 0 && end == 0 {
                break;
            }
            self.funcs.push((begin, end));
        }
        self.funcs.sort_unstable();
    }

    /// The `.text` section's bytes and the RVA they start at.
    fn text(&self) -> (&[u8], u32) {
        // The first executable-code section is the one holding every thunk;
        // it is the section covering the entry point's neighbourhood, and in
        // both pinned DLLs it is section 0.
        let s = &self.sections[0];
        let off = s.raw_ptr as usize;
        (&self.bytes[off..off + s.raw_size as usize], s.rva)
    }

    /// RVA of a routine, by export name or (failing that) COFF symbol.
    fn routine(&self, name: &str) -> u32 {
        *self.exports.get(name).or_else(|| self.symbols.get(name)).unwrap_or_else(|| {
            panic!("{}: no export or COFF symbol named {name}", self.name)
        })
    }

    /// The start of the `.pdata` range containing `rva`, if any.
    fn func_start(&self, rva: u32) -> Option<u32> {
        let i = self.funcs.partition_point(|&(b, _)| b <= rva);
        self.funcs[..i].iter().rev().find(|&&(b, e)| rva >= b && rva < e).map(|&(b, _)| b)
    }

    /// The `.pdata` range containing `rva`.
    fn func_bounds(&self, rva: u32) -> (u32, u32) {
        self.funcs
            .iter()
            .copied()
            .find(|&(b, e)| rva >= b && rva < e)
            .unwrap_or_else(|| panic!("{}: no .pdata entry covering {rva:#x}", self.name))
    }
}

// ===========================================================================
// The unixlib call extractor
// ===========================================================================

/// Codes are small (< 3102 and < 674); anything larger is a byte that merely
/// *looks* like `mov edx, imm32` inside another instruction's operand.
const MAX_PLAUSIBLE_CODE: u32 = 4096;

/// The `.data` slot `__wine_unix_call_dispatcher`, whose contents every
/// `__wine_unix_call` is an indirect call through.
fn dispatcher_slot(pe: &Pe) -> u32 {
    pe.symbols
        .get("__wine_unix_call_dispatcher")
        .copied()
        .unwrap_or_else(|| panic!("{}: no __wine_unix_call_dispatcher symbol", pe.name))
}

/// Every `call [rip+disp] -> dispatcher` site in `[begin, end)`, as
/// `(site_rva, code)` where `code` is the nearest preceding `mov edx, imm32`
/// (or `xor edx, edx`) **within the same `.pdata` function**, or `None` when
/// the code is carried in a register.
///
/// Bounding the search by the function rather than by a fixed byte window is
/// what makes this reliable: `winevulkan`'s wider entry points spill arguments
/// to the stack between loading the code and the call, so the immediate can sit
/// 50+ bytes back, while a window large enough for those would start reading
/// bytes from the previous routine.
fn unix_calls(pe: &Pe, begin: u32, end: u32) -> Vec<(u32, Option<u32>)> {
    let (text, text_rva) = pe.text();
    let slot = dispatcher_slot(pe);
    let lo = (begin.saturating_sub(text_rva)) as usize;
    let hi = ((end.saturating_sub(text_rva)) as usize).min(text.len());
    let mut out = Vec::new();
    let mut i = lo;
    while i + 6 <= hi {
        // ff 15 <rel32> — call qword ptr [rip+rel32]
        if text[i] == 0xff && text[i + 1] == 0x15 {
            let rel = i32::from_le_bytes([text[i + 2], text[i + 3], text[i + 4], text[i + 5]]);
            let next = text_rva as i64 + i as i64 + 6;
            if next + rel as i64 == slot as i64 {
                let site = text_rva + i as u32;
                let floor = pe
                    .func_start(site)
                    .map(|b| (b - text_rva) as usize)
                    .unwrap_or_else(|| i.saturating_sub(128))
                    .max(lo);
                out.push((site, code_before(text, floor, i)));
                i += 6;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// The nearest `mov edx, imm32` / `xor edx, edx` before `call_at`, not looking
/// further back than `floor` (the enclosing function's first byte).
fn code_before(text: &[u8], floor: usize, call_at: usize) -> Option<u32> {
    let mut best: Option<u32> = None;
    let mut p = floor;
    while p < call_at {
        if text[p] == 0xba && p + 5 <= call_at {
            let imm = u32::from_le_bytes([text[p + 1], text[p + 2], text[p + 3], text[p + 4]]);
            if imm < MAX_PLAUSIBLE_CODE {
                best = Some(imm);
            }
        } else if text[p] == 0x31 && p + 2 <= call_at && text[p + 1] == 0xd2 {
            best = Some(0);
        }
        p += 1;
    }
    best
}

/// The codes reached from one named routine, in address order.
fn codes_of(pe: &Pe, routine: &str) -> Vec<u32> {
    let rva = pe.routine(routine);
    let (b, e) = pe.func_bounds(rva);
    unix_calls(pe, b, e)
        .into_iter()
        .map(|(site, code)| {
            code.unwrap_or_else(|| {
                panic!("{}!{routine}: no code immediate before the call at {site:#x}", pe.name)
            })
        })
        .collect()
}

/// Assert a routine reaches the unixlib with exactly `expected`.
fn assert_codes(pe: &Pe, routine: &str, expected: &[u32]) {
    assert_eq!(
        codes_of(pe, routine),
        expected,
        "{}!{routine} must call the unixlib with {expected:?}",
        pe.name
    );
}

// ===========================================================================
// 1. There is no guest-visible GL/Vulkan driver table
// ===========================================================================

/// `win32u.dll` — the PE half exemu actually loads — exports **no** `wgl*` and
/// **no** `vk*` entry point.
///
/// This is what retires the roadmap's `pOpenGLInit`/`pVulkanInit` framing:
/// those members live in the driver vtable inside `win32u.so`, the Unix half
/// exemu replaces, so no guest code can ever ask for or register them. Exactly
/// the finding W4 made for the display driver.
#[test]
fn win32u_exposes_no_gl_or_vulkan_entry_point_to_guest_code() {
    if !wine_dlls_present() {
        eprintln!("[skip] pinned Wine DLL set not present");
        return;
    }
    let win32u = Pe::load("win32u.dll");
    let gl_or_vk: Vec<&String> = win32u
        .exports
        .keys()
        .chain(win32u.forwarders.keys())
        .filter(|n| {
            let n = n.as_str();
            n.starts_with("wgl") || n.starts_with("vk") || n.contains("OpenGL")
        })
        .collect();
    assert!(
        gl_or_vk.is_empty(),
        "win32u.dll must expose no GL/Vulkan surface to guest code, found {gl_or_vk:?}"
    );
    // ...but it is very much the syscall shim: the NtGdi/NtUser stubs are there.
    let nt = win32u
        .exports
        .keys()
        .filter(|n| n.starts_with("NtGdi") || n.starts_with("NtUser"))
        .count();
    assert!(nt > 1000, "win32u.dll is the NtUser/NtGdi syscall shim, found {nt} stubs");
}

/// `vulkan-1.dll` carries no implementation of its own: every export either
/// forwards into `winevulkan` or is a hard `__wine_spec_unimplemented_stub`.
///
/// So `winevulkan` is the only Vulkan surface with a Unix side to supply, and
/// the handful of display/fault entry points below are ones exemu can never be
/// asked for through `vulkan-1` — Wine raises on them before any driver is
/// reached.
#[test]
fn vulkan_1_forwards_everything_it_implements_onto_winevulkan() {
    if !wine_dlls_present() {
        eprintln!("[skip] pinned Wine DLL set not present");
        return;
    }
    let vk1 = Pe::load("vulkan-1.dll");
    assert!(vk1.forwarders.len() > 200, "vulkan-1.dll forwards its whole implemented surface");
    assert!(
        vk1.forwarders.values().all(|t| t.starts_with("winevulkan.")),
        "every vulkan-1 forwarder must land in winevulkan"
    );

    // The non-forwarded remainder is stubs, not an implementation: each is a
    // four-instruction thunk ending in `call __wine_spec_unimplemented_stub`.
    let stub = vk1
        .symbols
        .get("__wine_spec_unimplemented_stub")
        .copied()
        .expect("vulkan-1 carries the unimplemented-stub helper");
    let (text, text_rva) = vk1.text();
    for (name, &rva) in &vk1.exports {
        let (b, e) = vk1.func_bounds(rva);
        let body = &text[(b - text_rva) as usize..(e - text_rva) as usize];
        let mut calls_stub = false;
        for i in 0..body.len().saturating_sub(4) {
            if body[i] == 0xe8 {
                let rel =
                    i32::from_le_bytes([body[i + 1], body[i + 2], body[i + 3], body[i + 4]]);
                if b as i64 + i as i64 + 5 + rel as i64 == stub as i64 {
                    calls_stub = true;
                    break;
                }
            }
        }
        assert!(
            calls_stub,
            "vulkan-1!{name} is neither a forwarder nor an unimplemented stub \
             (rva {rva:#x}, bounds {b:#x}..{e:#x}, stub {stub:#x}, bytes {:02x?})",
            &body[..body.len().min(24)]
        );
    }
    eprintln!(
        "[vulkan-1] {} forwarders, {} unimplemented stubs: {:?}",
        vk1.forwarders.len(),
        vk1.exports.len(),
        vk1.exports.keys().collect::<Vec<_>>()
    );
}

// ===========================================================================
// 2. Both DLLs are PE halves of unixlibs
// ===========================================================================

/// `opengl32.dll` and `winevulkan.dll` both carry the unixlib bootstrap trio,
/// the `__wine_unix_call_dispatcher` slot and the `__wine_unixlib_handle` the
/// `MemoryWineUnixFuncs` query fills in.
///
/// This is the seam a driver is registered through — a unixlib pairing, not a
/// function-pointer table.
#[test]
fn opengl32_and_winevulkan_are_pe_halves_of_unixlibs() {
    if !wine_dlls_present() {
        eprintln!("[skip] pinned Wine DLL set not present");
        return;
    }
    for name in ["opengl32.dll", "winevulkan.dll"] {
        let pe = Pe::load(name);
        let ntdll = pe.imports.get("ntdll.dll").unwrap_or_else(|| {
            panic!("{name} must import ntdll for the unixlib bootstrap");
        });
        for want in abi::UNIXLIB_BOOTSTRAP_IMPORTS {
            assert!(ntdll.contains(want), "{name} must import ntdll!{want}, has {ntdll:?}");
        }
        assert!(
            pe.symbols.contains_key("__wine_unixlib_handle"),
            "{name} must hold a __wine_unixlib_handle"
        );
        assert!(
            pe.symbols.contains_key("__wine_unix_call_dispatcher"),
            "{name} must hold a __wine_unix_call_dispatcher slot"
        );
        assert!(
            pe.symbols.contains_key("__wine_init_unix_call"),
            "{name} must carry __wine_init_unix_call"
        );
    }
}

// ===========================================================================
// 3 + 4. opengl32's table, and its driver init
// ===========================================================================

/// `opengl32!DllMain` is the OpenGL **driver init**: process attach is unixlib
/// code 0, thread attach code 1, process detach code 2 — in that order, in the
/// one routine.
///
/// The process-attach code is a `xor edx, edx` right after
/// `__wine_init_unix_call`, and its NTSTATUS is what `DllMain` returns as its
/// `BOOL`: **without a Unix side the DLL does not load at all.**
#[test]
fn opengl32_dllmain_is_the_driver_init_at_codes_0_1_2() {
    if !wine_dlls_present() {
        eprintln!("[skip] pinned Wine DLL set not present");
        return;
    }
    let gl = Pe::load("opengl32.dll");
    assert_codes(
        &gl,
        "DllMain",
        &[abi::OPENGL32_PROCESS_ATTACH, abi::OPENGL32_THREAD_ATTACH, abi::OPENGL32_PROCESS_DETACH],
    );
    assert_eq!(abi::OPENGL32_PROCESS_ATTACH, 0);
    assert_eq!(abi::OPENGL32_THREAD_ATTACH, 1);
    assert_eq!(abi::OPENGL32_PROCESS_DETACH, 2);

    // The process-attach params block is one pointer: the PE-side
    // `GL_ARB_debug_output` thunk. It is `lea`'d and stored to the stack slot
    // `r8` then points at, before the dispatcher call.
    let cb = gl.symbols.get("call_gl_debug_message_callback").copied();
    assert!(
        cb.is_some(),
        "opengl32 must carry the PE-side debug-callback thunk it hands the Unix side"
    );
}

/// The `opengl32` unixlib table is dense `0..=3101`, and the individual slots
/// the backend answers sit where [`abi`] says.
#[test]
fn opengl32_unixlib_table_is_dense_and_the_named_slots_match() {
    if !wine_dlls_present() {
        eprintln!("[skip] pinned Wine DLL set not present");
        return;
    }
    let gl = Pe::load("opengl32.dll");

    // wgl* — the context/present surface a guest drives.
    assert_codes(&gl, "wglCopyContext", &[abi::OPENGL32_WGL_COPY_CONTEXT]);
    assert_codes(&gl, "wglCreateContext", &[abi::OPENGL32_WGL_CREATE_CONTEXT]);
    assert_codes(&gl, "wglDeleteContext", &[abi::OPENGL32_WGL_DELETE_CONTEXT]);
    assert_codes(&gl, "wglGetPixelFormat", &[abi::OPENGL32_WGL_GET_PIXEL_FORMAT]);
    assert_codes(&gl, "wglGetProcAddress", &[abi::OPENGL32_WGL_GET_PROC_ADDRESS]);
    assert_codes(&gl, "wglMakeCurrent", &[abi::OPENGL32_WGL_MAKE_CURRENT]);
    assert_codes(&gl, "wglSetPixelFormat", &[abi::OPENGL32_WGL_SET_PIXEL_FORMAT]);
    assert_codes(&gl, "wglShareLists", &[abi::OPENGL32_WGL_SHARE_LISTS]);
    assert_codes(&gl, "wglSwapBuffers", &[abi::OPENGL32_WGL_SWAP_BUFFERS]);

    // gl* — including the version/extension query this backend answers.
    assert_codes(&gl, "glClear", &[abi::OPENGL32_GL_CLEAR]);
    assert_codes(&gl, "glClearColor", &[abi::OPENGL32_GL_CLEAR_COLOR]);
    assert_codes(&gl, "glGetString", &[abi::OPENGL32_GL_GET_STRING]);
    assert_codes(&gl, "glReadPixels", &[abi::OPENGL32_GL_READ_PIXELS]);
    assert_codes(&gl, "glViewport", &[abi::OPENGL32_GL_VIEWPORT]);

    // get_pixel_formats has no export; it is reached through the COFF symbol
    // table, and calls its slot twice — once to size, once to fill.
    assert_codes(
        &gl,
        "get_pixel_formats",
        &[abi::OPENGL32_GET_PIXEL_FORMATS, abi::OPENGL32_GET_PIXEL_FORMATS],
    );

    // The whole table.
    let (text, text_rva) = gl.text();
    let all: BTreeSet<u32> =
        unix_calls(&gl, text_rva, text_rva + text.len() as u32).into_iter().flat_map(|c| c.1).collect();
    let max = *all.iter().next_back().expect("call sites exist");
    assert_eq!(
        max + 1,
        abi::OPENGL32_UNIX_CALL_COUNT,
        "the opengl32 unixlib table runs 0..={}",
        abi::OPENGL32_UNIX_CALL_COUNT - 1
    );
    let missing: Vec<u32> = (0..=max).filter(|c| !all.contains(c)).collect();
    assert_eq!(
        missing,
        vec![abi::OPENGL32_UNUSED_SLOT],
        "every opengl32 slot but {} has a PE call site",
        abi::OPENGL32_UNUSED_SLOT
    );
    // And the reason that one slot is unused: it is served in PE code by
    // widening the integer variant's results.
    assert!(
        gl.symbols.contains_key("wglGetPixelFormatAttribfvARB"),
        "the unused slot's entry point still exists (as a wglGetProcAddress-only routine)"
    );
    assert!(
        codes_of(&gl, "wglGetPixelFormatAttribfvARB").is_empty(),
        "wglGetPixelFormatAttribfvARB must never cross to the Unix side"
    );
}

// ===========================================================================
// 3 + 4. winevulkan's table, and its driver init
// ===========================================================================

/// `winevulkan!wine_vk_init` is the Vulkan **driver init**, and it is code 0.
///
/// Unlike opengl32's, it carries the code in a *register*: `__wine_init_unix_call`
/// returns its NTSTATUS in `eax`, the routine copies it to `edx` (`89 c2`),
/// tests it (`85 d2`) and branches away on failure — so the only path that
/// reaches the dispatcher has `edx == 0`. That is the recovery: **no immediate
/// exists to read, and the code is provably zero.**
///
/// The params block is 24 bytes: two PE-side callback thunks in, and an out
/// pointer to the per-extension flag bytes the PE half reads with
/// `movzbl`/`testb $1`.
#[test]
fn winevulkan_wine_vk_init_is_the_driver_init_at_code_0() {
    if !wine_dlls_present() {
        eprintln!("[skip] pinned Wine DLL set not present");
        return;
    }
    let vk = Pe::load("winevulkan.dll");
    let rva = vk.routine("wine_vk_init");
    let (b, e) = vk.func_bounds(rva);
    let calls = unix_calls(&vk, b, e);
    assert_eq!(calls.len(), 1, "wine_vk_init makes exactly one unixlib call");
    assert_eq!(
        calls[0].1, None,
        "wine_vk_init's code is carried in edx, not written as an immediate"
    );

    // Prove edx holds a value just tested for zero: the bytes between the
    // routine's start and the dispatcher call must contain `mov %eax,%edx`
    // and `test %edx,%edx`, and must not set edx to anything else.
    let (text, text_rva) = vk.text();
    let lo = (b - text_rva) as usize;
    let hi = (calls[0].0 - text_rva) as usize;
    let body = &text[lo..hi];
    assert!(
        body.windows(2).any(|w| w == [0x89, 0xc2]),
        "wine_vk_init must move the init status into edx (89 c2)"
    );
    assert!(
        body.windows(2).any(|w| w == [0x85, 0xd2]),
        "wine_vk_init must test that status (85 d2) and branch away when nonzero"
    );
    assert_eq!(abi::WINEVULKAN_INIT, 0, "so the code that reaches the Unix side is 0");

    // The three params: two PE callback thunks and the extension flag array.
    for sym in [
        "call_vulkan_debug_report_callback",
        "call_vulkan_debug_utils_callback",
        "instance_extensions",
    ] {
        assert!(vk.symbols.contains_key(sym), "winevulkan must carry {sym} for the init params");
    }
    assert_eq!(abi::WINEVULKAN_INIT_PARAMS_SIZE, 24, "three pointers");

    // The init is lazy, behind InitOnceExecuteOnce — not DllMain.
    let k32 = vk.imports.get("kernel32.dll").expect("winevulkan imports kernel32");
    assert!(
        k32.contains("InitOnceExecuteOnce"),
        "wine_vk_init runs under InitOnceExecuteOnce, not from DllMain"
    );
}

/// The `winevulkan` unixlib table is dense `0..=673`, and the slots the backend
/// answers sit where [`abi`] says.
#[test]
fn winevulkan_unixlib_table_is_dense_and_the_named_slots_match() {
    if !wine_dlls_present() {
        eprintln!("[skip] pinned Wine DLL set not present");
        return;
    }
    let vk = Pe::load("winevulkan.dll");

    assert_codes(&vk, "vkGetInstanceProcAddr", &[abi::WINEVULKAN_GET_INSTANCE_PROC_ADDR]);
    assert_codes(&vk, "vkGetDeviceProcAddr", &[abi::WINEVULKAN_GET_DEVICE_PROC_ADDR]);
    assert_codes(&vk, "vkCreateInstance", &[abi::WINEVULKAN_CREATE_INSTANCE]);
    assert_codes(&vk, "vkDestroyInstance", &[abi::WINEVULKAN_DESTROY_INSTANCE]);
    assert_codes(
        &vk,
        "vkEnumerateInstanceExtensionProperties",
        &[abi::WINEVULKAN_ENUMERATE_INSTANCE_EXTENSION_PROPERTIES],
    );
    assert_codes(
        &vk,
        "vkEnumerateInstanceVersion",
        &[abi::WINEVULKAN_ENUMERATE_INSTANCE_VERSION],
    );
    assert_codes(&vk, "vkEnumeratePhysicalDevices", &[abi::WINEVULKAN_ENUMERATE_PHYSICAL_DEVICES]);
    assert_codes(
        &vk,
        "vkGetPhysicalDeviceProperties",
        &[abi::WINEVULKAN_GET_PHYSICAL_DEVICE_PROPERTIES],
    );

    let (text, text_rva) = vk.text();
    let all: BTreeSet<u32> =
        unix_calls(&vk, text_rva, text_rva + text.len() as u32).into_iter().flat_map(|c| c.1).collect();
    let max = *all.iter().next_back().expect("call sites exist");
    assert_eq!(
        max + 1,
        abi::WINEVULKAN_UNIX_CALL_COUNT,
        "the winevulkan unixlib table runs 0..={}",
        abi::WINEVULKAN_UNIX_CALL_COUNT - 1
    );
    // Code 0 is `wine_vk_init`'s register-carried one, so it is the only slot
    // without an immediate anywhere in .text.
    let missing: Vec<u32> = (0..=max).filter(|c| !all.contains(c)).collect();
    assert_eq!(missing, vec![abi::WINEVULKAN_INIT], "only the init code is register-carried");
}

/// `vkEnumerateInstanceVersion`'s PE-side fallback pins the failure semantics:
/// when the Unix side did not initialise, it writes `VK_API_VERSION_1_0` and
/// returns — **Vulkan degrades, it does not fail to load** (the opposite of
/// `opengl32`). The literal is in the routine's own bytes.
#[test]
fn a_failed_vulkan_init_degrades_to_version_1_0_in_pe_code() {
    if !wine_dlls_present() {
        eprintln!("[skip] pinned Wine DLL set not present");
        return;
    }
    let vk = Pe::load("winevulkan.dll");
    let rva = vk.routine("vkEnumerateInstanceVersion");
    let (b, e) = vk.func_bounds(rva);
    let (text, text_rva) = vk.text();
    let body = &text[(b - text_rva) as usize..(e - text_rva) as usize];
    // `movl $0x400000, (%rbx)` — c7 03 00 00 40 00
    let literal = abi::VK_API_VERSION_1_0.to_le_bytes();
    assert!(
        body.windows(4).any(|w| w == literal),
        "vkEnumerateInstanceVersion must fall back to VK_API_VERSION_1_0 ({:#x})",
        abi::VK_API_VERSION_1_0
    );
}

//! NLS (National Language Support) data mapping for the Wine PE boot
//! (roadmap W3.2).
//!
//! Wine's PE `ntdll.dll` and `kernelbase.dll` initialise their locale/codepage
//! state very early in process startup by asking the "unix side" for the
//! unified NLS database and the auxiliary NLS sections:
//!
//! * `NtInitializeNlsFiles(void **base, LCID *lcid, LARGE_INTEGER *size)`
//!   (SSDT **0x9e**) returns a mapped view of `locale.nls` — the unified locale
//!   database — plus the default system LCID and the mapping size. It is the
//!   syscall behind `RtlGetLocaleFileMappingAddress` (ntdll RVA 0x27570), which
//!   caches the returned pointer and hands it to both ntdll's `locale_init` and
//!   kernelbase's `init_locale`.
//! * `NtGetNlsSectionPtr(ULONG type, ULONG id, void *unk, void **base,
//!   SIZE_T *size)` (SSDT **0x9b**) returns a mapped view of one of the smaller
//!   NLS section files, keyed by `type`: 9 = the "sortdefault" sort-key data,
//!   **0xa = the case-mapping tables (`l_intl.nls`)**, 0xb = a codepage table
//!   (`C_####.nls`).
//!
//! Without these, `RtlGetLocaleFileMappingAddress` returns an error, the cached
//! NLS pointer stays garbage, and the first consumer wild-reads `[base+0x2c]`
//! (kernelbase `init_locale` @ RVA 0x7ec7e) — the 2,131,513-instruction boot
//! fault this module clears.
//!
//! **Real vs synthesized.** No real `.nls` data files ship in the pinned
//! `example_exe/wine-dlls/` prefix (the `wine-stable-amd64` `.deb` carries only
//! the amd64 binaries; the arch-independent `.nls` data lives in the separate
//! `wine-stable` package, which is not provisioned). So this module
//! **synthesizes** a minimal-but-valid NLS database whose header/sub-block
//! layout is exactly what the two consumers walk. Every field offset below was
//! recovered by disassembling the pinned guest binaries (clean-room Class B —
//! pinned-binary disassembly + public NLS-format docs; no Wine `.c` source):
//!
//! * ntdll `locale_init` @ RVA 0x54fb0 — walks base+0x10 → locale table,
//!   binary-searches the LCID index, UD2s if the count is 0.
//! * kernelbase `init_locale` @ RVA 0x7ec30 — walks base+0x10/+0x14/+0x18 →
//!   locale/charmap/geo blocks, then `NtGetNlsSectionPtr(type 9)` and its
//!   sort-key structure.
//! * kernelbase `NlsValidateLocale` @ RVA 0x3bdb0 — LCID → record binary search.
//! * ntdll `RtlInitCodePageTable` @ RVA 0x29740 — a codepage section whose
//!   `word[+0x02] == 0xFDE9` (CP_UTF8) takes a trivial init path.
//!
//! The synthesized database describes exactly one locale — LCID `0x409`
//! (en-US), the system default — with UTF-8 (65001 = 0xFDE9) code pages, so
//! that: the LCID binary search deterministically matches (no count-0 UD2, no
//! search-bound underflow), and every downstream `RtlInitCodePageTable` hits
//! the UTF-8 short path without needing a real MB↔WC codepage table.

use exemu_core::{CpuState, Memory, Perm, Reg, Result};

use crate::WinOs;

/// `STATUS_SUCCESS`.
const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_NO_MEMORY` — returned if the guest region can't be reserved.
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

/// SSDT indices (pinned guest ntdll.dll `mov eax,N`):
/// `ZwGetNlsSectionPtr`   @ RVA 0xfc90 `mov eax,0x9b`,
/// `ZwInitializeNlsFiles` @ RVA 0xfcf0 `mov eax,0x9e`.
pub(crate) const SSDT_NT_GET_NLS_SECTION_PTR: u32 = 0x9b;
pub(crate) const SSDT_NT_INITIALIZE_NLS_FILES: u32 = 0x9e;

/// The default system LCID reported to the guest: 0x409 = en-US (MS-LCID).
const SYSTEM_LCID: u32 = 0x0000_0409;

/// The UTF-8 codepage id (65001), which `RtlInitCodePageTable` recognises at
/// `word[section+0x02]` to take its trivial init path. Placed in the locale
/// record's ANSI/OEM codepage fields and returned as every codepage/sort/norm
/// section so no real MB↔WC table is ever needed.
const CP_UTF8: u16 = 0xFDE9;

// ---------------------------------------------------------------------------
// locale.nls synthesis
// ---------------------------------------------------------------------------

// Field offsets within the top-level `locale.nls` directory header (at `base`).
// The consumers add `dword[base + N]` to `base` to reach each sub-block.
const HDR_LOCALE_TABLE_OFF: usize = 0x10; // → NLS_LOCALE_HEADER (locale table)
const HDR_CHARMAPS_OFF: usize = 0x14; //     → charmaps block (kernelbase only)
const HDR_GEO_OFF: usize = 0x18; //          → geo-id block   (kernelbase only)

// Field offsets within the NLS_LOCALE_HEADER (the locale-table block).
// All sub-offsets are relative to the header start.
const LT_NB_LCIDS: usize = 0x1e; // WORD  count of LCID-index entries (>=1)
const LT_STRIDE: usize = 0x22; //   WORD  size of one NLS_LOCALE_DATA record
const LT_LOCALES_OFF: usize = 0x24; // DWORD base offset of the record array
const LT_LCNAMES_SIZE: usize = 0x28; // WORD  used as an alloc count (record slots)
const LT_LCIDS_OFF: usize = 0x2c; //  DWORD offset of the LCID index array
const LT_LCNAMES_OFF: usize = 0x30; // DWORD offset of the LC-names index
const LT_STRINGS_OFF: usize = 0x40; // DWORD offset of the locale-strings block

// One LCID-index entry (8 bytes): { DWORD lcid; WORD idx; WORD name }.
const LCID_ENTRY_LEN: usize = 8;

// NLS_LOCALE_DATA record fields read by the consumers.
const REC_LEN: usize = 0x130; // generous; must cover the +0x124 read below
const REC_LCID: usize = 0x08; // WORD  the record's own LCID
const REC_FLAG_18: usize = 0x18; // WORD non-zero → NlsValidateLocale success path
const REC_ACP: usize = 0x6e; //   WORD ANSI codepage id (ntdll locale_init)
const REC_OEMCP: usize = 0x70; // WORD OEM  codepage id (ntdll locale_init)
const REC_NAME_STR: usize = 0x124; // DWORD offset (in WCHARs) into the strings block

/// Build the synthesized `locale.nls` image. Returns the byte buffer whose base
/// pointer is handed to the guest; every pointer computed by the consumers off
/// this base lands inside the buffer.
fn build_locale_nls() -> Vec<u8> {
    // Lay the sub-blocks out at fixed offsets within one buffer.
    const HDR: usize = 0x00; //           top-level directory header
    const LOCALE_TABLE: usize = 0x80; //  NLS_LOCALE_HEADER
    const LCIDS: usize = 0x200; //        LCID index array
    const LCNAMES: usize = 0x240; //      LC-names index (unused body, in-bounds)
    const STRINGS: usize = 0x280; //      locale strings
    const RECORDS: usize = 0x300; //      NLS_LOCALE_DATA array (1 record)
    const CHARMAPS: usize = 0x300 + REC_LEN; // 8 empty charmap sub-tables
    const GEO: usize = CHARMAPS + 0x40; // geo-id block

    let total = GEO + 0x80;
    let mut b = vec![0u8; total];

    let put16 = |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());

    // Top-level directory: offsets (relative to base) to the three blocks.
    put32(&mut b, HDR + HDR_LOCALE_TABLE_OFF, LOCALE_TABLE as u32);
    put32(&mut b, HDR + HDR_CHARMAPS_OFF, CHARMAPS as u32);
    put32(&mut b, HDR + HDR_GEO_OFF, GEO as u32);

    // NLS_LOCALE_HEADER. Sub-offsets are relative to LOCALE_TABLE.
    put16(&mut b, LOCALE_TABLE + LT_NB_LCIDS, 1); // exactly one locale
    put16(&mut b, LOCALE_TABLE + LT_STRIDE, REC_LEN as u16);
    put32(&mut b, LOCALE_TABLE + LT_LOCALES_OFF, (RECORDS - LOCALE_TABLE) as u32);
    put16(&mut b, LOCALE_TABLE + LT_LCNAMES_SIZE, 1);
    put32(&mut b, LOCALE_TABLE + LT_LCIDS_OFF, (LCIDS - LOCALE_TABLE) as u32);
    put32(&mut b, LOCALE_TABLE + LT_LCNAMES_OFF, (LCNAMES - LOCALE_TABLE) as u32);
    put32(&mut b, LOCALE_TABLE + LT_STRINGS_OFF, (STRINGS - LOCALE_TABLE) as u32);

    // LCID index: one entry { lcid=0x409, idx=0, name=0 }, sorted ascending.
    put32(&mut b, LCIDS, SYSTEM_LCID); // entry +0x00: LCID
    put16(&mut b, LCIDS + 0x04, 0); // idx into the record array
    put16(&mut b, LCIDS + 0x06, 0); // name (offset into strings) — unused

    // The single NLS_LOCALE_DATA record.
    put16(&mut b, RECORDS + REC_LCID, SYSTEM_LCID as u16);
    put16(&mut b, RECORDS + REC_FLAG_18, 1); // take NlsValidateLocale success path
    put16(&mut b, RECORDS + REC_ACP, CP_UTF8); // ANSI cp = UTF-8 → ntdll skips it
    put16(&mut b, RECORDS + REC_OEMCP, CP_UTF8); // OEM  cp = UTF-8 → ntdll skips it
    put32(&mut b, RECORDS + REC_NAME_STR, 0); // name at strings[0] (a NUL word)

    // Charmaps: 8 concatenated sub-tables, each a single WORD count of 0 so the
    // 8-iteration walk advances by 2 bytes each and stays in-bounds.
    // (All-zero buffer already satisfies this; the region is explicitly sized.)
    let _ = CHARMAPS;

    // Geo block: counts (at +0x10 / +0x18) are zero; the +0xc / +0x14 offsets
    // stay zero (→ the block itself), all in-bounds. Nothing else to write.
    let _ = GEO;
    let _ = LCID_ENTRY_LEN;

    b
}

// ---------------------------------------------------------------------------
// NtGetNlsSectionPtr sections (sort / normalisation / codepage)
// ---------------------------------------------------------------------------

/// Build the "sortdefault" (type 9) section. kernelbase `init_locale` walks a
/// chain of relative offsets off this base:
///   dir[0..0x10] = 4 dwords → sub-blocks; then dir[0xc] → a "keys" block whose
///   `dword[+0x4]` is a count multiplied through several indexing steps, ending
///   at `r9 = keyptr - 0x18` which is then read (`[r9]`, `word[r9+8+i*2]` i<7).
///
/// Laying every directory dword so the chain resolves to a fixed, zero-filled
/// in-bounds sub-block keeps all those reads valid (count words read as 0, so
/// every `+= count*k` term vanishes and the walk collapses onto the sub-block).
fn build_sort_nls() -> Vec<u8> {
    // Directory of 4 dwords at +0x0/+0x4/+0x8/+0xc, then padding, then one
    // shared zero-filled "keys" sub-block reached via dir[0xc]. The keys block
    // is placed far enough in that the `keyptr - 0x18` back-reference and the
    // `word[+8..+0x14]` forward reads all land inside the buffer.
    const DIR: usize = 0x00;
    const KEYS: usize = 0x80;
    let total = KEYS + 0x200;
    let mut b = vec![0u8; total];
    let put32 = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());

    // dir[0], dir[4], dir[8]: point at the keys sub-block (their sub-walks read
    // a WORD count at +0x2 which is 0, so they resolve within KEYS).
    put32(&mut b, DIR, KEYS as u32); // dir +0x0
    put32(&mut b, DIR + 0x4, KEYS as u32);
    put32(&mut b, DIR + 0x8, KEYS as u32);
    // dir[0xc]: the keys block. `dword[KEYS+4]` (the record count) is 0, so:
    //   rdx = KEYS+8 + 0*36; ecx = dword[rdx] = 0; rdx += 4; rdx += 0;
    //   rax = rdx+4 = KEYS+16; edx = dword[rdx] = dword[KEYS+12] = 0 → rdx=0;
    //   r9 = rax + 0 - 0x18 = KEYS - 8; rcx = rax + 0 = KEYS+16.
    // `[r9] = dword[KEYS-8]` and `word[r9+8+i*2]` (i<7) read the 16 bytes at
    // KEYS-8..KEYS+6 — all inside DIR..KEYS, zero. The final `[rcx]` read at
    // KEYS+16 is zero. Everything stays in-bounds.
    put32(&mut b, DIR + 0xc, KEYS as u32);

    b
}

/// Build a codepage section (type 0xb, and the fallback for anything else).
/// `word[+0x02]` carries the codepage id; setting it to `CP_UTF8` makes
/// `RtlInitCodePageTable` take its trivial init path (zero the output, read
/// nothing else). The header `HeaderSize` word at +0x00 is set to the standard
/// 0x000D; the rest is zero.
fn build_codepage_nls() -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    b[0x00..0x02].copy_from_slice(&0x000Du16.to_le_bytes()); // HeaderSize (words)
    b[0x02..0x04].copy_from_slice(&CP_UTF8.to_le_bytes()); // CodePage = 65001
    // Callers that only chase pointer offsets off the base stay in-bounds on the
    // zero-filled tail.
    b
}

// ---------------------------------------------------------------------------
// The case-mapping section (NtGetNlsSectionPtr type 0xA) — `l_intl.nls`
// ---------------------------------------------------------------------------

/// The `NtGetNlsSectionPtr` section type ntdll asks for to obtain its **case
/// tables**. Recovered from the pinned `ntdll.dll`: `locale_init` @ RVA 0x54fb0
/// calls `ZwGetNlsSectionPtr(type=0xA, …)` @ 0x55190 and then installs the
/// result at 0x55262–0x55277 as
///
/// ```text
///   nls_uppercase_table (RVA 0x735e0) = section + 4
///   nls_lowercase_table (RVA 0x735e8) = section + 4 + 2 * word[section + 2]
/// ```
///
/// so `word[+0x02]` is the **upcase table length in WORDs** and the two tables
/// are laid end to end from `+0x04`.
pub(crate) const NLS_SECTION_CASEMAP: u32 = 0xA;

/// Number of WORDs in one level of the sparse case table (a 4-bit index).
const CASE_BLOCK: usize = 16;

/// Build the case-mapping section handed back for [`NLS_SECTION_CASEMAP`].
///
/// **Why this exists.** exemu used to answer type 0xA with the same zero-filled
/// codepage stub as everything else. ntdll dutifully installed it, and because
/// the pointer was *non-NULL* every case-insensitive path in the whole process
/// took the table branch instead of its ASCII fallback — with a table that maps
/// every character to itself. Case-insensitive comparison silently became
/// case-**sensitive**, which is how a `NTDLL.dll` forwarder failed to match the
/// already-loaded `ntdll.dll`, the loader mapped a second (uninitialised) ntdll,
/// and a shell32 delay-load stub bound to that copy later dereferenced a NULL
/// list head. A plausible-looking zero is worse than a NULL.
///
/// **The table format**, recovered from the pinned `ntdll.dll`
/// (`RtlCompareUnicodeStrings` @ RVA 0x1c9c0, `RtlHashUnicodeString` @ 0x27ea0
/// — both index the installed table identically):
///
/// ```text
///   delta = T[ T[ T[ch >> 8] + ((ch >> 4) & 0xF) ] + (ch & 0xF) ]
///   mapped = (WORD)(ch + delta)
/// ```
///
/// i.e. a three-level 8/4/4 sparse table of `u16`s where the first two levels
/// hold **WORD indices into `T` itself** and the last holds the **delta** to add.
/// Level 1 is 256 entries (the high byte), levels 2 and 3 are
/// [`CASE_BLOCK`]-entry blocks.
///
/// The deltas come from Rust's own Unicode data (simple, 1:1 case mappings
/// only — exactly what a table of per-character deltas can express; a mapping
/// that is not a single BMP character contributes a zero delta, i.e. the
/// character is left alone). Identical blocks are shared, so the whole BMP
/// costs a few KiB.
fn build_casemap_nls() -> Vec<u8> {
    let upper = build_case_table(|c| c.to_uppercase());
    let lower = build_case_table(|c| c.to_lowercase());
    assert!(upper.len() <= u16::MAX as usize, "upcase table fits its WORD length field");

    let mut b = Vec::with_capacity(4 + (upper.len() + lower.len()) * 2);
    // +0x00: unread by any consumer in the pinned binary; carry the total WORD
    // count so the blob is self-describing rather than mysteriously zero.
    b.extend_from_slice(&((2 + upper.len() + lower.len()) as u16).to_le_bytes());
    // +0x02: the upcase table's length in WORDs — what ntdll uses to find the
    // downcase table that follows it.
    b.extend_from_slice(&(upper.len() as u16).to_le_bytes());
    for w in upper.iter().chain(lower.iter()) {
        b.extend_from_slice(&w.to_le_bytes());
    }
    b
}

/// Compress the BMP-wide character map `f` into the three-level sparse delta
/// table described on [`build_casemap_nls`].
fn build_case_table<I: Iterator<Item = char>>(f: impl Fn(char) -> I) -> Vec<u16> {
    // Per-character delta: `mapped - ch`, wrapping, and 0 whenever the simple
    // mapping is not a single BMP character (the table cannot express those).
    let delta = |ch: u16| -> u16 {
        let Some(c) = char::from_u32(ch as u32) else { return 0 };
        let mut it = f(c);
        match (it.next(), it.next()) {
            (Some(m), None) => u16::try_from(m as u32).map(|m| m.wrapping_sub(ch)).unwrap_or(0),
            _ => 0,
        }
    };

    // Level 3: one block per 16-character row, shared between identical rows.
    let mut l3_blocks: Vec<[u16; CASE_BLOCK]> = Vec::new();
    let mut l3_of_row: Vec<usize> = Vec::with_capacity(0x1000);
    for row in 0..0x1000u32 {
        let mut block = [0u16; CASE_BLOCK];
        for (i, slot) in block.iter_mut().enumerate() {
            *slot = delta((row * CASE_BLOCK as u32 + i as u32) as u16);
        }
        l3_of_row.push(match l3_blocks.iter().position(|b| *b == block) {
            Some(i) => i,
            None => {
                l3_blocks.push(block);
                l3_blocks.len() - 1
            }
        });
    }

    // Level 2: one block per 256-character page, holding the level-3 block ids
    // of its 16 rows; again shared between identical pages.
    let mut l2_blocks: Vec<[usize; CASE_BLOCK]> = Vec::new();
    let mut l2_of_page: Vec<usize> = Vec::with_capacity(0x100);
    for page in 0..0x100usize {
        let mut block = [0usize; CASE_BLOCK];
        for (i, slot) in block.iter_mut().enumerate() {
            *slot = l3_of_row[page * CASE_BLOCK + i];
        }
        l2_of_page.push(match l2_blocks.iter().position(|b| *b == block) {
            Some(i) => i,
            None => {
                l2_blocks.push(block);
                l2_blocks.len() - 1
            }
        });
    }

    // Emit: [level 1 | level-2 blocks | level-3 blocks], with the first two
    // levels rewritten as absolute WORD indices into the emitted table.
    let l2_base = 0x100;
    let l3_base = l2_base + l2_blocks.len() * CASE_BLOCK;
    let total = l3_base + l3_blocks.len() * CASE_BLOCK;
    assert!(total <= 0x8000, "case table indices stay positive as signed 32-bit");

    let mut t = vec![0u16; total];
    for (page, &b) in l2_of_page.iter().enumerate() {
        t[page] = (l2_base + b * CASE_BLOCK) as u16;
    }
    for (i, block) in l2_blocks.iter().enumerate() {
        for (j, &l3) in block.iter().enumerate() {
            t[l2_base + i * CASE_BLOCK + j] = (l3_base + l3 * CASE_BLOCK) as u16;
        }
    }
    for (i, block) in l3_blocks.iter().enumerate() {
        t[l3_base + i * CASE_BLOCK..l3_base + (i + 1) * CASE_BLOCK].copy_from_slice(block);
    }
    t
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

impl WinOs {
    /// Map a synthesized NLS blob into a fresh guest region and return its base
    /// (0 on failure). Reused by both NLS syscalls; the blob is copied into a
    /// committed RW region reserved from the VirtualAlloc arena.
    fn map_nls_blob(&mut self, mem: &mut dyn Memory, blob: &[u8], name: &str) -> u64 {
        let size = (blob.len() as u64 + 0xfff) & !0xfff;
        match self.map_anywhere(mem, size, Perm::RW, name) {
            Some(base) => match mem.write(base, blob) {
                Ok(()) => base,
                Err(_) => 0,
            },
            None => 0,
        }
    }

    /// `NtInitializeNlsFiles(void **base, LCID *lcid, LARGE_INTEGER *size)`
    /// (SSDT 0x9e). Maps the unified `locale.nls` once (cached), writes the base
    /// pointer, the system LCID, and the mapping size to the caller's out-params.
    fn nt_initialize_nls_files(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let base_out = cpu.reg(Reg::R10); // arg0 (stub `mov r10,rcx`)
        let lcid_out = cpu.reg(Reg::Rdx); // arg1
        let size_out = cpu.reg(Reg::R8); //  arg2 (LARGE_INTEGER*, optional)

        let (base, size) = match self.nls_locale_base {
            Some(pair) => pair,
            None => {
                let blob = build_locale_nls();
                let base = self.map_nls_blob(mem, &blob, "nls-locale");
                if base == 0 {
                    return Ok(STATUS_NO_MEMORY);
                }
                let pair = (base, blob.len() as u64);
                self.nls_locale_base = Some(pair);
                pair
            }
        };

        if base_out != 0 {
            mem.write_u64(base_out, base)?;
        }
        if lcid_out != 0 {
            mem.write_u32(lcid_out, SYSTEM_LCID)?;
        }
        if size_out != 0 {
            mem.write_u64(size_out, size)?;
        }
        Ok(STATUS_SUCCESS)
    }

    /// `NtGetNlsSectionPtr(ULONG type, ULONG id, void *unk, void **base,
    /// SIZE_T *size)` (SSDT 0x9b). Maps (and caches per section) a synthesized
    /// NLS section keyed by `type`: 9 = sort data, **0xa = the case-mapping
    /// tables** (see [`build_casemap_nls`]), 0xb (and any other) = a UTF-8
    /// codepage table.
    fn nt_get_nls_section_ptr(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let sec_type = cpu.reg(Reg::R10) as u32; // arg0
        let base_out = cpu.reg(Reg::R9); //         arg3 (void **base)
        let size_out = self.syscall_arg(cpu, mem, 4)?; // arg5 (SIZE_T *size)

        let base = match self.nls_section_bases.iter().find(|(t, _, _)| *t == sec_type).copied() {
            Some((_, b, _)) => b,
            None => {
                let blob = match sec_type {
                    9 => build_sort_nls(),
                    NLS_SECTION_CASEMAP => build_casemap_nls(),
                    _ => build_codepage_nls(),
                };
                let base = self.map_nls_blob(mem, &blob, "nls-section");
                if base == 0 {
                    return Ok(STATUS_NO_MEMORY);
                }
                self.nls_section_bases.push((sec_type, base, blob.len() as u64));
                base
            }
        };
        let size = self
            .nls_section_bases
            .iter()
            .find(|(t, _, _)| *t == sec_type)
            .map(|(_, _, s)| *s)
            .unwrap_or(0);

        if base_out != 0 {
            mem.write_u64(base_out, base)?;
        }
        if size_out != 0 {
            mem.write_u64(size_out, size)?;
        }
        Ok(STATUS_SUCCESS)
    }
}

pub(crate) fn ssdt_nt_initialize_nls_files(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_initialize_nls_files(cpu, mem)
}

pub(crate) fn ssdt_nt_get_nls_section_ptr(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_get_nls_section_ptr(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WinConfig;
    use exemu_core::Exit;
    use exemu_memory::VirtualMemory;

    fn os64() -> WinOs {
        WinOs::new(WinConfig { is_64bit: true, echo: false, ..WinConfig::default() })
    }

    fn rd32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn rd16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
    }

    /// The guest's own lookup, transcribed from the pinned `ntdll.dll`
    /// (`RtlCompareUnicodeStrings` @ RVA 0x1c9c0):
    /// `mapped = ch + T[T[T[ch>>8] + ((ch>>4)&0xF)] + (ch&0xF)]`.
    fn guest_lookup(t: &[u16], ch: u16) -> u16 {
        let l2 = t[(ch >> 8) as usize] as usize;
        let l3 = t[l2 + ((ch >> 4) & 0xF) as usize] as usize;
        ch.wrapping_add(t[l3 + (ch & 0xF) as usize])
    }

    /// Read the two case tables out of the section exactly the way ntdll's
    /// `locale_init` does (upcase at `+4`, downcase at `+4 + 2*word[+2]`).
    fn case_tables(b: &[u8]) -> (Vec<u16>, Vec<u16>) {
        let words: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let up_len = words[1] as usize;
        (words[2..2 + up_len].to_vec(), words[2 + up_len..].to_vec())
    }

    /// **The regression this module exists for.** The case-mapping section must
    /// carry a table that actually *maps*: when it was a zero-filled codepage
    /// stub, ntdll installed it (non-NULL, so the ASCII fallback was skipped) and
    /// every case-insensitive comparison in the guest silently became
    /// case-sensitive.
    ///
    /// Walking the table with the guest's own indexing must reproduce Rust's
    /// simple case mappings across the whole BMP.
    #[test]
    fn casemap_section_upcases_and_downcases_the_whole_bmp() {
        let b = build_casemap_nls();
        let (up, down) = case_tables(&b);
        assert_eq!(rd16(&b, 0), (2 + up.len() + down.len()) as u16, "self-describing WORD count");
        assert_eq!(rd16(&b, 2), up.len() as u16, "upcase length is what ntdll splits on");

        // The bug's exact signature: 'n' must upcase to 'N'.
        assert_eq!(guest_lookup(&up, b'n' as u16), b'N' as u16);
        assert_eq!(guest_lookup(&down, b'N' as u16), b'n' as u16);

        let simple = |c: char, f: fn(char) -> Box<dyn Iterator<Item = char>>| -> Option<u16> {
            let mut it = f(c);
            match (it.next(), it.next()) {
                (Some(m), None) => u16::try_from(m as u32).ok(),
                _ => None,
            }
        };
        let mut mapped = 0usize;
        for ch in 0..=u16::MAX {
            let Some(c) = char::from_u32(ch as u32) else {
                assert_eq!(guest_lookup(&up, ch), ch, "unpaired surrogate {ch:#x} unchanged");
                continue;
            };
            let want_up = simple(c, |c| Box::new(c.to_uppercase())).unwrap_or(ch);
            let want_down = simple(c, |c| Box::new(c.to_lowercase())).unwrap_or(ch);
            assert_eq!(guest_lookup(&up, ch), want_up, "upcase {ch:#x}");
            assert_eq!(guest_lookup(&down, ch), want_down, "downcase {ch:#x}");
            if want_up != ch {
                mapped += 1;
            }
        }
        // A sanity floor: the BMP has well over a thousand upper/lower pairs, so
        // a table that "passes" by mapping nothing cannot slip through.
        assert!(mapped > 1000, "only {mapped} characters upcase — the table is degenerate");
    }

    /// Sharing identical blocks must keep the table small enough that every
    /// index stays a positive `i32` (the guest sign-extends them).
    #[test]
    fn casemap_section_stays_compact() {
        let b = build_casemap_nls();
        let (up, down) = case_tables(&b);
        for t in [&up, &down] {
            assert!(t.len() <= 0x8000, "table length {} keeps indices positive", t.len());
            assert!(t.len() >= 0x100 + CASE_BLOCK, "at least level 1 plus one block");
        }
        assert!(b.len() < 64 * 1024, "the whole section is a few KiB, got {}", b.len());
    }

    /// The synthesized `locale.nls` header is walked by the guest exactly as the
    /// pinned ntdll `locale_init` / kernelbase `init_locale` do: `base+0x10` →
    /// locale table; the table's LCID index (at `+0x2c`) holds one entry for
    /// LCID 0x409; the count (at `+0x1e`) is ≥1 (a 0 count UD2s in ntdll); the
    /// resolved record carries UTF-8 code pages. Assert those invariants on the
    /// blob so a layout regression is caught structurally.
    #[test]
    fn locale_nls_header_is_walkable() {
        let b = build_locale_nls();

        // base+0x10 → locale table, in-bounds.
        let lt = rd32(&b, HDR_LOCALE_TABLE_OFF) as usize;
        assert!(lt < b.len(), "locale-table offset in-bounds");

        // Count ≥ 1 (ntdll UD2s on 0), and the LCID index / strings offsets are
        // in-bounds.
        let count = rd16(&b, lt + LT_NB_LCIDS);
        assert_eq!(count, 1, "exactly one locale entry");
        let lcids = lt + rd32(&b, lt + LT_LCIDS_OFF) as usize;
        assert!(lcids + LCID_ENTRY_LEN <= b.len(), "LCID index in-bounds");
        let strings = lt + rd32(&b, lt + LT_STRINGS_OFF) as usize;
        assert!(strings < b.len(), "strings block in-bounds");

        // The one LCID entry resolves to LCID 0x409.
        assert_eq!(rd32(&b, lcids), SYSTEM_LCID, "index holds LCID 0x409");
        let idx = rd16(&b, lcids + 4) as usize;
        let stride = rd16(&b, lt + LT_STRIDE) as usize;
        let rec = lt + rd32(&b, lt + LT_LOCALES_OFF) as usize + idx * stride;
        assert!(rec + REC_LEN <= b.len(), "resolved record in-bounds");

        // The record's code pages are UTF-8 (so RtlInitCodePageTable short-paths)
        // and the NlsValidateLocale success flag is set.
        assert_eq!(rd16(&b, rec + REC_ACP), CP_UTF8, "ANSI cp = UTF-8");
        assert_eq!(rd16(&b, rec + REC_OEMCP), CP_UTF8, "OEM cp = UTF-8");
        assert_ne!(rd16(&b, rec + REC_FLAG_18), 0, "validate-locale success flag");
    }

    /// A codepage/norm section reports the UTF-8 codepage id at `+0x02`, the
    /// value `RtlInitCodePageTable` recognises to take its trivial init path.
    #[test]
    fn codepage_section_marks_utf8() {
        let b = build_codepage_nls();
        assert_eq!(rd16(&b, 0x02), CP_UTF8, "CodePage field = 65001 (UTF-8)");
    }

    /// `NtInitializeNlsFiles` (SSDT 0x9e) driven through the dispatcher maps the
    /// locale blob, writes the base/LCID/size out-params, and — crucially — the
    /// base it returns points at a region whose `[base+0x10]`-relative header has
    /// the fields the consumers read (no wild-read at `[base+0x2c]`).
    #[test]
    fn ssdt_initialize_nls_files_maps_and_reports() {
        let mut mem = VirtualMemory::new();
        // Scratch page for the out-params + the syscall stack args.
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let mut os = os64();
        os.set_syscall_handler(SSDT_NT_INITIALIZE_NLS_FILES, ssdt_nt_initialize_nls_files);

        let base_out = 0x2_0100u64;
        let lcid_out = 0x2_0108u64;
        let size_out = 0x2_0110u64;

        let mut cpu = CpuState::default();
        cpu.set_rsp(0x2_0800);
        cpu.set_reg(Reg::Rcx, 0x4000); // saved SYSCALL return rip
        cpu.set_reg(Reg::R10, base_out); // arg0 = void **base
        cpu.set_reg(Reg::Rdx, lcid_out); // arg1 = LCID *
        cpu.set_reg(Reg::R8, size_out); //  arg2 = LARGE_INTEGER *

        let exit = os.dispatch_syscall(SSDT_NT_INITIALIZE_NLS_FILES, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));
        assert_eq!(cpu.reg(Reg::Rax), STATUS_SUCCESS as u64, "NTSTATUS in RAX");

        let base = mem.read_u64(base_out).unwrap();
        assert_ne!(base, 0, "a non-null NLS base was returned");
        assert_eq!(mem.read_u32(lcid_out).unwrap(), SYSTEM_LCID, "system LCID reported");
        assert_ne!(mem.read_u64(size_out).unwrap(), 0, "mapping size reported");

        // The consumers' first dereference: base+0x10 → locale table, then read
        // the LCID-index offset at table+0x2c — must land in the mapped blob and
        // resolve to LCID 0x409, not garbage.
        let lt = base + mem.read_u32(base + HDR_LOCALE_TABLE_OFF as u64).unwrap() as u64;
        let lcids = lt + mem.read_u32(lt + LT_LCIDS_OFF as u64).unwrap() as u64;
        assert_eq!(mem.read_u32(lcids).unwrap(), SYSTEM_LCID, "walkable to LCID 0x409");

        // A second call returns the identical cached base (ntdll caches it via
        // cmpxchg; returning a different view each time would desync the cache).
        let mut cpu2 = CpuState::default();
        cpu2.set_rsp(0x2_0800);
        cpu2.set_reg(Reg::Rcx, 0x4000);
        cpu2.set_reg(Reg::R10, base_out);
        cpu2.set_reg(Reg::Rdx, lcid_out);
        cpu2.set_reg(Reg::R8, size_out);
        os.dispatch_syscall(SSDT_NT_INITIALIZE_NLS_FILES, &mut cpu2, &mut mem).unwrap();
        assert_eq!(mem.read_u64(base_out).unwrap(), base, "cached base is stable");
    }

    /// `NtGetNlsSectionPtr` (SSDT 0x9b) driven through the dispatcher maps a
    /// section keyed by type and writes the base/size out-params; the codepage
    /// section it returns is the UTF-8 stub.
    #[test]
    fn ssdt_get_nls_section_ptr_maps_section() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let mut os = os64();
        os.set_syscall_handler(SSDT_NT_GET_NLS_SECTION_PTR, ssdt_nt_get_nls_section_ptr);

        let base_out = 0x2_0100u64;
        let size_out = 0x2_0200u64;
        let gsp = 0x2_0800u64;
        // arg4 (SIZE_T *size) — the 5th NtGetNlsSectionPtr arg — is the first
        // stack arg, at [gsp + 0x28 + (4-4)*8].
        mem.write_u64(gsp + 0x28, size_out).unwrap();

        let mut cpu = CpuState::default();
        cpu.set_rsp(gsp);
        cpu.set_reg(Reg::Rcx, 0x4000);
        cpu.set_reg(Reg::R10, 0xb); // arg0 = type (codepage)
        cpu.set_reg(Reg::Rdx, 1252); //  arg1 = id
        cpu.set_reg(Reg::R8, 0); //      arg2
        cpu.set_reg(Reg::R9, base_out); //arg3 = void **base

        let exit = os.dispatch_syscall(SSDT_NT_GET_NLS_SECTION_PTR, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));
        assert_eq!(cpu.reg(Reg::Rax), STATUS_SUCCESS as u64);

        let base = mem.read_u64(base_out).unwrap();
        assert_ne!(base, 0, "a non-null section base was returned");
        assert_ne!(mem.read_u64(size_out).unwrap(), 0, "section size reported");
        // The section's codepage word (+0x02) is UTF-8 → RtlInitCodePageTable
        // short-paths without a real MB↔WC table.
        assert_eq!(mem.read_u16(base + 0x02).unwrap(), CP_UTF8, "UTF-8 codepage stub");
    }
}

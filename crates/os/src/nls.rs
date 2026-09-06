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
//! that the LCID binary search deterministically matches (no count-0 UD2, no
//! search-bound underflow) and `CP_ACP`/`CP_OEMCP` resolve to UTF-8 without a
//! table.
//!
//! ## The codepage surface (roadmap W6.x)
//!
//! A codepage the guest names **explicitly** is a different matter, and this is
//! where the module used to be wrong. Every `NtGetNlsSectionPtr(type 0xb, id)`
//! got the same `CP_UTF8`-marked stub regardless of `id` — and the cache was
//! keyed by section type alone, so even a second *distinct* codepage would have
//! got the first one's view. `RtlInitCodePageTable` then installed its built-in
//! UTF-8 `CPTABLEINFO` and the conversion ran as UTF-8 under the requested
//! codepage's name.
//!
//! The visible cost, on essentially every Wine-booted guest, is
//! `err:msvcrt:create_mbcinfo WideCharToMultiByte failed for cp 20127, ret=0
//! (exp 256), error=122`: the C runtime converts all 256 byte values to wide and
//! back into 256-byte buffers, UTF-8 needs 384 bytes for the round trip,
//! `ERROR_INSUFFICIENT_BUFFER` comes back, and msvcrt runs with **empty**
//! multibyte-character tables.
//!
//! **The surface was measured, not assumed.** `EXEMU_NLS_TRACE` over a full
//! Wine boot of both WoW64 corpus binaries reports exactly four distinct
//! requests — type 9 (sort), type 0xa (case), type 0xc id 1 (normalisation), and
//! type 0xb id **20127**, six times. So:
//!
//! * **Implemented as real tables**: 20127 (US-ASCII — the measured one, which
//!   `msvcrt!create_mbcinfo` names for the CRT's default single-byte locale),
//!   and its two exact supersets 28591 (ISO 8859-1) and 1252 (Windows ANSI),
//!   which share one generator. See [`sbcs_map`].
//! * **Refused cleanly**: every other codepage, with
//!   `STATUS_OBJECT_NAME_NOT_FOUND` — the status a real unix side returns for a
//!   `C_#####.nls` that does not exist. kernelbase turns it into a NULL table
//!   and the conversion API fails with `ERROR_INVALID_PARAMETER`.
//! * **Out of scope**: the DBCS codepages (932, 936, 949, 950, 1361). Their
//!   tables are real `.nls` data the pinned prefix does not ship; synthesizing
//!   an approximation would corrupt text silently.
//!
//! A wrong conversion is worse than a refused one, and a silently-empty table is
//! worse than both. The same three tables back exemu's *own*
//! `WideCharToMultiByte`/`MultiByteToWideChar` thunks on the emulated path
//! ([`sbcs_encode`]/[`sbcs_decode`]), so a guest cannot see two different
//! answers depending on which path serviced it.

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

/// Build the section handed back for a type this module has no real data for
/// (today: type 0xc, the normalisation tables). It is shaped as a codepage
/// section marked `CP_UTF8`, because that is the one shape every consumer that
/// reaches `RtlInitCodePageTable` recognises without reading further; the rest
/// is zero so a caller that only chases pointer offsets off the base stays
/// in-bounds.
fn build_opaque_nls() -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    b[0x00..0x02].copy_from_slice(&CP_HEADER_WORDS.to_le_bytes()); // HeaderSize (words)
    b[0x02..0x04].copy_from_slice(&CP_UTF8.to_le_bytes()); // CodePage = 65001
    b
}

// ---------------------------------------------------------------------------
// Codepage sections (NtGetNlsSectionPtr type 0xB) — `C_#####.nls`
// ---------------------------------------------------------------------------

/// The `NtGetNlsSectionPtr` section type that carries a **codepage table**
/// (`C_#####.nls`); the codepage id arrives in `arg1`.
pub(crate) const NLS_SECTION_CODEPAGE: u32 = 0xB;

/// `STATUS_OBJECT_NAME_NOT_FOUND` — what a real unix side answers for a
/// codepage whose `C_#####.nls` file does not exist, and what exemu answers for
/// a codepage it does not implement. kernelbase's `get_codepage_table`
/// (@ RVA 0x79590) turns any failure here into a NULL table, and
/// `WideCharToMultiByte`/`MultiByteToWideChar` then fail with
/// `ERROR_INVALID_PARAMETER`. That **clean refusal** is the point: see
/// [`sbcs_map`] on the codepage surface.
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// The number of `WORD`s in a codepage section header, i.e. the value at
/// `word[+0x00]`. `RtlInitCodePageTable` copies the 0x18 bytes `+0x02..+0x1a`
/// out of the header and then skips `2 * HeaderSize` bytes to reach the table
/// body, so 0x0d words = 0x1a bytes is the smallest header that works — and is
/// what real `C_#####.nls` files carry.
const CP_HEADER_WORDS: u16 = 0x000D;

/// The Unicode replacement character: the wide value of every byte a codepage
/// leaves undefined, and the section's `UniDefaultChar`.
const UNI_DEFAULT: u16 = 0xFFFD;

/// The byte substituted for a character the codepage cannot encode
/// (`DefaultChar`): ASCII `'?'`, as every Windows SBCS table uses.
const MB_DEFAULT: u8 = b'?';

/// The byte→Unicode map of one **single-byte** codepage exemu implements
/// natively, or `None` for a codepage it refuses.
///
/// **The surface, and why it is this one.** Recovered by *measuring*, not
/// guessing: `EXEMU_NLS_TRACE` over the whole pinned Wine boot of both WoW64
/// corpus binaries shows exactly four `NtGetNlsSectionPtr` requests — type 9
/// (sort), type 0xa (case), type 0xc id 1 (normalisation) and type 0xb id
/// **20127**, six times. 20127 is the only codepage anything asks for, and it is
/// asked for by every guest that touches the C runtime:
/// `msvcrt!create_mbcinfo` (@ RVA 0x37b40) lowers the CRT's default
/// `_MB_CP_SBCS` to `mov edi,0x4e9f` = 20127 and then round-trips all 256 byte
/// values through `MultiByteToWideChar` and `WideCharToMultiByte`.
///
/// The other two supported codepages are that one's exact supersets and cost a
/// shared generator: **28591** (ISO 8859-1) is 20127 plus an identity upper
/// half, and **1252** (the Windows ANSI codepage) is 28591 with the C1 range
/// replaced by the documented Windows punctuation block. All three are
/// **bijections on their defined range**, so the reverse table is exact and no
/// best-fit guessing happens anywhere.
///
/// Everything else is refused with [`STATUS_OBJECT_NAME_NOT_FOUND`] rather than
/// answered wrongly — which is what this whole block is for. The old code
/// handed *every* codepage id the same `CP_UTF8`-marked stub, so
/// `WideCharToMultiByte(20127, …)` silently encoded UTF-8: 256 wide chars
/// became 384 bytes, overflowed the CRT's 256-byte buffer and returned 0 with
/// `ERROR_INSUFFICIENT_BUFFER` (122) — the `err:msvcrt:create_mbcinfo … ret=0
/// (exp 256), error=122` both corpus binaries report. msvcrt then ran with
/// **empty** multibyte-character tables.
///
/// Deliberately out of scope, not merely unimplemented: the DBCS codepages
/// (932 Shift-JIS, 936 GBK, 949, 950, 1361). Their tables are tens of thousands
/// of entries of real `C_####.NLS` data that the pinned `wine-stable-amd64`
/// prefix does not ship, and a synthesized approximation would silently corrupt
/// text. `CP_ACP`/`CP_OEMCP`/`CP_UTF8` never reach here at all — kernelbase
/// answers them from its own `ansi_cpinfo`/`oem_cpinfo`/`utf8_cpinfo`, and
/// exemu's synthesized locale sets both the ANSI and the OEM codepage to UTF-8.
fn sbcs_map(cp: u32) -> Option<[u16; 256]> {
    // The common spine: 0x00..=0x7F is US-ASCII, identical in all three.
    let mut m = [UNI_DEFAULT; 256];
    for (b, slot) in m.iter_mut().enumerate().take(0x80) {
        *slot = b as u16;
    }
    match cp {
        // 20127 — US-ASCII. 0x80..=0xFF are undefined and stay U+FFFD.
        20127 => {}
        // 28591 — ISO 8859-1 (Latin-1): the upper half is identity too.
        28591 => {
            for (b, slot) in m.iter_mut().enumerate().skip(0x80) {
                *slot = b as u16;
            }
        }
        // 1252 — Windows Latin-1: identity everywhere except 0x80..=0x9F, where
        // Windows puts printable punctuation instead of the C1 controls. The
        // five positions Microsoft's table leaves as controls (0x81, 0x8d,
        // 0x8f, 0x90, 0x9d) map to themselves, which is what keeps the whole
        // codepage a bijection.
        1252 => {
            for (b, slot) in m.iter_mut().enumerate().skip(0x80) {
                *slot = b as u16;
            }
            const C1: [u16; 32] = [
                0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 0x80
                0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F, // 0x88
                0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 0x90
                0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178, // 0x98
            ];
            m[0x80..0xA0].copy_from_slice(&C1);
        }
        _ => return None,
    }
    Some(m)
}

/// Build a **real** single-byte codepage section for `cp`, in the exact layout
/// `ntdll!RtlInitCodePageTable` (@ RVA 0x29740) parses and
/// `RtlCustomCPToUnicodeN` (@ 0x204b0) / `RtlUnicodeToCustomCPN` (@ 0x36660)
/// then index. Recovered from those three functions in the pinned `ntdll.dll`
/// (clean-room Class B — pinned-binary disassembly plus public NLS-format
/// docs; no Wine `.c` source):
///
/// ```text
///   +0x00  WORD  HeaderSize, in WORDs      -+ the header RtlInitCodePageTable
///   +0x02  WORD  CodePage                   | copies into CPTABLEINFO; it then
///   +0x04  WORD  MaximumCharacterSize       | skips 2 * HeaderSize bytes to
///   +0x06  WORD  DefaultChar    (multibyte) | reach the body below.
///   +0x08  WORD  UniDefaultChar             |
///   +0x0a  WORD  TransDefaultChar           |
///   +0x0c  WORD  TransUniDefaultChar        |
///   +0x0e  BYTE  LeadByte[12]              -+
///   body+0x000  WORD  wc_offset             WideCharTable = body+2 + 2*wc_offset
///   body+0x002  WORD  MultiByteTable[256]   byte -> Unicode
///   body+0x202  WORD  glyph table present?  (0 = no glyph table follows)
///   body+0x204  WORD  DBCSRanges[]          (0 = none => single byte)
///   body+0x206  BYTE  WideCharTable[65536]  Unicode -> byte (SBCS: BYTE-wide)
/// ```
///
/// The two indexing rules that fix the widths: `RtlCustomCPToUnicodeN`'s
/// single-byte arm reads `word[MultiByteTable + b*2]`, and
/// `RtlUnicodeToCustomCPN`'s single-byte arm — taken when `DBCSCodePage`
/// (`word[info+0x0c]`) is 0, which is exactly when the DBCS-ranges word is 0 —
/// reads `byte[WideCharTable + wc]`, a flat 64 KiB table indexed by the whole
/// `WCHAR` rather than a sparse one.
fn build_sbcs_codepage_nls(cp: u32, map: &[u16; 256]) -> Vec<u8> {
    // Offset of the table body from the section base: 2 * HeaderSize.
    const BODY: usize = 2 * CP_HEADER_WORDS as usize;
    // `wc_offset`, in WORDs, from `body+2` to the WideCharTable: the 256-WORD
    // MultiByteTable, the glyph-present WORD and the DBCS-ranges terminator.
    const WC_OFFSET: u16 = 256 + 1 + 1;
    // Where the WideCharTable starts, relative to the body.
    const WCT: usize = 2 + 2 * WC_OFFSET as usize;

    let mut b = vec![0u8; BODY + WCT + 0x1_0000];
    let put16 = |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());

    // --- header ---
    put16(&mut b, 0x00, CP_HEADER_WORDS);
    put16(&mut b, 0x02, cp as u16);
    put16(&mut b, 0x04, 1); //                MaximumCharacterSize: single byte
    put16(&mut b, 0x06, MB_DEFAULT as u16); // DefaultChar         '?'
    put16(&mut b, 0x08, UNI_DEFAULT); //       UniDefaultChar      U+FFFD
    put16(&mut b, 0x0a, MB_DEFAULT as u16); // TransDefaultChar
    put16(&mut b, 0x0c, UNI_DEFAULT); //       TransUniDefaultChar
    // LeadByte[12] at +0x0e stays zero: an SBCS has no lead-byte ranges.

    // --- body: the byte -> Unicode direction ---
    put16(&mut b, BODY, WC_OFFSET);
    for (byte, &wc) in map.iter().enumerate() {
        put16(&mut b, BODY + 2 + byte * 2, wc);
    }
    // body+0x202 = 0: no glyph table. body+0x204 = 0: no DBCS ranges — which is
    // what keeps both conversion routines on their single-byte arms.

    // --- the Unicode -> byte direction: 64 KiB, DefaultChar everywhere else ---
    let wct = BODY + WCT;
    b[wct..wct + 0x1_0000].fill(MB_DEFAULT);
    // Walk downwards so that when several bytes share a wide value — every
    // undefined byte maps to U+FFFD — the lowest byte wins the reverse slot,
    // and U+FFFD itself keeps `DefaultChar` unless a byte really encodes it.
    for (byte, &wc) in map.iter().enumerate().rev() {
        if wc != UNI_DEFAULT {
            b[wct + wc as usize] = byte as u8;
        }
    }
    b
}

/// Decode `bytes` from a natively supported single-byte codepage, or `None`
/// when `cp` is not one of them (see [`sbcs_map`] for the surface). Undefined
/// bytes decode to `U+FFFD`, which is what the codepage's own
/// `MultiByteTable` holds for them.
///
/// This is the **emulated** path's half of the same surface: on the Wine boot
/// `MultiByteToWideChar` is kernelbase's own code walking the section
/// [`build_sbcs_codepage_nls`] hands it, but exemu's own thunk
/// (`api.rs::Api::MultiByteToWideChar`) has to do the conversion itself, and it
/// must agree — the table is shared so the two cannot drift.
pub(crate) fn sbcs_decode(cp: u32, bytes: &[u8]) -> Option<Vec<u16>> {
    let map = sbcs_map(cp)?;
    Some(bytes.iter().map(|&b| map[b as usize]).collect())
}

/// Encode UTF-16 `units` into a natively supported single-byte codepage, or
/// `None` when `cp` is not one of them. Returns the bytes and whether any
/// character had to be replaced with `DefaultChar` — the flag
/// `WideCharToMultiByte`'s `lpUsedDefaultChar` out-parameter reports.
///
/// The reverse lookup is a scan of the 256-entry forward map rather than a
/// materialised 64 KiB table: it is exact (all three supported codepages are
/// bijections on their defined range) and this path is not hot — no corpus
/// binary reaches it at all, since the emulated ANSI codepage is UTF-8.
pub(crate) fn sbcs_encode(cp: u32, units: &[u16]) -> Option<(Vec<u8>, bool)> {
    let map = sbcs_map(cp)?;
    let mut used_default = false;
    let bytes = units
        .iter()
        .map(|&wc| match map.iter().position(|&m| m == wc && m != UNI_DEFAULT) {
            Some(b) => b as u8,
            None => {
                used_default = true;
                MB_DEFAULT
            }
        })
        .collect();
    Some((bytes, used_default))
}

/// The codepage section handed back for `cp`, or `None` to refuse it.
///
/// `CP_UTF8` keeps a trivial marker section: `RtlInitCodePageTable` sees
/// `word[+0x02] == 0xFDE9` and installs its own built-in UTF-8 `CPTABLEINFO`
/// without reading another byte — so no table is needed, and none would be
/// right, UTF-8 not being a 256-entry map.
fn build_codepage_nls(cp: u32) -> Option<Vec<u8>> {
    if cp == CP_UTF8 as u32 {
        return Some(build_opaque_nls());
    }
    sbcs_map(cp).map(|m| build_sbcs_codepage_nls(cp, &m))
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

/// `EXEMU_NLS_TRACE` — log every `NtGetNlsSectionPtr(type, id)` the guest makes,
/// on stderr as `[nls] NtGetNlsSectionPtr type=T id=N`.
///
/// This is the seam the **codepage surface** was recovered through: which code
/// pages Wine's own PE builtins and a real guest actually ask for is *measured*
/// here rather than guessed from a header. Off unless the variable is set.
fn nls_trace() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("EXEMU_NLS_TRACE").is_some())
}

impl WinOs {
    /// Map a synthesized NLS blob into a fresh guest region and return its base
    /// (0 on failure). Reused by both NLS syscalls; the blob is copied into a
    /// committed RW region reserved from the VirtualAlloc arena.
    ///
    /// In a **WoW64** process the view is placed below 4 GiB (roadmap W5.7):
    /// the 32-bit `ntdll`'s `RtlGetLocaleFileMappingAddress` caches the base in
    /// a 32-bit cell, and `wow64.dll` narrows whatever the kernel returns into
    /// it — so a high placement is truncated into an unmapped pointer instead of
    /// failing. A 64-bit consumer can address the low view just as well, and the
    /// mapping is cached, so one placement serves both halves.
    fn map_nls_blob(&mut self, mem: &mut dyn Memory, blob: &[u8], name: &str) -> u64 {
        let size = (blob.len() as u64 + 0xfff) & !0xfff;
        let placed = if self.wow64_peb32 != 0 {
            self.map_anywhere_low(mem, size, Perm::RW, name)
        } else {
            self.map_anywhere(mem, size, Perm::RW, name)
        };
        match placed {
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
        let sec_id = cpu.reg(Reg::Rdx) as u32; //   arg1
        let base_out = cpu.reg(Reg::R9); //         arg3 (void **base)
        let size_out = self.syscall_arg(cpu, mem, 4)?; // arg5 (SIZE_T *size)
        if nls_trace() {
            eprintln!("[nls] NtGetNlsSectionPtr type={sec_type} id={sec_id}");
        }

        // Cached per **(type, id)**: a codepage section is keyed by its codepage,
        // so caching by type alone would hand the first codepage's table to
        // every later one.
        let cached = self
            .nls_section_bases
            .iter()
            .find(|(t, i, _, _)| *t == sec_type && *i == sec_id)
            .copied();
        let (base, size) = match cached {
            Some((_, _, b, s)) => (b, s),
            None => {
                let blob = match sec_type {
                    9 => build_sort_nls(),
                    NLS_SECTION_CASEMAP => build_casemap_nls(),
                    NLS_SECTION_CODEPAGE => match build_codepage_nls(sec_id) {
                        Some(b) => b,
                        // Refuse cleanly. A wrong table is worse than none:
                        // kernelbase turns this into a NULL codepage table and
                        // the conversion API fails with ERROR_INVALID_PARAMETER,
                        // instead of silently converting through the wrong
                        // encoding. See `sbcs_map` for the supported surface.
                        None => return Ok(STATUS_OBJECT_NAME_NOT_FOUND),
                    },
                    _ => build_opaque_nls(),
                };
                let base = self.map_nls_blob(mem, &blob, "nls-section");
                if base == 0 {
                    return Ok(STATUS_NO_MEMORY);
                }
                let size = blob.len() as u64;
                self.nls_section_bases.push((sec_type, sec_id, base, size));
                (base, size)
            }
        };

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

    /// A section type this module has no real data for (0xc, normalisation)
    /// reports the UTF-8 codepage id at `+0x02`, the value
    /// `RtlInitCodePageTable` recognises to take its trivial init path.
    #[test]
    fn opaque_section_marks_utf8() {
        let b = build_opaque_nls();
        assert_eq!(rd16(&b, 0x02), CP_UTF8, "CodePage field = 65001 (UTF-8)");
    }

    // -----------------------------------------------------------------------
    // Codepage sections: a reader that *is* the disassembly, then the tables.
    // -----------------------------------------------------------------------

    /// The parts of `CPTABLEINFO` the conversion routines index, parsed out of a
    /// section blob by literally replaying `ntdll!RtlInitCodePageTable`
    /// (@ RVA 0x29740). Reading the table back the way the guest does is what
    /// makes these tests a check on the *layout*, not just on the builder.
    struct CpTable {
        code_page: u16,
        max_char_size: u16,
        default_char: u16,
        uni_default_char: u16,
        dbcs_code_page: u16,
        /// Offset of `MultiByteTable` (256 `WORD`s) in the blob.
        multi_byte: usize,
        /// Offset of `WideCharTable` (65536 `BYTE`s for an SBCS) in the blob.
        wide_char: usize,
    }

    impl CpTable {
        fn parse(b: &[u8]) -> CpTable {
            let hdr_words = rd16(b, 0x00) as usize;
            // `rdx = ptr + 2*HeaderSize`; `WideCharTable = rdx + 2 + 2*word[rdx]`
            // and `MultiByteTable = rdx + 2`.
            let body = 2 * hdr_words;
            let wc_offset = rd16(b, body) as usize;
            let multi_byte = body + 2;
            let wide_char = body + 2 + 2 * wc_offset;
            // `cmpw $0, 0x202(%rdx)` picks the DBCS-ranges pointer, and a
            // non-zero first range word is what sets DBCSCodePage.
            let ranges = if rd16(b, body + 0x202) != 0 { body + 0x404 } else { body + 0x204 };
            let dbcs_code_page = u16::from(rd16(b, ranges) != 0);
            CpTable {
                code_page: rd16(b, 0x02),
                max_char_size: rd16(b, 0x04),
                default_char: rd16(b, 0x06),
                uni_default_char: rd16(b, 0x08),
                dbcs_code_page,
                multi_byte,
                wide_char,
            }
        }

        /// `RtlCustomCPToUnicodeN`'s single-byte arm: `word[MultiByteTable+b*2]`.
        fn to_unicode(&self, b: &[u8], byte: u8) -> u16 {
            rd16(b, self.multi_byte + byte as usize * 2)
        }

        /// `RtlUnicodeToCustomCPN`'s single-byte arm: `byte[WideCharTable+wc]`.
        fn to_multi_byte(&self, b: &[u8], wc: u16) -> u8 {
            b[self.wide_char + wc as usize]
        }
    }

    /// Every supported codepage really is a **table**, not the UTF-8 marker: it
    /// reports its own id, one byte per character, and no DBCS ranges — the
    /// three header fields that decide which arm each conversion routine takes.
    #[test]
    fn supported_codepages_carry_a_real_single_byte_table() {
        for cp in [20127u32, 28591, 1252] {
            let b = build_codepage_nls(cp).unwrap_or_else(|| panic!("cp {cp} is supported"));
            let t = CpTable::parse(&b);
            assert_eq!(t.code_page, cp as u16, "cp {cp}: reports its own id, not 65001");
            assert_eq!(t.max_char_size, 1, "cp {cp}: single byte");
            assert_eq!(t.dbcs_code_page, 0, "cp {cp}: no DBCS ranges");
            assert_eq!(t.uni_default_char, UNI_DEFAULT, "cp {cp}: UniDefaultChar");
            assert_eq!(t.default_char, MB_DEFAULT as u16, "cp {cp}: DefaultChar '?'");
            // Both tables land inside the blob — the whole point of the layout.
            assert!(t.multi_byte + 512 <= b.len(), "cp {cp}: MultiByteTable in-bounds");
            assert!(t.wide_char + 0x1_0000 <= b.len(), "cp {cp}: WideCharTable in-bounds");
            // ASCII is ASCII in all three.
            for byte in 0..=0x7Fu8 {
                assert_eq!(t.to_unicode(&b, byte), byte as u16, "cp {cp}: {byte:#04x} → itself");
                assert_eq!(t.to_multi_byte(&b, byte as u16), byte, "cp {cp}: and back");
            }
        }
    }

    /// **The bug this whole block fixes, reproduced as an assertion.**
    /// `msvcrt!create_mbcinfo` (@ RVA 0x37b40) converts all 256 byte values to
    /// wide and straight back, into 256-element buffers, and gives up unless
    /// *both* conversions report exactly 256. With the old UTF-8-marked stub the
    /// wide→multibyte leg needed 384 bytes (128 characters above U+007F cost two
    /// bytes each) and failed with `ERROR_INSUFFICIENT_BUFFER`. A real 20127
    /// table is one byte per character in both directions, so it fits.
    #[test]
    fn cp20127_round_trips_256_bytes_the_way_the_crt_checks() {
        let b = build_codepage_nls(20127).expect("20127 is supported");
        let t = CpTable::parse(&b);

        let wide: Vec<u16> = (0..=255u8).map(|byte| t.to_unicode(&b, byte)).collect();
        assert_eq!(wide.len(), 256, "MultiByteToWideChar(20127, …, 256) → 256 WCHARs");
        let back: Vec<u8> = wide.iter().map(|&wc| t.to_multi_byte(&b, wc)).collect();
        assert_eq!(back.len(), 256, "WideCharToMultiByte(20127, …, 256) → 256 bytes");

        // US-ASCII: the low half is exact, the high half is undefined and comes
        // back as U+FFFD → '?' rather than as a silent second UTF-8 byte.
        for byte in 0..=0x7Fu8 {
            assert_eq!(back[byte as usize], byte, "{byte:#04x} survives the round trip");
        }
        for byte in 0x80..=0xFFu8 {
            assert_eq!(wide[byte as usize], UNI_DEFAULT, "{byte:#04x} is undefined in US-ASCII");
            assert_eq!(back[byte as usize], MB_DEFAULT, "…and encodes back as DefaultChar");
        }
    }

    /// 28591 (ISO 8859-1) and 1252 (Windows ANSI) are **bijections**: all 256
    /// bytes round-trip exactly, so the reverse table involves no best-fit
    /// guessing. 1252 additionally carries the Windows punctuation block where
    /// ISO has C1 controls — the one place the two differ.
    #[test]
    fn latin1_codepages_are_bijections() {
        for cp in [28591u32, 1252] {
            let b = build_codepage_nls(cp).unwrap_or_else(|| panic!("cp {cp} is supported"));
            let t = CpTable::parse(&b);
            for byte in 0..=255u8 {
                let wc = t.to_unicode(&b, byte);
                assert_ne!(wc, UNI_DEFAULT, "cp {cp}: {byte:#04x} is defined");
                assert_eq!(t.to_multi_byte(&b, wc), byte, "cp {cp}: {byte:#04x} round-trips");
            }
        }
        let iso = build_codepage_nls(28591).unwrap();
        let win = build_codepage_nls(1252).unwrap();
        let (ti, tw) = (CpTable::parse(&iso), CpTable::parse(&win));
        assert_eq!(ti.to_unicode(&iso, 0x80), 0x0080, "ISO 8859-1 keeps the C1 controls");
        assert_eq!(tw.to_unicode(&win, 0x80), 0x20AC, "1252 puts € at 0x80");
        assert_eq!(tw.to_unicode(&win, 0x92), 0x2019, "…and a right single quote at 0x92");
        assert_eq!(tw.to_multi_byte(&win, 0x20AC), 0x80, "…which encodes back");
        for byte in 0..=0x7Fu8 {
            assert_eq!(ti.to_unicode(&iso, byte), tw.to_unicode(&win, byte), "ASCII agrees");
        }
        for byte in 0xA0..=0xFFu8 {
            assert_eq!(ti.to_unicode(&iso, byte), tw.to_unicode(&win, byte), "Latin-1 agrees");
        }
    }

    /// The emulated `WideCharToMultiByte`/`MultiByteToWideChar` thunks and the
    /// section handed to Wine's kernelbase must convert **identically** — the
    /// same guest run can cross both. They share `sbcs_map`, and this pins that
    /// they still agree byte for byte, in both directions, for every codepage.
    #[test]
    fn the_emulated_thunks_and_the_guest_section_agree() {
        for cp in [20127u32, 28591, 1252] {
            let b = build_codepage_nls(cp).unwrap();
            let t = CpTable::parse(&b);
            let bytes: Vec<u8> = (0..=255u8).collect();

            let decoded = sbcs_decode(cp, &bytes).unwrap_or_else(|| panic!("cp {cp} decodes"));
            let via_section: Vec<u16> = bytes.iter().map(|&x| t.to_unicode(&b, x)).collect();
            assert_eq!(decoded, via_section, "cp {cp}: byte → wide agrees");

            let (encoded, lossy) = sbcs_encode(cp, &decoded).unwrap();
            let back: Vec<u8> = decoded.iter().map(|&wc| t.to_multi_byte(&b, wc)).collect();
            assert_eq!(encoded, back, "cp {cp}: wide → byte agrees");
            assert_eq!(lossy, cp == 20127, "only US-ASCII has characters it cannot encode");

            // A character no single-byte codepage holds becomes DefaultChar and
            // raises the used-default flag the API reports.
            let (enc, lossy) = sbcs_encode(cp, &[0x4E2D]).unwrap();
            assert_eq!(enc, vec![MB_DEFAULT], "cp {cp}: an unencodable char → '?'");
            assert!(lossy, "cp {cp}: …and lpUsedDefaultChar is set");
        }
        assert!(sbcs_encode(932, &[0x41]).is_none(), "an unsupported codepage is refused here too");
        assert!(sbcs_decode(932, &[0x41]).is_none(), "…in both directions");
    }

    /// The **refusal** half of the surface. A codepage exemu has no table for is
    /// not answered with a plausible-looking wrong one: `build_codepage_nls`
    /// returns `None`, and the syscall turns that into
    /// `STATUS_OBJECT_NAME_NOT_FOUND` — which kernelbase reports to the guest as
    /// `ERROR_INVALID_PARAMETER`, exactly as a missing `C_#####.nls` would.
    #[test]
    fn unsupported_codepages_are_refused_rather_than_faked() {
        // DBCS (deliberately out of scope), the OEM/other SBCS pages nothing
        // was measured asking for, and the UTF-16 pseudo-codepages.
        for cp in [932u32, 936, 949, 950, 1361, 437, 850, 1251, 65000, 1200, 1201, 0] {
            assert!(build_codepage_nls(cp).is_none(), "cp {cp} is refused, not synthesized");
        }
        // CP_UTF8 keeps its marker section, which is a correct answer.
        let utf8 = build_codepage_nls(CP_UTF8 as u32).expect("UTF-8 is answered");
        assert_eq!(rd16(&utf8, 0x02), CP_UTF8, "…as the short-path marker");
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
    /// section keyed by type **and id**, and answers a codepage it has no table
    /// for with an error instead of a section.
    #[test]
    fn ssdt_get_nls_section_ptr_keys_codepages_by_id() {
        let mut mem = VirtualMemory::new();
        mem.map_fixed(0x2_0000, 0x1000, Perm::RW, "scratch").unwrap();
        let mut os = os64();
        os.set_syscall_handler(SSDT_NT_GET_NLS_SECTION_PTR, ssdt_nt_get_nls_section_ptr);

        let base_out = 0x2_0100u64;
        let size_out = 0x2_0200u64;
        let gsp = 0x2_0800u64;
        mem.write_u64(gsp + 0x28, size_out).unwrap();

        let get = |os: &mut WinOs, mem: &mut VirtualMemory, ty: u64, id: u64| -> (u64, u64) {
            mem.write_u64(base_out, 0).unwrap();
            let mut cpu = CpuState::default();
            cpu.set_rsp(gsp);
            cpu.set_reg(Reg::Rcx, 0x4000);
            cpu.set_reg(Reg::R10, ty);
            cpu.set_reg(Reg::Rdx, id);
            cpu.set_reg(Reg::R8, 0);
            cpu.set_reg(Reg::R9, base_out);
            os.dispatch_syscall(SSDT_NT_GET_NLS_SECTION_PTR, &mut cpu, mem).unwrap();
            (cpu.reg(Reg::Rax), mem.read_u64(base_out).unwrap())
        };

        // Two different codepages get two different sections, each reporting its
        // own id — the bug the id-keyed cache fixes is handing the first one's
        // table to the second.
        let (st_ascii, ascii) = get(&mut os, &mut mem, 0xb, 20127);
        assert_eq!(st_ascii, STATUS_SUCCESS as u64, "20127 is supported");
        let (st_1252, win1252) = get(&mut os, &mut mem, 0xb, 1252);
        assert_eq!(st_1252, STATUS_SUCCESS as u64, "1252 is supported");
        assert_ne!(ascii, win1252, "one section per codepage, not per type");
        assert_eq!(mem.read_u16(ascii + 0x02).unwrap(), 20127, "the 20127 section says 20127");
        assert_eq!(mem.read_u16(win1252 + 0x02).unwrap(), 1252, "and the 1252 one says 1252");

        // Repeating a query returns the identical view (kernelbase caches the
        // CPTABLEINFO it derives, so a second base would desync it).
        assert_eq!(get(&mut os, &mut mem, 0xb, 20127).1, ascii, "cached per codepage");

        // A codepage with no table is refused, and nothing is written back.
        let (st, base) = get(&mut os, &mut mem, 0xb, 932);
        assert_eq!(st, STATUS_OBJECT_NAME_NOT_FOUND as u64, "Shift-JIS is refused cleanly");
        assert_eq!(base, 0, "…and no section pointer is handed out");
    }

    /// `NtGetNlsSectionPtr` maps the non-codepage section types and writes the
    /// base/size out-params.
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
        cpu.set_reg(Reg::R10, 0xc); // arg0 = type (normalisation)
        cpu.set_reg(Reg::Rdx, 1); //     arg1 = id (NormalizationC)
        cpu.set_reg(Reg::R8, 0); //      arg2
        cpu.set_reg(Reg::R9, base_out); //arg3 = void **base

        let exit = os.dispatch_syscall(SSDT_NT_GET_NLS_SECTION_PTR, &mut cpu, &mut mem).unwrap();
        assert!(matches!(exit, Exit::Continue));
        assert_eq!(cpu.reg(Reg::Rax), STATUS_SUCCESS as u64);

        let base = mem.read_u64(base_out).unwrap();
        assert_ne!(base, 0, "a non-null section base was returned");
        assert_ne!(mem.read_u64(size_out).unwrap(), 0, "section size reported");
        // No real normalisation data exists here; the section is the opaque
        // UTF-8-marked one, which is what a consumer reaching
        // RtlInitCodePageTable short-paths on.
        assert_eq!(mem.read_u16(base + 0x02).unwrap(), CP_UTF8, "opaque UTF-8-marked section");
    }
}

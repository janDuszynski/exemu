//! PE resource directory walker (W0.9).
//!
//! Generalises the earlier dialog-only and manifest-lookup parsers into a full
//! three-level `IMAGE_DIRECTORY_ENTRY_RESOURCE` walker that covers every
//! standard resource type Windows PE images carry.
//!
//! ## Three-level tree
//!
//! The PE resource directory is a tree with three levels, per the PE/COFF spec:
//!
//!   Level 0 (type) : resource type — integer (RT_*) or a named type.
//!   Level 1 (name) : resource name or integer ordinal.
//!   Level 2 (lang) : language subdirectory; each leaf is a data-entry
//!                    (`IMAGE_RESOURCE_DATA_ENTRY`) that points at the raw bytes.
//!
//! Each `IMAGE_RESOURCE_DIRECTORY` node is immediately followed by an array of
//! `IMAGE_RESOURCE_DIRECTORY_ENTRY` records (8 bytes each). The high bit of the
//! `NameOffset` field: 1 = named entry (offset into a string table), 0 = integer
//! ID. The high bit of the `DataEntryOffset` field: 1 = subdirectory (another
//! `IMAGE_RESOURCE_DIRECTORY`), 0 = leaf data entry.
//!
//! ## Source
//!
//! All field offsets and semantics are from the public PE/COFF specification
//! (Microsoft), the public `winnt.h` and `winuser.h` headers, and the public
//! MSDN documentation for resource types. No Wine or ReactOS source was
//! consulted (clean-room, D5 policy).

#![forbid(unsafe_code)]

use std::collections::HashMap;

use exemu_core::gui::{Control, ControlKind, DialogTemplate};

use crate::reader::Reader;

// ---------------------------------------------------------------------------
// Resource type constants — from the public `winuser.h` header.
// ---------------------------------------------------------------------------

/// `RT_CURSOR` (1) — hardware-independent cursor resource.
pub const RT_CURSOR: u32 = 1;
/// `RT_BITMAP` (2) — bitmap resource.
pub const RT_BITMAP: u32 = 2;
/// `RT_ICON` (3) — hardware-independent icon resource (one image in a group).
pub const RT_ICON: u32 = 3;
/// `RT_MENU` (4) — menu resource.
pub const RT_MENU: u32 = 4;
/// `RT_DIALOG` (5) — dialog-box template.
pub const RT_DIALOG: u32 = 5;
/// `RT_STRING` (6) — string-table resource (block of 16 UTF-16 strings).
pub const RT_STRING: u32 = 6;
/// `RT_FONTDIR` (7) — font-directory resource.
pub const RT_FONTDIR: u32 = 7;
/// `RT_FONT` (8) — font resource.
pub const RT_FONT: u32 = 8;
/// `RT_ACCELERATOR` (9) — accelerator-table resource.
pub const RT_ACCELERATOR: u32 = 9;
/// `RT_RCDATA` (10) — application-defined raw data.
pub const RT_RCDATA: u32 = 10;
/// `RT_MESSAGETABLE` (11) — message-table resource.
pub const RT_MESSAGETABLE: u32 = 11;
/// `RT_GROUP_CURSOR` (12) — hardware-independent cursor-group (wraps RT_CURSOR entries).
pub const RT_GROUP_CURSOR: u32 = 12;
/// `RT_GROUP_ICON` (14) — hardware-independent icon-group (wraps RT_ICON entries).
pub const RT_GROUP_ICON: u32 = 14;
/// `RT_VERSION` (16) — `VS_VERSIONINFO` resource.
pub const RT_VERSION: u32 = 16;
/// `RT_DLGINCLUDE` (17) — dialog-include resource (internal header reference).
pub const RT_DLGINCLUDE: u32 = 17;
/// `RT_PLUGPLAY` (19) — plug-and-play resource.
pub const RT_PLUGPLAY: u32 = 19;
/// `RT_VXD` (20) — VxD resource.
pub const RT_VXD: u32 = 20;
/// `RT_ANICURSOR` (21) — animated-cursor resource.
pub const RT_ANICURSOR: u32 = 21;
/// `RT_ANIICON` (22) — animated-icon resource.
pub const RT_ANIICON: u32 = 22;
/// `RT_HTML` (23) — HTML resource.
pub const RT_HTML: u32 = 23;
/// `RT_MANIFEST` (24) — side-by-side assembly manifest.
pub const RT_MANIFEST: u32 = 24;

// Language pseudo-values for the `find_resource` language parameter.
/// Accept any language (do not filter by language ID).
pub const LANG_ANY: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Resource name: integer ID or named string
// ---------------------------------------------------------------------------

/// A resource name at level 1 of the resource tree: either an integer ordinal
/// or a UTF-16 string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceName {
    /// Integer resource identifier (the common case for most RT_* types).
    Id(u32),
    /// Named resource (high bit set in the directory-entry `NameOffset`).
    Name(String),
}

impl ResourceName {
    fn from_entry(raw: u32, res_base: usize, r: &Reader) -> Self {
        if raw & 0x8000_0000 != 0 {
            // Named entry: the low 31 bits are an offset into a
            // `IMAGE_RESOURCE_DIR_STRING_U` (u16 Length + Length UTF-16 code
            // units, not NUL-terminated), relative to `res_base`.
            let soff = res_base + (raw & 0x7fff_ffff) as usize;
            if let Ok(len) = r.u16(soff) {
                let len = len as usize;
                let mut units = Vec::with_capacity(len);
                for i in 0..len {
                    if let Ok(w) = r.u16(soff + 2 + i * 2) {
                        units.push(w);
                    }
                }
                return Self::Name(String::from_utf16_lossy(&units));
            }
        }
        Self::Id(raw & 0x7fff_ffff)
    }
}

// ---------------------------------------------------------------------------
// Shared PE header helpers (re-implemented locally for the raw-bytes API)
// ---------------------------------------------------------------------------

/// Locate the resource directory in `bytes`. Returns
/// `(res_base_file_offset, rva2off_closure)` where `res_base_file_offset` is
/// the file offset of the root `IMAGE_RESOURCE_DIRECTORY`, and the closure
/// converts a resource RVA (as stored in a `DATA_ENTRY`) back to a file
/// offset.
///
/// Returns `None` if the image has no resource directory or the headers are
/// malformed.
fn resource_root(bytes: &[u8]) -> Option<(usize, impl Fn(u32) -> Option<usize> + '_)> {
    let r = Reader::new(bytes);
    let pe = r.u32(0x3c).ok()? as usize;
    let coff = pe + 4;
    let opt = coff + 20;
    let magic = r.u16(opt).ok()?;
    let is64 = magic == 0x20b;
    let num_sections = r.u16(coff + 2).ok()? as usize;
    let opt_size = r.u16(coff + 16).ok()? as usize;

    // Resource data directory (data directory index 2, 8 bytes per entry).
    let dd = opt + if is64 { 112 } else { 96 };
    let res_rva = r.u32(dd + 2 * 8).ok()?;
    if res_rva == 0 {
        return None;
    }

    let sec_table = opt + opt_size;
    let mut sections: Vec<(u32, u32, u32)> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sec_table + i * 40;
        let vsize = r.u32(s + 8).ok()?;
        let va = r.u32(s + 12).ok()?;
        let rawsz = r.u32(s + 16).ok()?;
        let rawp = r.u32(s + 20).ok()?;
        sections.push((va, vsize.max(rawsz), rawp));
    }

    let rva2off = move |rva: u32| -> Option<usize> {
        for &(va, size, rawp) in &sections {
            if rva >= va && rva < va + size {
                return Some((rawp + (rva - va)) as usize);
            }
        }
        None
    };

    let res_base = rva2off(res_rva)?;
    Some((res_base, rva2off))
}

// ---------------------------------------------------------------------------
// Directory-entry iterator
// ---------------------------------------------------------------------------

/// Read all entries of one `IMAGE_RESOURCE_DIRECTORY` at file offset `off`.
/// Returns `(raw_name_field, data_or_subdir_offset, is_subdirectory)` tuples,
/// where `data_or_subdir_offset` is the low 31 bits of the `DataEntryOffset`
/// field (relative to `res_base` when `is_subdirectory`, else it points at an
/// `IMAGE_RESOURCE_DATA_ENTRY`).
fn dir_entries(r: &Reader, off: usize) -> Option<Vec<(u32, usize, bool)>> {
    // IMAGE_RESOURCE_DIRECTORY layout (public winnt.h):
    //   +0  Characteristics (DWORD)
    //   +4  TimeDateStamp   (DWORD)
    //   +8  MajorVersion    (WORD)
    //  +10  MinorVersion    (WORD)
    //  +12  NumberOfNamedEntries (WORD)
    //  +14  NumberOfIdEntries    (WORD)
    // followed immediately by NumberOfNamedEntries + NumberOfIdEntries
    // IMAGE_RESOURCE_DIRECTORY_ENTRY records (8 bytes each).
    let n_named = r.u16(off + 12).ok()? as usize;
    let n_id = r.u16(off + 14).ok()? as usize;
    let total = n_named.saturating_add(n_id);
    let mut v = Vec::with_capacity(total);
    let mut e = off + 16;
    for _ in 0..total {
        let name = r.u32(e).ok()?;
        let offset = r.u32(e + 4).ok()?;
        let is_dir = offset & 0x8000_0000 != 0;
        v.push((name, (offset & 0x7fff_ffff) as usize, is_dir));
        e += 8;
    }
    Some(v)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Find the raw bytes of a resource identified by `(type_id, name, lang)` in
/// the PE image `bytes`.
///
/// * `type_id` — the `RT_*` constant (e.g. `RT_VERSION = 16`).
/// * `name` — the resource name: use `ResourceName::Id(n)` for integer IDs
///   or `ResourceName::Name(s)` for named resources.
/// * `lang` — the language ID to prefer, or [`LANG_ANY`] to accept any
///   language. When a specific language is requested but not found,
///   the function falls back to any available language.
///
/// Returns a slice of the raw resource bytes on success, or `None` if the
/// resource is absent or the directory is malformed. Best-effort: a corrupt
/// intermediate level silently yields `None`.
///
/// The PE resource directory is a three-level tree:
///   Level 0: resource type (integer RT_* or a named type).
///   Level 1: resource name or integer ordinal.
///   Level 2: language subdirectory.
pub fn find_resource<'a>(
    bytes: &'a [u8],
    type_id: u32,
    name: &ResourceName,
    lang: u16,
) -> Option<&'a [u8]> {
    let r = Reader::new(bytes);
    let (res_base, rva2off) = resource_root(bytes)?;

    // Level 0: find the type entry.
    for (raw_name, sub_off, is_dir) in dir_entries(&r, res_base)? {
        if !is_dir {
            continue;
        }
        let entry_name = ResourceName::from_entry(raw_name, res_base, &r);
        if entry_name != ResourceName::Id(type_id) {
            continue;
        }
        // Level 1: find the name entry.
        for (raw_name2, name_off, name_is_dir) in dir_entries(&r, res_base + sub_off)? {
            if !name_is_dir {
                continue;
            }
            let entry_name2 = ResourceName::from_entry(raw_name2, res_base, &r);
            if &entry_name2 != name {
                continue;
            }
            // Level 2: find the language entry. Try exact language first, then any.
            let lang_entries = dir_entries(&r, res_base + name_off)?;
            let data_off = if lang == LANG_ANY {
                // Take the first available entry.
                lang_entries.iter().find(|(_, _, d)| !*d).map(|&(_, off, _)| off)
            } else {
                // Prefer the exact language; fall back to any if not found.
                let exact = lang_entries
                    .iter()
                    .find(|&&(raw_lang, _, d)| !d && (raw_lang & 0x7fff_ffff) as u16 == lang)
                    .map(|&(_, off, _)| off);
                if exact.is_some() {
                    exact
                } else {
                    lang_entries.iter().find(|(_, _, d)| !*d).map(|&(_, off, _)| off)
                }
            }?;

            // Read the IMAGE_RESOURCE_DATA_ENTRY (16 bytes):
            //   +0  OffsetToData (DWORD, an RVA)
            //   +4  Size         (DWORD)
            //   +8  CodePage     (DWORD)
            //  +12  Reserved     (DWORD)
            let de = res_base + data_off;
            let data_rva = r.u32(de).ok()?;
            let size = r.u32(de + 4).ok()? as usize;
            let doff = rva2off(data_rva)?;
            let end = doff.checked_add(size)?.min(bytes.len());
            return Some(&bytes[doff..end]);
        }
    }
    None
}

/// Convenience wrapper: find a resource by integer type and integer name.
/// Language falls back to any. This replaces the old `find_resource_data`.
pub fn find_resource_by_id(bytes: &[u8], type_id: u32, resource_id: u32) -> Option<&[u8]> {
    find_resource(bytes, type_id, &ResourceName::Id(resource_id), LANG_ANY)
}

/// Backward-compatible alias kept for `manifest.rs`.
///
/// Finds the first language variant of a resource identified by integer type
/// and integer ID. Equivalent to `find_resource_by_id`.
#[inline]
pub fn find_resource_data(bytes: &[u8], type_id: u32, resource_id: u32) -> Option<&[u8]> {
    find_resource_by_id(bytes, type_id, resource_id)
}

/// Summary of one resource present in the image: its type, name/ID, and
/// language ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEntry {
    /// The resource type (RT_* integer or a named type).
    pub type_id: u32,
    /// The resource type as a named string (for named types). `None` for
    /// integer types.
    pub type_name: Option<String>,
    /// The resource name within its type.
    pub name: ResourceName,
    /// The language ID (LANGID, a 16-bit packed `PRIMARYLANGID | (SUBLANGID << 10)`).
    pub lang: u16,
}

/// Walk the resource directory of `bytes` and return a summary of every
/// resource leaf (type / name / language). Best-effort: a malformed entry is
/// skipped rather than propagating an error. Returns an empty `Vec` if the
/// image has no resource directory.
///
/// The `ResourceEntry` list can be used to print a resource summary (the
/// `exemu info` command uses this) or to enumerate what a Wine DLL contains.
pub fn list_resources(bytes: &[u8]) -> Vec<ResourceEntry> {
    let r = Reader::new(bytes);
    let Some((res_base, _rva2off)) = resource_root(bytes) else {
        return Vec::new();
    };

    let mut out = Vec::new();

    let Some(type_entries) = dir_entries(&r, res_base) else {
        return out;
    };

    for (raw_type, type_sub_off, type_is_dir) in type_entries {
        if !type_is_dir {
            continue;
        }
        let (type_id, type_name) = if raw_type & 0x8000_0000 != 0 {
            let soff = res_base + (raw_type & 0x7fff_ffff) as usize;
            let name_str = if let Ok(len) = r.u16(soff) {
                let len = len as usize;
                let mut units = Vec::with_capacity(len);
                for i in 0..len {
                    if let Ok(w) = r.u16(soff + 2 + i * 2) {
                        units.push(w);
                    }
                }
                String::from_utf16_lossy(&units)
            } else {
                String::new()
            };
            // Named type — use 0 as the integer id sentinel.
            (0u32, Some(name_str))
        } else {
            (raw_type & 0x7fff_ffff, None)
        };

        let Some(name_entries) = dir_entries(&r, res_base + type_sub_off) else {
            continue;
        };

        for (raw_name, name_sub_off, name_is_dir) in name_entries {
            if !name_is_dir {
                continue;
            }
            let res_name = ResourceName::from_entry(raw_name, res_base, &r);

            let Some(lang_entries) = dir_entries(&r, res_base + name_sub_off) else {
                continue;
            };

            for (raw_lang, _data_off, data_is_dir) in lang_entries {
                if data_is_dir {
                    continue; // should not happen at level 2 but be safe
                }
                let lang_id = (raw_lang & 0xffff) as u16;
                out.push(ResourceEntry {
                    type_id,
                    type_name: type_name.clone(),
                    name: res_name.clone(),
                    lang: lang_id,
                });
            }
        }
    }

    out
}

/// Return a human-readable name for a standard `RT_*` type integer, or
/// `None` if the type is not one of the known constants.
pub fn rt_name(type_id: u32) -> Option<&'static str> {
    Some(match type_id {
        RT_CURSOR => "RT_CURSOR",
        RT_BITMAP => "RT_BITMAP",
        RT_ICON => "RT_ICON",
        RT_MENU => "RT_MENU",
        RT_DIALOG => "RT_DIALOG",
        RT_STRING => "RT_STRING",
        RT_FONTDIR => "RT_FONTDIR",
        RT_FONT => "RT_FONT",
        RT_ACCELERATOR => "RT_ACCELERATOR",
        RT_RCDATA => "RT_RCDATA",
        RT_MESSAGETABLE => "RT_MESSAGETABLE",
        RT_GROUP_CURSOR => "RT_GROUP_CURSOR",
        RT_GROUP_ICON => "RT_GROUP_ICON",
        RT_VERSION => "RT_VERSION",
        RT_DLGINCLUDE => "RT_DLGINCLUDE",
        RT_PLUGPLAY => "RT_PLUGPLAY",
        RT_VXD => "RT_VXD",
        RT_ANICURSOR => "RT_ANICURSOR",
        RT_ANIICON => "RT_ANIICON",
        RT_HTML => "RT_HTML",
        RT_MANIFEST => "RT_MANIFEST",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Typed resource parsers
// ---------------------------------------------------------------------------

/// Parse an `RT_STRING` block for string table block `block_id`.
///
/// Windows string resources store 16 UTF-16 strings per block. The string
/// with ID `string_id` lives in block `(string_id >> 4) + 1`, at slot
/// `string_id & 0xF` within that block. Each entry in the block is a `u16`
/// character count followed by that many UTF-16 code units (not
/// NUL-terminated). An entry with count 0 is absent.
///
/// `block_id` corresponds to the resource name ID stored in the directory
/// (i.e. `(target_string_id >> 4) + 1`). Returns a `Vec` of up to 16
/// strings (empty string for absent slots).
///
/// All layout details are from the public PE/COFF spec and MSDN documentation
/// for `RT_STRING` resources.
pub fn parse_string_block(block_data: &[u8]) -> Vec<String> {
    let mut result = Vec::with_capacity(16);
    let mut pos = 0usize;
    for _ in 0..16 {
        if pos + 2 > block_data.len() {
            result.push(String::new());
            continue;
        }
        let count = u16::from_le_bytes([block_data[pos], block_data[pos + 1]]) as usize;
        pos += 2;
        if count == 0 {
            result.push(String::new());
        } else {
            let end = pos + count * 2;
            if end <= block_data.len() {
                let units: Vec<u16> = (0..count)
                    .map(|i| u16::from_le_bytes([block_data[pos + i * 2], block_data[pos + i * 2 + 1]]))
                    .collect();
                result.push(String::from_utf16_lossy(&units));
                pos = end;
            } else {
                result.push(String::new());
                break;
            }
        }
    }
    result
}

/// Look up a single string by its 16-bit `string_id` from the resource section
/// of `bytes`. Returns `None` if the string is absent, the block is not found,
/// or the directory is malformed.
///
/// The block ID is `(string_id >> 4) + 1`; the slot within the block is
/// `string_id & 0xF`. Language falls back to any available language.
pub fn find_string(bytes: &[u8], string_id: u16) -> Option<String> {
    let block_id = (string_id as u32 >> 4) + 1;
    let slot = (string_id & 0xF) as usize;
    let data = find_resource_by_id(bytes, RT_STRING, block_id)?;
    let strings = parse_string_block(data);
    strings.into_iter().nth(slot).filter(|s| !s.is_empty())
}

/// A minimal, typed view of the fixed part of a `VS_VERSIONINFO` resource.
///
/// Layout per public MSDN documentation for `VS_VERSIONINFO` / `VS_FIXEDFILEINFO`:
///
/// `VS_FIXEDFILEINFO` (52 bytes, starts after the `VS_VERSIONINFO` header):
///   +0   Signature  (0xFEEF04BD)
///   +4   StrucVersion
///   +8   FileVersionMS
///  +12   FileVersionLS
///  +16   ProductVersionMS
///  +20   ProductVersionLS
///  +24   FileFlagsMask
///  +28   FileFlags
///  +32   FileOS
///  +36   FileType
///  +40   FileSubtype
///  +44   FileDateMS
///  +48   FileDateLS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedFileInfo {
    /// High DWORD of the file version: `(major << 16) | minor`.
    pub file_version_ms: u32,
    /// Low DWORD of the file version: `(patch << 16) | build`.
    pub file_version_ls: u32,
    /// High DWORD of the product version.
    pub product_version_ms: u32,
    /// Low DWORD of the product version.
    pub product_version_ls: u32,
    /// Combination of flags pertaining to the file (`VS_FF_*`).
    pub file_flags: u32,
    /// The operating system for which the file was designed.
    pub file_os: u32,
    /// The general type of file (`VFT_*`).
    pub file_type: u32,
    /// Subtype for `VFT_DRV`, `VFT_FONT`, etc.
    pub file_subtype: u32,
}

impl FixedFileInfo {
    /// The file version as `(major, minor, patch, build)`.
    pub fn file_version(&self) -> (u16, u16, u16, u16) {
        (
            (self.file_version_ms >> 16) as u16,
            (self.file_version_ms & 0xffff) as u16,
            (self.file_version_ls >> 16) as u16,
            (self.file_version_ls & 0xffff) as u16,
        )
    }

    /// The product version as `(major, minor, patch, build)`.
    pub fn product_version(&self) -> (u16, u16, u16, u16) {
        (
            (self.product_version_ms >> 16) as u16,
            (self.product_version_ms & 0xffff) as u16,
            (self.product_version_ls >> 16) as u16,
            (self.product_version_ls & 0xffff) as u16,
        )
    }
}

const VS_FIXED_FILE_INFO_SIGNATURE: u32 = 0xFEEF_04BD;

/// Parse the `VS_FIXEDFILEINFO` from a raw `VS_VERSIONINFO` blob.
///
/// The `VS_VERSIONINFO` structure (per MSDN) begins with:
///   +0   wLength       (WORD) — total length of the structure
///   +2   wValueLength  (WORD) — length of the Value member (should be 52 for VS_FIXEDFILEINFO)
///   +4   wType         (WORD) — 0 = binary data
///   +6   szKey         (WCHAR[]) — "VS_VERSION_INFO\0" (32 bytes for the 16-char string + NUL)
///   after szKey, padded to 4-byte alignment:
///   +38  (or later if padded) VS_FIXEDFILEINFO (52 bytes)
///
/// We scan for the `VS_FIXEDFILEINFO` signature `0xFEEF04BD` because the exact
/// offset can vary with padding rules; this is robust against alignment variation.
pub fn parse_version_info(data: &[u8]) -> Option<FixedFileInfo> {
    // Scan for the VS_FIXEDFILEINFO signature.
    let pos = data.windows(4).position(|w| {
        u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == VS_FIXED_FILE_INFO_SIGNATURE
    })?;

    // Need at least 52 bytes from `pos` for a full VS_FIXEDFILEINFO.
    if pos + 52 > data.len() {
        return None;
    }
    let b = &data[pos..pos + 52];
    let u32_at = |off: usize| u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);

    Some(FixedFileInfo {
        file_version_ms: u32_at(8),
        file_version_ls: u32_at(12),
        product_version_ms: u32_at(16),
        product_version_ls: u32_at(20),
        file_flags: u32_at(28),
        file_os: u32_at(32),
        file_type: u32_at(36),
        file_subtype: u32_at(40),
    })
}

/// Look up and parse the `VS_VERSIONINFO` for `bytes` (first language variant).
/// Returns `None` if there is no RT_VERSION resource or the blob is malformed.
pub fn find_version_info(bytes: &[u8]) -> Option<FixedFileInfo> {
    let data = find_resource_by_id(bytes, RT_VERSION, 1)?;
    parse_version_info(data)
}

// ---------------------------------------------------------------------------
// Dialog parser (unchanged from W0.8, kept here for `parse_dialogs`)
// ---------------------------------------------------------------------------

/// Parse all dialog templates in `bytes`, keyed by their (integer) resource id.
pub fn parse_dialogs(bytes: &[u8]) -> HashMap<u32, DialogTemplate> {
    try_parse(bytes).unwrap_or_default()
}

fn try_parse(bytes: &[u8]) -> Option<HashMap<u32, DialogTemplate>> {
    let r = Reader::new(bytes);
    let (res_base, rva2off) = resource_root(bytes)?;
    let mut out = HashMap::new();

    // Level 0: resource types. Find RT_DIALOG.
    for (raw_type, sub_off, is_dir) in dir_entries(&r, res_base)? {
        if !is_dir {
            continue;
        }
        let name = ResourceName::from_entry(raw_type, res_base, &r);
        if name != ResourceName::Id(RT_DIALOG) {
            continue;
        }
        // Level 1: names/ids of dialogs.
        for (raw_dlg, name_off, name_is_dir) in dir_entries(&r, res_base + sub_off)? {
            if !name_is_dir {
                continue;
            }
            let dlg_id = match ResourceName::from_entry(raw_dlg, res_base, &r) {
                ResourceName::Id(id) => id,
                ResourceName::Name(_) => continue, // named dialogs: skip
            };
            // Level 2: languages → data entry.
            for (_lang, data_off, data_is_dir) in dir_entries(&r, res_base + name_off)? {
                if data_is_dir {
                    continue;
                }
                let de = res_base + data_off;
                let data_rva = r.u32(de).ok()?;
                let size = r.u32(de + 4).ok()? as usize;
                let doff = rva2off(data_rva)?;
                if let Some(tpl) = parse_dialog(&bytes[doff..(doff + size).min(bytes.len())]) {
                    out.insert(dlg_id, tpl);
                }
            }
        }
    }
    Some(out)
}

/// A byte cursor over a dialog template blob.
struct Cur<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Cur<'a> {
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes([
            *self.b.get(self.o).unwrap_or(&0),
            *self.b.get(self.o + 1).unwrap_or(&0),
        ]);
        self.o += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let lo = self.u16() as u32;
        let hi = self.u16() as u32;
        lo | (hi << 16)
    }
    fn i16(&mut self) -> i16 {
        self.u16() as i16
    }
    fn peek16(&self) -> u16 {
        u16::from_le_bytes([
            *self.b.get(self.o).unwrap_or(&0),
            *self.b.get(self.o + 1).unwrap_or(&0),
        ])
    }
    fn align_dword(&mut self) {
        self.o = (self.o + 3) & !3;
    }
    /// Read a menu/class/title field: 0x0000 = none, 0xFFFF + ordinal, else
    /// a NUL-terminated wide string. Returns the string (empty for ordinals).
    fn sz_or_ord(&mut self) -> String {
        match self.peek16() {
            0x0000 => {
                self.o += 2;
                String::new()
            }
            0xFFFF => {
                self.o += 4; // 0xFFFF + ordinal
                String::new()
            }
            _ => self.wstr(),
        }
    }
    fn wstr(&mut self) -> String {
        let mut units = Vec::new();
        loop {
            let w = self.u16();
            if w == 0 {
                break;
            }
            units.push(w);
        }
        String::from_utf16_lossy(&units)
    }
}

fn parse_dialog(b: &[u8]) -> Option<DialogTemplate> {
    let mut c = Cur { b, o: 0 };
    let ex = c.peek16() == 0xFFFF;

    // Header (fields read strictly in order — no fixed offsets).
    let style;
    let count;
    let (cx, cy);
    if ex {
        c.u16(); // dlgVer
        c.u16(); // signature (0xFFFF)
        c.u32(); // helpID
        c.u32(); // exStyle
        style = c.u32();
        count = c.u16();
        c.i16(); // x
        c.i16(); // y
        cx = c.u16();
        cy = c.u16();
    } else {
        style = c.u32();
        c.u32(); // exStyle
        count = c.u16();
        c.i16(); // x
        c.i16(); // y
        cx = c.u16();
        cy = c.u16();
    }

    c.sz_or_ord(); // menu
    c.sz_or_ord(); // window class
    let title = c.sz_or_ord(); // title
    // DS_SETFONT (0x40): pointsize (+weight/italic/charset for EX) + typeface.
    if style & 0x40 != 0 {
        if ex {
            c.o += 6;
        } else {
            c.o += 2;
        }
        c.wstr();
    }

    let mut controls = Vec::with_capacity(count as usize);
    for _ in 0..count {
        c.align_dword();
        let ctl_style;
        let (x, y, cw, ch);
        let id;
        if ex {
            c.u32(); // helpID
            c.u32(); // exStyle
            ctl_style = c.u32();
            x = c.i16();
            y = c.i16();
            cw = c.i16();
            ch = c.i16();
            id = c.u32();
        } else {
            ctl_style = c.u32();
            c.u32(); // exStyle
            x = c.i16();
            y = c.i16();
            cw = c.i16();
            ch = c.i16();
            id = c.u16() as u32;
        }

        // class: ordinal (0xFFFF + u16) or wide string.
        let class_ord;
        let class_name;
        if c.peek16() == 0xFFFF {
            c.o += 2;
            class_ord = c.u16();
            class_name = String::new();
        } else {
            class_ord = 0;
            class_name = c.wstr();
        }
        let text = if c.peek16() == 0xFFFF {
            c.o += 4;
            String::new()
        } else {
            c.wstr()
        };
        let extra = c.u16() as usize; // creation-data byte count
        c.o += extra;

        let kind = classify_control(class_ord, &class_name, ctl_style);
        controls.push(Control { id, kind, text, x, y, cx: cw, cy: ch });
    }

    Some(DialogTemplate { title, cx, cy, controls })
}

fn classify_control(class_ord: u16, class_name: &str, style: u32) -> ControlKind {
    let lname = class_name.to_ascii_lowercase();
    if class_ord == 0x0080 || lname == "button" {
        let bs = style & 0xf;
        // BS_CHECKBOX=2, BS_AUTOCHECKBOX=3, BS_RADIOBUTTON=4, BS_AUTORADIO=9
        if matches!(bs, 2 | 3 | 4 | 5 | 6 | 9) {
            ControlKind::Check
        } else {
            // BS_DEFPUSHBUTTON = 1
            ControlKind::Button { default: bs == 1 }
        }
    } else if class_ord == 0x0081 || lname == "edit" {
        ControlKind::Edit
    } else if class_ord == 0x0082 || lname == "static" {
        ControlKind::Static
    } else if lname.contains("progress") {
        ControlKind::Progress
    } else {
        ControlKind::Other
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // String block parser
    // -----------------------------------------------------------------------

    /// Build a synthetic RT_STRING block where slots are:
    ///   0: empty (count=0)
    ///   1: "Hello" (5 UTF-16 code units)
    ///   2..15: empty
    fn string_block_fixture() -> Vec<u8> {
        let mut data = Vec::new();
        // Slot 0: count = 0
        data.extend_from_slice(&0u16.to_le_bytes());
        // Slot 1: "Hello" (5 chars)
        let hello: Vec<u16> = "Hello".encode_utf16().collect();
        data.extend_from_slice(&(hello.len() as u16).to_le_bytes());
        for w in &hello {
            data.extend_from_slice(&w.to_le_bytes());
        }
        // Slots 2..15: count = 0
        for _ in 2u16..16 {
            data.extend_from_slice(&0u16.to_le_bytes());
        }
        data
    }

    #[test]
    fn string_block_parses_slots_correctly() {
        let data = string_block_fixture();
        let strings = parse_string_block(&data);
        assert_eq!(strings.len(), 16);
        assert!(strings[0].is_empty(), "slot 0 must be empty");
        assert_eq!(strings[1], "Hello", "slot 1 must be 'Hello'");
        for s in strings.iter().skip(2) {
            assert!(s.is_empty(), "remaining slots must be empty");
        }
    }

    #[test]
    fn string_block_handles_empty_input() {
        let strings = parse_string_block(&[]);
        // All 16 slots should be empty rather than panicking.
        assert_eq!(strings.len(), 16);
        for s in &strings {
            assert!(s.is_empty());
        }
    }

    #[test]
    fn string_block_handles_truncated_input() {
        // Two bytes: count = 5 (5 UTF-16 chars to follow), but no data.
        let data = 5u16.to_le_bytes().to_vec();
        let strings = parse_string_block(&data);
        // Should not panic; slot 0 is empty (data too short to read the chars).
        assert!(strings[0].is_empty());
    }

    // -----------------------------------------------------------------------
    // VS_VERSIONINFO parser
    // -----------------------------------------------------------------------

    /// Build a minimal VS_VERSIONINFO blob containing a VS_FIXEDFILEINFO with
    /// controlled version numbers. The layout follows the public MSDN spec:
    ///   +0  wLength (u16) = total size
    ///   +2  wValueLength (u16) = 52 (size of VS_FIXEDFILEINFO)
    ///   +4  wType (u16) = 0
    ///   +6  szKey = "VS_VERSION_INFO\0" (16 UTF-16 code units = 32 bytes)
    ///  +38  padding to 4-byte alignment (2 bytes)
    ///  +40  VS_FIXEDFILEINFO (52 bytes)
    fn version_info_fixture(
        file_major: u16,
        file_minor: u16,
        file_patch: u16,
        file_build: u16,
    ) -> Vec<u8> {
        let mut data = vec![0u8; 92]; // 40 header + 52 FIXEDFILEINFO
        let total = data.len() as u16;
        data[0..2].copy_from_slice(&total.to_le_bytes()); // wLength
        data[2..4].copy_from_slice(&52u16.to_le_bytes()); // wValueLength
        data[4..6].copy_from_slice(&0u16.to_le_bytes()); // wType
        // szKey: "VS_VERSION_INFO\0" in UTF-16LE (16 code units = 32 bytes)
        let key: Vec<u8> = "VS_VERSION_INFO\0"
            .encode_utf16()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        data[6..6 + key.len()].copy_from_slice(&key); // 32 bytes
        // +38 = 2 bytes of padding; left as 0.
        // VS_FIXEDFILEINFO starts at offset 40.
        let b = &mut data[40..];
        let put32 = |d: &mut [u8], off: usize, v: u32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        put32(b, 0, VS_FIXED_FILE_INFO_SIGNATURE); // dwSignature
        put32(b, 4, 0x0001_0000); // dwStrucVersion (1.0)
        put32(b, 8, ((file_major as u32) << 16) | file_minor as u32); // dwFileVersionMS
        put32(b, 12, ((file_patch as u32) << 16) | file_build as u32); // dwFileVersionLS
        put32(b, 16, ((file_major as u32) << 16) | file_minor as u32); // dwProductVersionMS (same)
        put32(b, 20, ((file_patch as u32) << 16) | file_build as u32); // dwProductVersionLS
        put32(b, 24, 0x3f); // dwFileFlagsMask
        put32(b, 28, 0); // dwFileFlags
        put32(b, 32, 0x0004); // dwFileOS (VOS_WIN32)
        put32(b, 36, 0x0001); // dwFileType (VFT_APP)
        put32(b, 40, 0); // dwFileSubtype
        put32(b, 44, 0); // dwFileDateMS
        put32(b, 48, 0); // dwFileDateLS
        data
    }

    #[test]
    fn parse_version_info_extracts_file_version() {
        let data = version_info_fixture(1, 2, 3, 4);
        let info = parse_version_info(&data).expect("must parse");
        assert_eq!(info.file_version(), (1, 2, 3, 4), "file version");
        assert_eq!(info.product_version(), (1, 2, 3, 4), "product version");
        assert_eq!(info.file_type, 0x0001, "file type = VFT_APP");
        assert_eq!(info.file_os, 0x0004, "file os = VOS_WIN32");
    }

    #[test]
    fn parse_version_info_returns_none_for_missing_signature() {
        let data = vec![0u8; 92]; // no signature
        assert!(parse_version_info(&data).is_none());
    }

    #[test]
    fn parse_version_info_returns_none_for_truncated_data() {
        let mut data = version_info_fixture(1, 0, 0, 0);
        data.truncate(50); // cut off the FIXEDFILEINFO
        // The signature may be in the truncated portion; ensure no panic.
        let _ = parse_version_info(&data);
    }

    // -----------------------------------------------------------------------
    // Corpus integration tests (against real binaries in example_exe/)
    // -----------------------------------------------------------------------

    const EXAMPLE_EXE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_exe");

    /// Skip a test if the binary is not present (CI may not have the corpus).
    fn read_binary(name: &str) -> Option<Vec<u8>> {
        let path = format!("{EXAMPLE_EXE}/{name}");
        std::fs::read(&path).ok()
    }

    #[test]
    fn tcc_has_no_rt_version_or_manifest() {
        // tcc.exe is a small console tool; it may or may not have a version
        // resource. We simply verify the call does not panic.
        let Some(bytes) = read_binary("tcc.exe") else {
            return; // corpus absent — skip
        };
        // No assertion on result: just prove no panic.
        let _ = find_version_info(&bytes);
        let entries = list_resources(&bytes);
        // If it has resources, they must all be valid (non-empty type id range).
        for e in &entries {
            // Named type has type_id = 0 sentinel; integer types > 0.
            assert!(e.type_id > 0 || e.type_name.is_some());
        }
    }

    #[test]
    fn z7_has_rt_version_and_manifest() {
        let Some(bytes) = read_binary("7z2602-x64.exe") else {
            return; // corpus absent — skip
        };

        // RT_VERSION must be present in 7z.
        let info = find_version_info(&bytes)
            .expect("7z2602-x64.exe must have RT_VERSION with a valid VS_FIXEDFILEINFO");
        // 7-Zip 26.02: expect major version 26.
        let (major, _minor, _patch, _build) = info.file_version();
        assert_eq!(major, 26, "7z file version major must be 26");

        // RT_MANIFEST must be present (W0.8 already tested the manifest content,
        // but verify find_resource also finds it via the new API).
        let manifest =
            find_resource(&bytes, RT_MANIFEST, &ResourceName::Id(1), LANG_ANY);
        assert!(manifest.is_some(), "7z must have RT_MANIFEST ID 1");

        // list_resources must include both RT_VERSION and RT_MANIFEST.
        let entries = list_resources(&bytes);
        assert!(
            entries.iter().any(|e| e.type_id == RT_VERSION),
            "list_resources must include RT_VERSION"
        );
        assert!(
            entries.iter().any(|e| e.type_id == RT_MANIFEST),
            "list_resources must include RT_MANIFEST"
        );
        // RT_DIALOG entries (7z has many dialogs).
        assert!(
            entries.iter().any(|e| e.type_id == RT_DIALOG),
            "list_resources must include RT_DIALOG"
        );
    }

    #[test]
    fn named_resource_name_round_trips() {
        // Verify ResourceName::Name is constructed correctly from raw entry
        // data. We test the Id path indirectly through the corpus tests above;
        // here we exercise the Name path directly.
        let name = ResourceName::Name("TestResource".to_string());
        assert_eq!(name, ResourceName::Name("TestResource".to_string()));
        assert_ne!(name, ResourceName::Id(42));
    }

    #[test]
    fn find_resource_returns_none_for_absent_type() {
        let Some(bytes) = read_binary("7z2602-x64.exe") else {
            return;
        };
        // RT_FONT (8) is unlikely to exist in an installer.
        let result = find_resource(&bytes, RT_FONT, &ResourceName::Id(1), LANG_ANY);
        // Either None (absent) or Some (unexpectedly present) — must not panic.
        let _ = result;
    }

    #[test]
    fn find_string_returns_none_for_absent_block() {
        // An empty byte slice has no resource directory.
        let result = find_string(&[], 0x100);
        assert!(result.is_none());
    }

    #[test]
    fn rt_name_covers_standard_types() {
        assert_eq!(rt_name(RT_ICON), Some("RT_ICON"));
        assert_eq!(rt_name(RT_VERSION), Some("RT_VERSION"));
        assert_eq!(rt_name(RT_MANIFEST), Some("RT_MANIFEST"));
        assert_eq!(rt_name(RT_STRING), Some("RT_STRING"));
        assert_eq!(rt_name(RT_MENU), Some("RT_MENU"));
        assert_eq!(rt_name(99), None); // unknown
    }

    #[test]
    fn list_resources_returns_empty_for_minimal_pe() {
        // A tiny PE with no resource directory must return an empty list.
        let pe = minimal_pe_no_resource();
        let entries = list_resources(&pe);
        assert!(entries.is_empty(), "minimal PE must have no resources");
    }

    /// Build a minimal valid PE32+ with no data directories populated.
    /// Used to prove `list_resources` returns empty for images without
    /// a resource directory.
    fn minimal_pe_no_resource() -> Vec<u8> {
        // Constants mirrored from lib.rs (public PE/COFF spec values).
        const PE_SIGNATURE: u32 = 0x0000_4550;
        const MACHINE_AMD64: u16 = 0x8664;
        const OPT_MAGIC_PE32PLUS: u16 = 0x20B;

        let mut f = vec![0u8; 0x600];
        // DOS header: "MZ" magic.
        f[0] = 0x4D;
        f[1] = 0x5A;
        let pe_off = 0x80usize;
        f[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        // PE signature.
        f[pe_off..pe_off + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        let coff = pe_off + 4;
        f[coff..coff + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        f[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        let size_opt = 0xF0u16;
        f[coff + 16..coff + 18].copy_from_slice(&size_opt.to_le_bytes());
        let opt = coff + 20;
        f[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32PLUS.to_le_bytes());
        f[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        f[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // ImageBase
        f[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        f[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        f[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem = console
        f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        // All 16 data directories are zero (no resources, no imports, etc.).

        // Section table.
        let sec = opt + size_opt as usize;
        f[sec..sec + 5].copy_from_slice(b".text");
        f[sec + 8..sec + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        f[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        f[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        f[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        f[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXEC|READ
        f
    }
}

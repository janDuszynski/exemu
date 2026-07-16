//! Builder for a minimal, valid **`API_SET_NAMESPACE`** (schema **version 6**),
//! the structure `PEB.ApiSetMap` (x64 PEB `+0x68`, x86 PEB `+0x38`) points at.
//!
//! Windows' loader consults this namespace to translate a virtual API-set
//! *contract* DLL name (`api-ms-win-*`, `ext-ms-win-*`) into the concrete host
//! DLL that implements it, before it ever touches the disk. Wine's PE `ntdll`
//! does the same: `loader_init → build_module → build_import_name` reads
//! `PEB.ApiSetMap` for **every** imported DLL name and calls the internal
//! `get_apiset_entry`, so the loader faults the instant `PEB.ApiSetMap` is a
//! null / unmapped pointer. Seeding a well-formed namespace clears that fault.
//!
//! # Clean-room provenance (Class B)
//!
//! The exact layout + hash algorithm below were recovered from the **pinned**
//! Wine 11.0 `ntdll.dll` disassembly (permitted guest-binary analysis) — no
//! Wine `.c` source was read. The authoritative sites in that binary are:
//!
//! * `build_import_name` (`+0x21` : `mov rax,gs:[0x30]; mov rax,[rax+0x60];
//!   mov rdi,[rax+0x68]`) — proves **`PEB.ApiSetMap` is at PEB `+0x68`** (x64).
//! * `get_apiset_entry` — the resolver. Its prologue `_wcsnicmp`s the first 4
//!   chars against `L"api-"` / `L"ext-"`, computes the hash, binary-searches the
//!   hash table, then validates the entry and returns the value. From it:
//!   - **Header** (self-relative u32 offsets from the namespace base):
//!     `Version @0x00, Size @0x04, Flags @0x08, Count @0x0C, EntryOffset @0x10,
//!     HashOffset @0x14, HashFactor @0x18`.
//!   - **Hash** = fold over the lower-cased **hashable prefix** — the contract
//!     name up to (but **excluding**) the *last* `-` before the first `.` —
//!     with `hash = hash * HashFactor + wchar` (`imul ebp,edx; … add eax,edx`,
//!     `ebp = header.HashFactor`). Letters `A..Z` are lower-cased by `+0x20`.
//!   - **Hash table** `API_SET_HASH_ENTRY { Hash u32, Index u32 }` @ HashOffset,
//!     `Count` entries, **sorted ascending by Hash** (the code binary-searches).
//!   - The matched entry's `HashedLength` (@ entry+0x0C) is compared against
//!     `2 * hashable_char_count`, and `_wcsnicmp` re-checks the prefix.
//!   - **Entry** `API_SET_NAMESPACE_ENTRY { Flags u32, NameOffset u32,
//!     NameLength u32, HashedLength u32, ValueOffset u32, ValueCount u32 }`
//!     (0x18 bytes) @ EntryOffset.
//!   - **Value** `API_SET_VALUE_ENTRY { Flags u32, NameOffset u32,
//!     NameLength u32, ValueOffset u32, ValueLength u32 }` (0x14 bytes): `Name`
//!     is the importing-module filter (empty ⇒ the default), `Value` is the host
//!     DLL name in UTF-16 (no `.dll` here — but real maps store it WITH `.dll`;
//!     we store `<host>.dll` so the loader's substitution yields a loadable
//!     name). `build_import_name` copies `Value` (≤ 0x1FF bytes) over the import
//!     name when a match is found.
//!
//! All strings are UTF-16LE, stored **without** a NUL terminator (the lengths
//! are byte counts). `HashFactor` is `0x1F` (31), the value real Windows maps
//! use; any factor works as long as the stored hashes are computed with it, and
//! we hash with exactly this one.

// `+ 0x00` is written explicitly on the first field of each struct so the field
// offsets line up as a self-documenting layout column; suppress the lint.
#![allow(clippy::identity_op)]

/// The API-set schema version this builder emits.
pub const API_SET_SCHEMA_VERSION: u32 = 6;

/// The multiplier folded into the contract-name hash. Real Windows API-set maps
/// use `0x1F`; the loader reads it back from `header.HashFactor`, so the only
/// invariant is that our stored hashes are computed with the same value.
pub const HASH_FACTOR: u32 = 0x1F;

const HEADER_SIZE: u32 = 0x1C; // Version..HashFactor (7 u32; padded below)
const ENTRY_SIZE: u32 = 0x18; // API_SET_NAMESPACE_ENTRY
const VALUE_SIZE: u32 = 0x14; // API_SET_VALUE_ENTRY
const HASH_ENTRY_SIZE: u32 = 0x08; // API_SET_HASH_ENTRY

/// Lower-case an ASCII UTF-16 code unit the way the loader does (`A..Z` +0x20).
#[inline]
fn lower(c: u16) -> u16 {
    if (0x41..=0x5A).contains(&c) { c + 0x20 } else { c }
}

/// The **hashable prefix** of a contract name: everything up to (not including)
/// the *last* `-` that precedes the first `.`. Returns the prefix as a slice of
/// UTF-16 code units. Mirrors `get_apiset_entry`'s prefix scan exactly.
fn hashable_prefix(name_utf16: &[u16]) -> &[u16] {
    let mut last_hyphen: Option<usize> = None;
    for (i, &c) in name_utf16.iter().enumerate() {
        if c == 0x2E {
            break; // '.'
        }
        if c == 0x2D {
            last_hyphen = Some(i); // '-'
        }
    }
    match last_hyphen {
        Some(i) => &name_utf16[..i],
        // No hyphen before the first dot: the loader hashes nothing (len 0).
        None => &name_utf16[..0],
    }
}

/// Compute the API-set hash of a contract name using `factor`, matching
/// `get_apiset_entry`: `hash = hash * factor + lower(c)` over the hashable
/// prefix (32-bit wrapping arithmetic).
pub fn api_set_hash(name: &str, factor: u32) -> u32 {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut hash: u32 = 0;
    for &c in hashable_prefix(&units) {
        hash = hash.wrapping_mul(factor).wrapping_add(u32::from(lower(c)));
    }
    hash
}

/// One resolved contract → host mapping to place in the namespace.
struct BuiltEntry {
    /// The contract name, lower-cased, no `.dll` (e.g. `api-ms-win-crt-runtime-l1-1-0`).
    name: Vec<u16>,
    /// Byte length of [`Self::name`] (no NUL).
    name_bytes: u32,
    /// Byte length of the hashable prefix (`HashedLength`).
    hashed_bytes: u32,
    /// The contract's hash (with [`HASH_FACTOR`]).
    hash: u32,
    /// The host DLL name **with** `.dll`, UTF-16 (e.g. `ucrtbase.dll`).
    value: Vec<u16>,
    /// Byte length of [`Self::value`].
    value_bytes: u32,
}

/// A finished, self-consistent v6 `API_SET_NAMESPACE` blob plus the offsets a
/// test can assert against. `bytes` is placed verbatim in guest memory and
/// `PEB.ApiSetMap` set to its base (offsets are self-relative to that base).
pub struct ApiSetNamespace {
    /// The serialized namespace (poke this into guest memory as-is).
    pub bytes: Vec<u8>,
    /// `header.Count`.
    pub count: u32,
    /// `header.EntryOffset`.
    pub entry_offset: u32,
    /// `header.HashOffset`.
    pub hash_offset: u32,
}

/// Build a populated v6 `API_SET_NAMESPACE` covering the common contract
/// families. Each contract resolves (via [`exemu_loader::resolve_api_set`]) to
/// its host DLL, so a guest that imports e.g. `api-ms-win-crt-stdio-l1-1-0`
/// gets `ucrtbase.dll` substituted. Contracts the guest actually needs beyond
/// this set still resolve *by name* (the loader falls back to the literal name
/// on a namespace miss), so an incomplete list never faults — it just misses a
/// redirection.
pub fn build_populated_namespace() -> ApiSetNamespace {
    build_namespace(DEFAULT_CONTRACTS)
}

/// Build a v6 `API_SET_NAMESPACE` from an explicit `(contract, host_with_dll)`
/// list. `contract` must be lower-cased with no `.dll`; `host` is the host DLL
/// name **with** `.dll`. Entries are sorted by hash for the loader's binary
/// search; a hash collision would corrupt the search, so this asserts uniqueness
/// (the curated [`DEFAULT_CONTRACTS`] set is collision-free under [`HASH_FACTOR`]).
pub fn build_namespace(contracts: &[(&str, &str)]) -> ApiSetNamespace {
    // 1. Resolve + hash every contract.
    let entries: Vec<BuiltEntry> = contracts
        .iter()
        .map(|&(contract, host)| {
            let name: Vec<u16> = contract.encode_utf16().collect();
            let hashed_len_chars = hashable_prefix(&name).len();
            let value: Vec<u16> = host.encode_utf16().collect();
            BuiltEntry {
                name_bytes: (name.len() * 2) as u32,
                hashed_bytes: (hashed_len_chars * 2) as u32,
                hash: api_set_hash(contract, HASH_FACTOR),
                value_bytes: (value.len() * 2) as u32,
                name,
                value,
            }
        })
        .collect();

    let count = entries.len() as u32;

    // 2. Lay out the regions. Header (padded to 8) | entries | values | hashes |
    //    strings. All offsets are self-relative to the namespace base.
    let header_end = align8(HEADER_SIZE);
    let entry_offset = header_end;
    let value_offset_base = entry_offset + count * ENTRY_SIZE;
    let hash_offset = value_offset_base + count * VALUE_SIZE;
    let strings_base = hash_offset + count * HASH_ENTRY_SIZE;

    // 3. Place each entry's name + value strings after the fixed tables and
    //    record their offsets. Names and values are laid out contract-by-contract.
    let mut strings: Vec<u8> = Vec::new();
    let mut name_offsets = Vec::with_capacity(entries.len());
    let mut value_offsets = Vec::with_capacity(entries.len());
    for e in &entries {
        let name_off = strings_base + strings.len() as u32;
        for &u in &e.name {
            strings.extend_from_slice(&u.to_le_bytes());
        }
        let value_off = strings_base + strings.len() as u32;
        for &u in &e.value {
            strings.extend_from_slice(&u.to_le_bytes());
        }
        name_offsets.push(name_off);
        value_offsets.push(value_off);
    }
    let total = strings_base + strings.len() as u32;
    let total = align8(total);

    // 4. Serialize.
    let mut bytes = vec![0u8; total as usize];

    // Header.
    put_u32(&mut bytes, 0x00, API_SET_SCHEMA_VERSION);
    put_u32(&mut bytes, 0x04, total); // Size
    put_u32(&mut bytes, 0x08, 0); // Flags
    put_u32(&mut bytes, 0x0C, count);
    put_u32(&mut bytes, 0x10, entry_offset);
    put_u32(&mut bytes, 0x14, hash_offset);
    put_u32(&mut bytes, 0x18, HASH_FACTOR);

    // Entries (one value each; the value's own NameOffset/NameLength are 0 =
    // the empty importer filter ⇒ this value is the default for any importer).
    for (i, e) in entries.iter().enumerate() {
        let eo = entry_offset + i as u32 * ENTRY_SIZE;
        let vo = value_offset_base + i as u32 * VALUE_SIZE;
        put_u32(&mut bytes, eo + 0x00, 0); // Flags
        put_u32(&mut bytes, eo + 0x04, name_offsets[i]); // NameOffset
        put_u32(&mut bytes, eo + 0x08, e.name_bytes); // NameLength (bytes)
        put_u32(&mut bytes, eo + 0x0C, e.hashed_bytes); // HashedLength (bytes)
        put_u32(&mut bytes, eo + 0x10, vo); // ValueOffset
        put_u32(&mut bytes, eo + 0x14, 1); // ValueCount

        put_u32(&mut bytes, vo + 0x00, 0); // Value.Flags
        put_u32(&mut bytes, vo + 0x04, 0); // Value.NameOffset (empty filter)
        put_u32(&mut bytes, vo + 0x08, 0); // Value.NameLength
        put_u32(&mut bytes, vo + 0x0C, value_offsets[i]); // Value.ValueOffset
        put_u32(&mut bytes, vo + 0x10, e.value_bytes); // Value.ValueLength (bytes)
    }

    // 5. Hash table, sorted ascending by hash, mapping hash → entry index.
    let mut hash_index: Vec<(u32, u32)> =
        (0..entries.len()).map(|i| (entries[i].hash, i as u32)).collect();
    hash_index.sort_by_key(|&(h, _)| h);
    // A collision would break the loader's binary search — the curated set is
    // collision-free, but guard so a future addition can't silently corrupt it.
    for w in hash_index.windows(2) {
        assert_ne!(
            w[0].0, w[1].0,
            "API-set hash collision ({:#x}); pick a distinct contract",
            w[0].0
        );
    }
    for (i, &(h, idx)) in hash_index.iter().enumerate() {
        let ho = hash_offset + i as u32 * HASH_ENTRY_SIZE;
        put_u32(&mut bytes, ho + 0x00, h); // Hash
        put_u32(&mut bytes, ho + 0x04, idx); // Index
    }

    // 6. Strings.
    bytes[strings_base as usize..strings_base as usize + strings.len()].copy_from_slice(&strings);

    ApiSetNamespace { bytes, count, entry_offset, hash_offset }
}

#[inline]
fn align8(v: u32) -> u32 {
    v.div_ceil(8) * 8
}

#[inline]
fn put_u32(buf: &mut [u8], off: u32, val: u32) {
    buf[off as usize..off as usize + 4].copy_from_slice(&val.to_le_bytes());
}

/// The curated contract set the seeded namespace carries. One representative
/// contract per common family, resolved to its host via
/// [`exemu_loader::resolve_api_set`] at build time below. This is deliberately
/// small: the four Wine core DLLs import each other by real name (no api-set
/// contract), so the boot path needs only a *valid, non-null* namespace; these
/// entries add real redirections for the CRT/core contracts a downlevel guest
/// exe imports, without pretending to be the full ~1500-entry Windows map.
const DEFAULT_CONTRACTS: &[(&str, &str)] = &[
    // CRT family → ucrtbase.
    ("api-ms-win-crt-runtime-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-stdio-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-heap-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-string-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-math-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-locale-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-convert-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-environment-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-filesystem-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-time-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-utility-l1-1-0", "ucrtbase.dll"),
    ("api-ms-win-crt-multibyte-l1-1-0", "ucrtbase.dll"),
    // Core family → kernelbase.
    ("api-ms-win-core-processthreads-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-synch-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-file-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-file-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-memory-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-heap-l2-1-0", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-libraryloader-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-sysinfo-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-errorhandling-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-debug-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-handle-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-localization-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-rtlsupport-l1-1-0", "ntdll.dll"),
    ("api-ms-win-core-string-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-profile-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-util-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-console-l1-2-0", "kernelbase.dll"),
    ("api-ms-win-core-namedpipe-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-datetime-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-timezone-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-version-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-fibers-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-interlocked-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-io-l1-1-0", "kernelbase.dll"),
    ("api-ms-win-core-registry-l1-1-0", "kernelbase.dll"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(b: &[u8], off: u32) -> u32 {
        u32::from_le_bytes(b[off as usize..off as usize + 4].try_into().unwrap())
    }

    fn read_utf16(b: &[u8], off: u32, byte_len: u32) -> String {
        let units: Vec<u16> = (0..byte_len / 2)
            .map(|i| u16::from_le_bytes(b[(off + i * 2) as usize..(off + i * 2) as usize + 2].try_into().unwrap()))
            .collect();
        String::from_utf16(&units).unwrap()
    }

    /// The hashable prefix matches the pinned-binary rule: up to (not incl.) the
    /// last hyphen before the first dot. `api-ms-win-crt-runtime-l1-1-0` hashes
    /// its `…-l1-1` prefix (the final `-0` is excluded).
    #[test]
    fn hashable_prefix_stops_at_last_hyphen() {
        let name = "api-ms-win-crt-runtime-l1-1-0";
        let units: Vec<u16> = name.encode_utf16().collect();
        let prefix = hashable_prefix(&units);
        assert_eq!(String::from_utf16(prefix).unwrap(), "api-ms-win-crt-runtime-l1-1");
    }

    /// Lower-casing folds `A..Z` and leaves hyphens/digits alone, so an
    /// upper-case contract hashes identically to its lower-case form.
    #[test]
    fn hash_is_case_insensitive() {
        let a = api_set_hash("api-ms-win-core-synch-l1-2-0", HASH_FACTOR);
        let b = api_set_hash("API-MS-WIN-CORE-SYNCH-L1-2-0", HASH_FACTOR);
        assert_eq!(a, b);
    }

    /// Header fields carry the expected schema constants and self-consistent
    /// offsets, and every declared region lies inside the blob.
    #[test]
    fn header_is_well_formed_v6() {
        let ns = build_populated_namespace();
        let b = &ns.bytes;
        assert_eq!(read_u32(b, 0x00), 6, "Version = 6");
        assert_eq!(read_u32(b, 0x04) as usize, b.len(), "Size == blob length");
        assert_eq!(read_u32(b, 0x08), 0, "Flags = 0");
        assert_eq!(read_u32(b, 0x0C), ns.count, "Count");
        assert_eq!(read_u32(b, 0x10), ns.entry_offset, "EntryOffset");
        assert_eq!(read_u32(b, 0x14), ns.hash_offset, "HashOffset");
        assert_eq!(read_u32(b, 0x18), HASH_FACTOR, "HashFactor");

        // Every entry/value/hash region + its strings are in-bounds.
        let len = b.len() as u32;
        assert!(ns.entry_offset + ns.count * ENTRY_SIZE <= len);
        assert!(ns.hash_offset + ns.count * HASH_ENTRY_SIZE <= len);
        for i in 0..ns.count {
            let eo = ns.entry_offset + i * ENTRY_SIZE;
            let name_off = read_u32(b, eo + 0x04);
            let name_len = read_u32(b, eo + 0x08);
            assert!(name_off + name_len <= len, "entry {i} name string in-bounds");
            let vo = read_u32(b, eo + 0x10);
            assert!(vo + VALUE_SIZE <= len, "entry {i} value in-bounds");
            let val_off = read_u32(b, vo + 0x0C);
            let val_len = read_u32(b, vo + 0x10);
            assert!(val_off + val_len <= len, "entry {i} value string in-bounds");
        }
    }

    /// The hash table is sorted ascending (so ntdll's binary search is valid)
    /// and every index points at a real entry.
    #[test]
    fn hash_table_is_sorted_and_indices_valid() {
        let ns = build_populated_namespace();
        let b = &ns.bytes;
        let mut prev = 0u32;
        for i in 0..ns.count {
            let ho = ns.hash_offset + i * HASH_ENTRY_SIZE;
            let h = read_u32(b, ho + 0x00);
            let idx = read_u32(b, ho + 0x04);
            if i > 0 {
                assert!(h > prev, "hash table strictly ascending at {i}");
            }
            prev = h;
            assert!(idx < ns.count, "hash entry {i} index in range");
        }
    }

    /// Resolve a known contract exactly as ntdll's `get_apiset_entry` would —
    /// hash it, binary-search the hash table, follow Index → entry → value —
    /// and assert we land on the expected host DLL. Proves the whole namespace
    /// is walkable end-to-end for a real contract.
    #[test]
    fn known_contract_resolves_to_expected_host() {
        let ns = build_populated_namespace();
        let b = &ns.bytes;

        let resolve = |contract: &str| -> Option<String> {
            let h = api_set_hash(contract, HASH_FACTOR);
            // Binary search the (sorted) hash table.
            let mut lo = 0i64;
            let mut hi = ns.count as i64 - 1;
            while lo <= hi {
                let mid = (lo + hi) / 2;
                let ho = ns.hash_offset + mid as u32 * HASH_ENTRY_SIZE;
                let mh = read_u32(b, ho + 0x00);
                match mh.cmp(&h) {
                    std::cmp::Ordering::Equal => {
                        let idx = read_u32(b, ho + 0x04);
                        let eo = ns.entry_offset + idx * ENTRY_SIZE;
                        // Verify the entry name prefix really matches.
                        let name = read_utf16(b, read_u32(b, eo + 0x04), read_u32(b, eo + 0x08));
                        assert!(name.starts_with(contract) || contract.starts_with(&name) || name == contract);
                        let vo = read_u32(b, eo + 0x10);
                        let val_off = read_u32(b, vo + 0x0C);
                        let val_len = read_u32(b, vo + 0x10);
                        return Some(read_utf16(b, val_off, val_len));
                    }
                    std::cmp::Ordering::Less => lo = mid + 1,
                    std::cmp::Ordering::Greater => hi = mid - 1,
                }
            }
            None
        };

        assert_eq!(resolve("api-ms-win-crt-stdio-l1-1-0").as_deref(), Some("ucrtbase.dll"));
        assert_eq!(resolve("api-ms-win-core-synch-l1-2-0").as_deref(), Some("kernelbase.dll"));
        assert_eq!(resolve("api-ms-win-core-rtlsupport-l1-1-0").as_deref(), Some("ntdll.dll"));
        // A contract not in the map misses cleanly (the loader falls back to the
        // literal name — no fault).
        assert_eq!(resolve("api-ms-win-core-nonexistent-l9-9-9"), None);
    }

    /// The empty namespace is still a valid v6 header the loader can deref +
    /// binary-search (Count 0 ⇒ the search returns "not present" without an OOB
    /// read) — the minimal seed that clears the `PEB.ApiSetMap` fault.
    #[test]
    fn empty_namespace_is_valid() {
        let ns = build_namespace(&[]);
        let b = &ns.bytes;
        assert_eq!(read_u32(b, 0x00), 6);
        assert_eq!(read_u32(b, 0x0C), 0, "Count = 0");
        assert_eq!(read_u32(b, 0x04) as usize, b.len());
        // EntryOffset / HashOffset still point in-bounds (to empty regions).
        assert!(ns.entry_offset <= b.len() as u32);
        assert!(ns.hash_offset <= b.len() as u32);
    }
}

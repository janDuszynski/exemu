#![allow(clippy::identity_op)]

pub const API_SET_SCHEMA_VERSION: u32 = 6;

pub const HASH_FACTOR: u32 = 0x1F;

const HEADER_SIZE: u32 = 0x1C;
const ENTRY_SIZE: u32 = 0x18;
const VALUE_SIZE: u32 = 0x14;
const HASH_ENTRY_SIZE: u32 = 0x08;

#[inline]
fn lower(c: u16) -> u16 {
    if (0x41..=0x5A).contains(&c) { c + 0x20 } else { c }
}

fn hashable_prefix(name_utf16: &[u16]) -> &[u16] {
    let mut last_hyphen: Option<usize> = None;
    for (i, &c) in name_utf16.iter().enumerate() {
        if c == 0x2E {
            break;
        }
        if c == 0x2D {
            last_hyphen = Some(i);
        }
    }
    match last_hyphen {
        Some(i) => &name_utf16[..i],
        None => &name_utf16[..0],
    }
}

pub fn api_set_hash(name: &str, factor: u32) -> u32 {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut hash: u32 = 0;
    for &c in hashable_prefix(&units) {
        hash = hash.wrapping_mul(factor).wrapping_add(u32::from(lower(c)));
    }
    hash
}

struct BuiltEntry {
    name: Vec<u16>,
    name_bytes: u32,
    hashed_bytes: u32,
    hash: u32,
    value: Vec<u16>,
    value_bytes: u32,
}

pub struct ApiSetNamespace {
    pub bytes: Vec<u8>,
    pub count: u32,
    pub entry_offset: u32,
    pub hash_offset: u32,
}

pub fn build_populated_namespace() -> ApiSetNamespace {
    build_namespace(DEFAULT_CONTRACTS)
}

pub fn build_namespace(contracts: &[(&str, &str)]) -> ApiSetNamespace {
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

    let header_end = align8(HEADER_SIZE);
    let entry_offset = header_end;
    let value_offset_base = entry_offset + count * ENTRY_SIZE;
    let hash_offset = value_offset_base + count * VALUE_SIZE;
    let strings_base = hash_offset + count * HASH_ENTRY_SIZE;

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

    let mut bytes = vec![0u8; total as usize];

    put_u32(&mut bytes, 0x00, API_SET_SCHEMA_VERSION);
    put_u32(&mut bytes, 0x04, total);
    put_u32(&mut bytes, 0x08, 0);
    put_u32(&mut bytes, 0x0C, count);
    put_u32(&mut bytes, 0x10, entry_offset);
    put_u32(&mut bytes, 0x14, hash_offset);
    put_u32(&mut bytes, 0x18, HASH_FACTOR);

    for (i, e) in entries.iter().enumerate() {
        let eo = entry_offset + i as u32 * ENTRY_SIZE;
        let vo = value_offset_base + i as u32 * VALUE_SIZE;
        put_u32(&mut bytes, eo + 0x00, 0);
        put_u32(&mut bytes, eo + 0x04, name_offsets[i]);
        put_u32(&mut bytes, eo + 0x08, e.name_bytes);
        put_u32(&mut bytes, eo + 0x0C, e.hashed_bytes);
        put_u32(&mut bytes, eo + 0x10, vo);
        put_u32(&mut bytes, eo + 0x14, 1);

        put_u32(&mut bytes, vo + 0x00, 0);
        put_u32(&mut bytes, vo + 0x04, 0);
        put_u32(&mut bytes, vo + 0x08, 0);
        put_u32(&mut bytes, vo + 0x0C, value_offsets[i]);
        put_u32(&mut bytes, vo + 0x10, e.value_bytes);
    }

    let mut hash_index: Vec<(u32, u32)> =
        (0..entries.len()).map(|i| (entries[i].hash, i as u32)).collect();
    hash_index.sort_by_key(|&(h, _)| h);
    for w in hash_index.windows(2) {
        assert_ne!(
            w[0].0, w[1].0,
            "API-set hash collision ({:#x}); pick a distinct contract",
            w[0].0
        );
    }
    for (i, &(h, idx)) in hash_index.iter().enumerate() {
        let ho = hash_offset + i as u32 * HASH_ENTRY_SIZE;
        put_u32(&mut bytes, ho + 0x00, h);
        put_u32(&mut bytes, ho + 0x04, idx);
    }

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

const DEFAULT_CONTRACTS: &[(&str, &str)] = &[
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

    #[test]
    fn hashable_prefix_stops_at_last_hyphen() {
        let name = "api-ms-win-crt-runtime-l1-1-0";
        let units: Vec<u16> = name.encode_utf16().collect();
        let prefix = hashable_prefix(&units);
        assert_eq!(String::from_utf16(prefix).unwrap(), "api-ms-win-crt-runtime-l1-1");
    }

    #[test]
    fn hash_is_case_insensitive() {
        let a = api_set_hash("api-ms-win-core-synch-l1-2-0", HASH_FACTOR);
        let b = api_set_hash("API-MS-WIN-CORE-SYNCH-L1-2-0", HASH_FACTOR);
        assert_eq!(a, b);
    }

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

    #[test]
    fn known_contract_resolves_to_expected_host() {
        let ns = build_populated_namespace();
        let b = &ns.bytes;

        let resolve = |contract: &str| -> Option<String> {
            let h = api_set_hash(contract, HASH_FACTOR);
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
        assert_eq!(resolve("api-ms-win-core-nonexistent-l9-9-9"), None);
    }

    #[test]
    fn empty_namespace_is_valid() {
        let ns = build_namespace(&[]);
        let b = &ns.bytes;
        assert_eq!(read_u32(b, 0x00), 6);
        assert_eq!(read_u32(b, 0x0C), 0, "Count = 0");
        assert_eq!(read_u32(b, 0x04) as usize, b.len());
        assert!(ns.entry_offset <= b.len() as u32);
        assert!(ns.hash_offset <= b.len() as u32);
    }
}

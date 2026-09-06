const MAX_BLOCK: usize = 0x8000;

pub fn build_cab(name: &str, data: &[u8]) -> Vec<u8> {
    assert!(!name.is_empty(), "an archived name is required");
    assert!(name.is_ascii(), "the stored name must be ASCII (no _A_NAME_IS_UTF here)");
    assert!(!name.contains('\0'), "the stored name is NUL-terminated, so it cannot contain NUL");
    assert!(
        data.len() <= MAX_BLOCK,
        "this writer emits a single CFDATA block, so the payload is capped at {MAX_BLOCK} bytes"
    );

    let name_bytes = name.as_bytes();
    let coff_files = 36 + 8;
    let cffile_len = 16 + name_bytes.len() + 1;
    let coff_cab_start = coff_files + cffile_len;
    let total = coff_cab_start + 8 + data.len();

    let mut f = Vec::with_capacity(total);

    f.extend_from_slice(b"MSCF");
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&(total as u32).to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&(coff_files as u32).to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.push(3);
    f.push(1);
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&CAB_SET_ID.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    debug_assert_eq!(f.len(), 36);

    f.extend_from_slice(&(coff_cab_start as u32).to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    debug_assert_eq!(f.len(), coff_files);

    f.extend_from_slice(&(data.len() as u32).to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes());
    f.extend_from_slice(&CAB_DATE.to_le_bytes());
    f.extend_from_slice(&CAB_TIME.to_le_bytes());
    f.extend_from_slice(&0x20u16.to_le_bytes());
    f.extend_from_slice(name_bytes);
    f.push(0);
    debug_assert_eq!(f.len(), coff_cab_start);

    let len = data.len() as u16;
    let mut sizes = [0u8; 4];
    sizes[..2].copy_from_slice(&len.to_le_bytes());
    sizes[2..].copy_from_slice(&len.to_le_bytes());
    let csum = checksum(data, checksum(&sizes, 0));
    f.extend_from_slice(&csum.to_le_bytes());
    f.extend_from_slice(&len.to_le_bytes());
    f.extend_from_slice(&len.to_le_bytes());
    f.extend_from_slice(data);

    debug_assert_eq!(f.len(), total);
    f
}

pub const CAB_SET_ID: u16 = 0x6565;

pub const CAB_DATE: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1;

pub const CAB_TIME: u16 = 12 << 11;

fn checksum(buf: &[u8], seed: u32) -> u32 {
    let mut acc = seed;
    let mut chunks = buf.chunks_exact(4);
    for c in &mut chunks {
        acc ^= u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    let rest = chunks.remainder();
    let mut tail = 0u32;
    for (i, &b) in rest.iter().enumerate() {
        tail |= (b as u32) << (8 * (rest.len() - 1 - i));
    }
    acc ^ tail
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_folder_file_and_data_land_where_the_header_says() {
        let payload = b"exemu W6.5 cabinet payload";
        let cab = build_cab("hello.txt", payload);

        assert_eq!(&cab[0..4], b"MSCF", "signature");
        let cb_cabinet = u32::from_le_bytes(cab[8..12].try_into().unwrap()) as usize;
        assert_eq!(cb_cabinet, cab.len(), "cbCabinet is the real file size");
        let coff_files = u32::from_le_bytes(cab[16..20].try_into().unwrap()) as usize;
        assert_eq!(coff_files, 44, "CFFILE follows CFHEADER + one CFFOLDER");
        assert_eq!(cab[24], 3, "versionMinor");
        assert_eq!(cab[25], 1, "versionMajor");
        assert_eq!(u16::from_le_bytes(cab[26..28].try_into().unwrap()), 1, "cFolders");
        assert_eq!(u16::from_le_bytes(cab[28..30].try_into().unwrap()), 1, "cFiles");
        assert_eq!(u16::from_le_bytes(cab[30..32].try_into().unwrap()), 0, "no flags");

        let coff_cab_start = u32::from_le_bytes(cab[36..40].try_into().unwrap()) as usize;
        assert_eq!(u16::from_le_bytes(cab[40..42].try_into().unwrap()), 1, "cCFData");
        assert_eq!(u16::from_le_bytes(cab[42..44].try_into().unwrap()), 0, "tcompTYPE_NONE");

        assert_eq!(
            u32::from_le_bytes(cab[44..48].try_into().unwrap()) as usize,
            payload.len(),
            "cbFile"
        );
        assert_eq!(u32::from_le_bytes(cab[48..52].try_into().unwrap()), 0, "uoffFolderStart");
        assert_eq!(u16::from_le_bytes(cab[52..54].try_into().unwrap()), 0, "iFolder");
        assert_eq!(&cab[60..70], b"hello.txt\0", "the NUL-terminated archived name");
        assert_eq!(coff_cab_start, 70, "coffCabStart follows the CFFILE");

        let n = u16::from_le_bytes(cab[74..76].try_into().unwrap()) as usize;
        assert_eq!(n, payload.len(), "cbData");
        assert_eq!(u16::from_le_bytes(cab[76..78].try_into().unwrap()) as usize, n, "cbUncomp");
        assert_eq!(&cab[78..78 + n], payload, "stored data is the payload verbatim");
    }

    #[test]
    fn cfdata_checksum_matches_an_independent_recomputation() {
        let payload = b"7 bytes";
        let cab = build_cab("odd.bin", payload);
        let stored = u32::from_le_bytes(cab[68..72].try_into().unwrap());

        let mut seed = 0u32;
        let sizes = [7u8, 0, 7, 0];
        seed ^= u32::from_le_bytes(sizes);
        let mut acc = seed;
        acc ^= u32::from_le_bytes([b'7', b' ', b'b', b'y']);
        acc ^= (b't' as u32) << 16 | (b'e' as u32) << 8 | (b's' as u32);

        assert_eq!(stored, acc, "the CFDATA checksum");
        assert_ne!(stored, 0, "a zeroed checksum would not exercise a validating reader");
    }

    #[test]
    fn checksum_handles_an_aligned_payload() {
        assert_eq!(checksum(&[1, 0, 0, 0, 2, 0, 0, 0], 0), 3);
        assert_eq!(checksum(&[], 0x1234), 0x1234, "an empty buffer is the seed");
    }

    #[test]
    fn generation_is_deterministic() {
        assert_eq!(build_cab("a.txt", b"abc"), build_cab("a.txt", b"abc"));
        assert_ne!(build_cab("a.txt", b"abc"), build_cab("b.txt", b"abc"));
        assert_ne!(build_cab("a.txt", b"abc"), build_cab("a.txt", b"abd"));
    }
}

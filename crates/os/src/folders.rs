pub mod csidl {
    pub const DESKTOP: u32 = 0x00;
    pub const PROGRAMS: u32 = 0x02;
    pub const PERSONAL: u32 = 0x05;
    pub const FAVORITES: u32 = 0x06;
    pub const STARTUP: u32 = 0x07;
    pub const RECENT: u32 = 0x08;
    pub const SENDTO: u32 = 0x09;
    pub const STARTMENU: u32 = 0x0b;
    pub const MYMUSIC: u32 = 0x0d;
    pub const MYVIDEO: u32 = 0x0e;
    pub const DESKTOPDIRECTORY: u32 = 0x10;
    pub const TEMPLATES: u32 = 0x15;
    pub const COMMON_STARTMENU: u32 = 0x16;
    pub const COMMON_PROGRAMS: u32 = 0x17;
    pub const COMMON_STARTUP: u32 = 0x18;
    pub const COMMON_DESKTOPDIRECTORY: u32 = 0x19;
    pub const APPDATA: u32 = 0x1a;
    pub const PRINTHOOD: u32 = 0x1b;
    pub const LOCAL_APPDATA: u32 = 0x1c;
    pub const COMMON_FAVORITES: u32 = 0x1f;
    pub const INTERNET_CACHE: u32 = 0x20;
    pub const COOKIES: u32 = 0x21;
    pub const HISTORY: u32 = 0x22;
    pub const COMMON_APPDATA: u32 = 0x23;
    pub const WINDOWS: u32 = 0x24;
    pub const SYSTEM: u32 = 0x25;
    pub const PROGRAM_FILES: u32 = 0x26;
    pub const MYPICTURES: u32 = 0x27;
    pub const PROFILE: u32 = 0x28;
    pub const PROGRAM_FILES_COMMON: u32 = 0x2b;
    pub const COMMON_TEMPLATES: u32 = 0x2d;
    pub const COMMON_DOCUMENTS: u32 = 0x2e;
    pub const COMMON_ADMINTOOLS: u32 = 0x2f;
    pub const ADMINTOOLS: u32 = 0x30;
    pub const COMMON_MUSIC: u32 = 0x35;
    pub const COMMON_PICTURES: u32 = 0x36;
    pub const COMMON_VIDEO: u32 = 0x37;
    pub const RESOURCES: u32 = 0x38;
    pub const CDBURN_AREA: u32 = 0x3b;
    pub const PROGRAM_FILESX86: u32 = 0x2a;
    pub const PROGRAM_FILES_COMMONX86: u32 = 0x2c;

    pub const FLAG_CREATE: u32 = 0x8000;
    pub const FLAG_DONT_VERIFY: u32 = 0x4000;
    pub const FLAG_MASK: u32 = 0xFF00;
}

const USER: &str = "C:\\Users\\exemu";

pub fn csidl_path(csidl: u32) -> Option<&'static str> {
    use csidl::*;
    Some(match csidl & !FLAG_MASK {
        DESKTOP | DESKTOPDIRECTORY => concat!("C:\\Users\\exemu", "\\Desktop"),
        PERSONAL => concat!("C:\\Users\\exemu", "\\Documents"),
        MYPICTURES => concat!("C:\\Users\\exemu", "\\Pictures"),
        MYMUSIC => concat!("C:\\Users\\exemu", "\\Music"),
        MYVIDEO => concat!("C:\\Users\\exemu", "\\Videos"),
        FAVORITES => concat!("C:\\Users\\exemu", "\\Favorites"),
        RECENT => concat!("C:\\Users\\exemu", "\\AppData\\Roaming\\Microsoft\\Windows\\Recent"),
        SENDTO => concat!("C:\\Users\\exemu", "\\AppData\\Roaming\\Microsoft\\Windows\\SendTo"),
        PRINTHOOD => concat!("C:\\Users\\exemu", "\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts"),
        TEMPLATES => concat!("C:\\Users\\exemu", "\\AppData\\Roaming\\Microsoft\\Windows\\Templates"),
        STARTMENU => concat!("C:\\Users\\exemu", "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"),
        PROGRAMS => concat!("C:\\Users\\exemu", "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs"),
        STARTUP => {
            concat!("C:\\Users\\exemu", "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        }
        ADMINTOOLS => concat!(
            "C:\\Users\\exemu",
            "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"
        ),
        INTERNET_CACHE => {
            concat!("C:\\Users\\exemu", "\\AppData\\Local\\Microsoft\\Windows\\INetCache")
        }
        COOKIES => concat!("C:\\Users\\exemu", "\\AppData\\Local\\Microsoft\\Windows\\INetCookies"),
        HISTORY => concat!("C:\\Users\\exemu", "\\AppData\\Local\\Microsoft\\Windows\\History"),
        CDBURN_AREA => concat!("C:\\Users\\exemu", "\\AppData\\Local\\Microsoft\\Windows\\Burn\\Burn"),
        APPDATA => concat!("C:\\Users\\exemu", "\\AppData\\Roaming"),
        LOCAL_APPDATA => concat!("C:\\Users\\exemu", "\\AppData\\Local"),
        PROFILE => USER,

        COMMON_APPDATA => "C:\\ProgramData",
        COMMON_STARTMENU => "C:\\ProgramData\\Microsoft\\Windows\\Start Menu",
        COMMON_PROGRAMS => "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs",
        COMMON_STARTUP => "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        COMMON_ADMINTOOLS => "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
        COMMON_TEMPLATES => "C:\\ProgramData\\Microsoft\\Windows\\Templates",
        COMMON_DESKTOPDIRECTORY => "C:\\Users\\Public\\Desktop",
        COMMON_DOCUMENTS => "C:\\Users\\Public\\Documents",
        COMMON_MUSIC => "C:\\Users\\Public\\Music",
        COMMON_PICTURES => "C:\\Users\\Public\\Pictures",
        COMMON_VIDEO => "C:\\Users\\Public\\Videos",
        COMMON_FAVORITES => "C:\\Users\\Public\\Favorites",

        WINDOWS => "C:\\Windows",
        SYSTEM => "C:\\Windows\\system32",
        RESOURCES => "C:\\Windows\\Resources",
        PROGRAM_FILES => "C:\\Program Files",
        PROGRAM_FILES_COMMON => "C:\\Program Files\\Common Files",
        PROGRAM_FILESX86 => "C:\\Program Files (x86)",
        PROGRAM_FILES_COMMONX86 => "C:\\Program Files (x86)\\Common Files",
        _ => return None,
    })
}

pub fn all_guest_dirs() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    for csidl in 0u32..=0x40 {
        if let Some(p) = csidl_path(csidl) {
            if !v.contains(&p) {
                v.push(p);
            }
        }
    }
    let downloads = concat!("C:\\Users\\exemu", "\\Downloads");
    if !v.contains(&downloads) {
        v.push(downloads);
    }
    v
}

pub type KnownFolderId = [u8; 16];

const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> KnownFolderId {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7],
    ]
}

const KNOWN_FOLDERS: &[(KnownFolderId, u32)] = &[
    (
        guid(0x3EB685DB, 0x65F9, 0x4CF6, [0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D]),
        csidl::APPDATA,
    ),
    (
        guid(0xF1B32785, 0x6FBA, 0x4FCF, [0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91]),
        csidl::LOCAL_APPDATA,
    ),
    (
        guid(0x62AB5D82, 0xFDC1, 0x4DC3, [0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97]),
        csidl::COMMON_APPDATA,
    ),
    (
        guid(0xFDD39AD0, 0x238F, 0x46AF, [0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7]),
        csidl::PERSONAL,
    ),
    (
        guid(0xB4BFCC3A, 0xDB2C, 0x424C, [0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41]),
        csidl::DESKTOP,
    ),
    (
        guid(0x374DE290, 0x123F, 0x4565, [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B]),
        u32::MAX,
    ),
    (
        guid(0x33E28130, 0x4E1E, 0x4676, [0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB]),
        csidl::MYPICTURES,
    ),
    (
        guid(0x4BD8D571, 0x6D19, 0x48D3, [0xBE, 0x97, 0x42, 0x22, 0x20, 0x08, 0x0E, 0x43]),
        csidl::MYMUSIC,
    ),
    (
        guid(0x18989B1D, 0x99B5, 0x455B, [0x84, 0x1C, 0xAB, 0x7C, 0x74, 0xE4, 0xDD, 0xFC]),
        csidl::MYVIDEO,
    ),
    (
        guid(0x5E6C858F, 0x0E22, 0x4760, [0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73]),
        csidl::PROFILE,
    ),
    (
        guid(0xF38BF404, 0x1D43, 0x42F2, [0x93, 0x05, 0x67, 0xDE, 0x0B, 0x28, 0xFC, 0x23]),
        csidl::WINDOWS,
    ),
    (
        guid(0x1AC14E77, 0x02E7, 0x4E5D, [0xB7, 0x44, 0x2E, 0xB1, 0xAE, 0x51, 0x98, 0xB7]),
        csidl::SYSTEM,
    ),
    (
        guid(0x905E63B6, 0xC1BF, 0x494E, [0xB2, 0x9C, 0x65, 0xB7, 0x32, 0xD3, 0xD2, 0x1A]),
        csidl::PROGRAM_FILES,
    ),
    (
        guid(0x7C5A40EF, 0xA0FB, 0x4BFC, [0x87, 0x4A, 0xC0, 0xF2, 0xE0, 0xB9, 0xFA, 0x8E]),
        csidl::PROGRAM_FILESX86,
    ),
    (
        guid(0x625B53C3, 0xAB48, 0x4EC1, [0xBA, 0x1F, 0xA1, 0xEF, 0x41, 0x46, 0xFC, 0x19]),
        csidl::STARTMENU,
    ),
    (
        guid(0xA77F5D77, 0x2E2B, 0x44C3, [0xA6, 0xA2, 0xAB, 0xA6, 0x01, 0x05, 0x4A, 0x51]),
        csidl::PROGRAMS,
    ),
    (
        guid(0xA4115719, 0xD62E, 0x491D, [0xAA, 0x7C, 0xE7, 0x4B, 0x8B, 0xE3, 0xB0, 0x67]),
        csidl::COMMON_STARTMENU,
    ),
    (
        guid(0x0139D44E, 0x6AFE, 0x49F2, [0x86, 0x90, 0x3D, 0xAF, 0xCA, 0xE6, 0xFF, 0xB8]),
        csidl::COMMON_PROGRAMS,
    ),
    (
        guid(0xC4AA340D, 0xF20F, 0x4863, [0xAF, 0xEF, 0xF8, 0x7E, 0xF2, 0xE6, 0xBA, 0x25]),
        csidl::COMMON_DESKTOPDIRECTORY,
    ),
    (
        guid(0xED4824AF, 0xDCE4, 0x45A8, [0x81, 0xE2, 0xFC, 0x79, 0x65, 0x08, 0x36, 0x34]),
        csidl::COMMON_DOCUMENTS,
    ),
];

pub fn known_folder_path(rfid: &KnownFolderId) -> Option<&'static str> {
    let csidl = KNOWN_FOLDERS.iter().find(|(g, _)| g == rfid).map(|(_, c)| *c)?;
    if csidl == u32::MAX {
        return Some(concat!("C:\\Users\\exemu", "\\Downloads"));
    }
    csidl_path(csidl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_folder_is_a_guest_path_under_c_drive() {
        let mut n = 0;
        for csidl in 0u32..=0x40 {
            if let Some(p) = csidl_path(csidl) {
                assert!(p.starts_with("C:\\"), "CSIDL {csidl:#x} -> {p:?} is not under C:\\");
                assert!(!p.contains('/'), "CSIDL {csidl:#x} -> {p:?} looks like a host path");
                assert!(!p.starts_with("\\\\"), "CSIDL {csidl:#x} -> {p:?} is a UNC path");
                n += 1;
            }
        }
        assert!(n >= 30, "expected a useful table, got {n} entries");

        for (g, _) in KNOWN_FOLDERS {
            let p = known_folder_path(g).expect("every listed KNOWNFOLDERID resolves");
            assert!(p.starts_with("C:\\"), "{g:?} -> {p:?} is not under C:\\");
            assert!(!p.contains('/'), "{g:?} -> {p:?} looks like a host path");
        }
    }

    #[test]
    fn csidl_agrees_with_the_environment_block() {
        let env = crate::default_environment();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();

        assert_eq!(csidl_path(csidl::APPDATA).unwrap(), get("APPDATA"));
        assert_eq!(csidl_path(csidl::LOCAL_APPDATA).unwrap(), get("LOCALAPPDATA"));
        assert_eq!(csidl_path(csidl::COMMON_APPDATA).unwrap(), get("ProgramData"));
        assert_eq!(csidl_path(csidl::PROFILE).unwrap(), get("USERPROFILE"));
        assert_eq!(csidl_path(csidl::PROGRAM_FILES).unwrap(), get("ProgramFiles"));
        assert_eq!(csidl_path(csidl::PROGRAM_FILESX86).unwrap(), get("ProgramFiles(x86)"));
        assert_eq!(csidl_path(csidl::PROGRAM_FILES_COMMON).unwrap(), get("CommonProgramFiles"));
        assert_eq!(csidl_path(csidl::WINDOWS).unwrap(), get("windir"));
        assert!(csidl_path(csidl::SYSTEM).unwrap().starts_with(&get("windir")));
    }

    #[test]
    fn flag_bits_are_masked_before_lookup() {
        let plain = csidl_path(csidl::APPDATA).unwrap();
        assert_eq!(csidl_path(csidl::APPDATA | csidl::FLAG_CREATE).unwrap(), plain);
        assert_eq!(csidl_path(csidl::APPDATA | csidl::FLAG_DONT_VERIFY).unwrap(), plain);
        assert_eq!(
            csidl_path(csidl::APPDATA | csidl::FLAG_CREATE | csidl::FLAG_DONT_VERIFY).unwrap(),
            plain
        );
    }

    #[test]
    fn unmodelled_csidl_is_none() {
        assert_eq!(csidl_path(0x3f), None, "CSIDL_COMPUTERSNEARME is not modelled");
        assert_eq!(csidl_path(0xfe), None);
        assert_eq!(csidl_path(csidl::FLAG_CREATE | 0xfe), None);
    }

    #[test]
    fn known_folder_guid_byte_order() {
        let roaming = guid(0x3EB685DB, 0x65F9, 0x4CF6, [0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D]);
        assert_eq!(
            roaming,
            [0xDB, 0x85, 0xB6, 0x3E, 0xF9, 0x65, 0xF6, 0x4C, 0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D]
        );
        assert_eq!(known_folder_path(&roaming).unwrap(), "C:\\Users\\exemu\\AppData\\Roaming");

        assert_eq!(known_folder_path(&[0u8; 16]), None);
    }

    #[test]
    fn known_folder_ids_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for (g, _) in KNOWN_FOLDERS {
            assert!(seen.insert(*g), "duplicate KNOWNFOLDERID in the table: {g:?}");
        }
        assert_eq!(seen.len(), KNOWN_FOLDERS.len());
    }

    #[test]
    fn start_menu_chain_nests() {
        let sm = csidl_path(csidl::STARTMENU).unwrap();
        let pr = csidl_path(csidl::PROGRAMS).unwrap();
        let su = csidl_path(csidl::STARTUP).unwrap();
        assert!(pr.starts_with(sm), "{pr} is not under {sm}");
        assert!(su.starts_with(pr), "{su} is not under {pr}");

        let csm = csidl_path(csidl::COMMON_STARTMENU).unwrap();
        let cpr = csidl_path(csidl::COMMON_PROGRAMS).unwrap();
        assert!(cpr.starts_with(csm), "{cpr} is not under {csm}");
    }
}

//! Known folders — `CSIDL_*` and `FOLDERID_*` → guest Windows paths (roadmap W6.6).
//!
//! Wine's `shell32.dll` runs as guest code and answers `SHGetFolderPathW` /
//! `SHGetKnownFolderPath` itself; what it needs from exemu is a coherent set of
//! *guest* paths. This module is that table.
//!
//! # The security property, and why it is structural rather than enforced
//!
//! Every entry here is a **guest Windows path under `C:\`** — never a host path.
//! Guest paths reach the host only through [`crate::WinOs::host_path`], which
//! roots everything at the sandbox directory and drops `..` components, so a
//! guest asking for `CSIDL_PERSONAL` receives `C:\Users\exemu\Documents` and
//! lands in `$TMPDIR/exemu-sandbox/C/Users/exemu/Documents`. It cannot reach the
//! real `~/Documents`, and that is true **by construction**: there is no host
//! path in this file to get wrong, and no separate check to forget.
//!
//! This is the deliberate choice. Mapping a few folders to real macOS
//! equivalents (`~/Documents`, `~/Downloads`) would be friendlier — a guest that
//! saves a file would put it where the user expects — but it would hand an
//! arbitrary Windows binary a writable handle on the user's real documents
//! merely because it asked. Until there is an explicit, user-visible consent
//! mechanism (roadmap W9.5 covers the security model), everything stays in the
//! sandbox. If that changes, it should change *here*, deliberately, and only for
//! folders the user has opted into — not as a side effect of some other change.
//!
//! # Consistency with the environment block
//!
//! The paths agree with [`crate::default_environment`] (`USERPROFILE`,
//! `APPDATA`, `LOCALAPPDATA`, `ProgramData`, `ProgramFiles`, `windir`). A guest
//! that compares `%APPDATA%` against `SHGetFolderPath(CSIDL_APPDATA)` — installers
//! do this — must see the same string, so the two tables are pinned equal by a
//! test below.

/// `CSIDL_*` values (shlobj.h). Only the ones a real installer asks for.
/// The high bits `CSIDL_FLAG_CREATE` (0x8000) and `CSIDL_FLAG_DONT_VERIFY`
/// (0x4000) are masked off by [`csidl_path`] before lookup.
pub mod csidl {
    /// `C:\Users\exemu\Desktop`
    pub const DESKTOP: u32 = 0x00;
    /// Start-menu `Programs` — the 7-Zip installer's shortcut target.
    pub const PROGRAMS: u32 = 0x02;
    /// `CSIDL_PERSONAL` — "My Documents".
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
    /// All-users start menu.
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
    /// `CSIDL_COMMON_APPDATA` — `C:\ProgramData`.
    pub const COMMON_APPDATA: u32 = 0x23;
    /// `C:\Windows`
    pub const WINDOWS: u32 = 0x24;
    /// `C:\Windows\system32`
    pub const SYSTEM: u32 = 0x25;
    /// `C:\Program Files`
    pub const PROGRAM_FILES: u32 = 0x26;
    pub const MYPICTURES: u32 = 0x27;
    pub const PROFILE: u32 = 0x28;
    /// `C:\Program Files\Common Files`
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
    /// `CSIDL_PROGRAM_FILESX86`
    pub const PROGRAM_FILESX86: u32 = 0x2a;
    /// `CSIDL_PROGRAM_FILES_COMMONX86`
    pub const PROGRAM_FILES_COMMONX86: u32 = 0x2c;

    /// `CSIDL_FLAG_CREATE` — caller wants the folder created if absent.
    pub const FLAG_CREATE: u32 = 0x8000;
    /// `CSIDL_FLAG_DONT_VERIFY` — return the path without checking existence.
    pub const FLAG_DONT_VERIFY: u32 = 0x4000;
    /// Every documented flag bit, masked off before the table lookup.
    pub const FLAG_MASK: u32 = 0xFF00;
}

const USER: &str = "C:\\Users\\exemu";

/// The guest path for a `CSIDL_*` value, or `None` if it is one exemu does not
/// model. Flag bits (`CSIDL_FLAG_CREATE` etc.) are masked off first, so
/// `CSIDL_APPDATA | CSIDL_FLAG_CREATE` resolves like plain `CSIDL_APPDATA` —
/// real installers almost always pass the create flag.
///
/// Creating the directory is deliberately **not** done here: this is a pure
/// lookup, and the caller decides whether the request was a create request.
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

/// Every distinct guest path this module models, for a caller that wants to
/// *materialise* the profile tree rather than merely name it.
///
/// A real Wine prefix is **created** with these directories present (that is
/// what `wineboot` does on first run); exemu boots Wine's DLLs against a
/// sandbox that has only `C:\windows\system32`. Shell code distinguishes
/// "folder exists" from "folder is merely nameable" — `SHGetFolderPath` without
/// `CSIDL_FLAG_CREATE` reports failure for an absent directory even while
/// filling in the path — so the tree has to actually exist.
///
/// Order is unspecified; callers should create parents as needed (each path is
/// absolute, so a recursive create handles nesting without sorting).
pub fn all_guest_dirs() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    for csidl in 0u32..=0x40 {
        if let Some(p) = csidl_path(csidl) {
            if !v.contains(&p) {
                v.push(p);
            }
        }
    }
    // `Downloads` has no CSIDL but is part of a modern profile.
    let downloads = concat!("C:\\Users\\exemu", "\\Downloads");
    if !v.contains(&downloads) {
        v.push(downloads);
    }
    v
}

/// A `KNOWNFOLDERID` GUID in its in-memory little-endian layout: `{u32, u16,
/// u16, [u8; 8]}` — i.e. exactly the 16 bytes a guest passes by pointer.
pub type KnownFolderId = [u8; 16];

/// Build a `KNOWNFOLDERID` from its canonical textual fields, in the byte order
/// a guest actually passes (Data1/2/3 little-endian, Data4 big-endian).
const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> KnownFolderId {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7],
    ]
}

/// `FOLDERID_*` → the `CSIDL_*` that names the same directory. Modern shell code
/// (`SHGetKnownFolderPath`) uses these GUIDs; routing them through the CSIDL
/// table keeps exactly one source of truth for the paths themselves.
const KNOWN_FOLDERS: &[(KnownFolderId, u32)] = &[
    // FOLDERID_RoamingAppData {3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}
    (
        guid(0x3EB685DB, 0x65F9, 0x4CF6, [0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D]),
        csidl::APPDATA,
    ),
    // FOLDERID_LocalAppData {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
    (
        guid(0xF1B32785, 0x6FBA, 0x4FCF, [0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91]),
        csidl::LOCAL_APPDATA,
    ),
    // FOLDERID_ProgramData {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}
    (
        guid(0x62AB5D82, 0xFDC1, 0x4DC3, [0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97]),
        csidl::COMMON_APPDATA,
    ),
    // FOLDERID_Documents {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
    (
        guid(0xFDD39AD0, 0x238F, 0x46AF, [0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7]),
        csidl::PERSONAL,
    ),
    // FOLDERID_Desktop {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
    (
        guid(0xB4BFCC3A, 0xDB2C, 0x424C, [0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41]),
        csidl::DESKTOP,
    ),
    // FOLDERID_Downloads {374DE290-123F-4565-9164-39C4925E467B}
    (
        guid(0x374DE290, 0x123F, 0x4565, [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B]),
        // No CSIDL equivalent; Downloads is modelled under the profile below.
        u32::MAX,
    ),
    // FOLDERID_Pictures {33E28130-4E1E-4676-835A-98395C3BC3BB}
    (
        guid(0x33E28130, 0x4E1E, 0x4676, [0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB]),
        csidl::MYPICTURES,
    ),
    // FOLDERID_Music {4BD8D571-6D19-48D3-BE97-422220080E43}
    (
        guid(0x4BD8D571, 0x6D19, 0x48D3, [0xBE, 0x97, 0x42, 0x22, 0x20, 0x08, 0x0E, 0x43]),
        csidl::MYMUSIC,
    ),
    // FOLDERID_Videos {18989B1D-99B5-455B-841C-AB7C74E4DDFC}
    (
        guid(0x18989B1D, 0x99B5, 0x455B, [0x84, 0x1C, 0xAB, 0x7C, 0x74, 0xE4, 0xDD, 0xFC]),
        csidl::MYVIDEO,
    ),
    // FOLDERID_Profile {5E6C858F-0E22-4760-9AFE-EA3317B67173}
    (
        guid(0x5E6C858F, 0x0E22, 0x4760, [0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73]),
        csidl::PROFILE,
    ),
    // FOLDERID_Windows {F38BF404-1D43-42F2-9305-67DE0B28FC23}
    (
        guid(0xF38BF404, 0x1D43, 0x42F2, [0x93, 0x05, 0x67, 0xDE, 0x0B, 0x28, 0xFC, 0x23]),
        csidl::WINDOWS,
    ),
    // FOLDERID_System {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}
    (
        guid(0x1AC14E77, 0x02E7, 0x4E5D, [0xB7, 0x44, 0x2E, 0xB1, 0xAE, 0x51, 0x98, 0xB7]),
        csidl::SYSTEM,
    ),
    // FOLDERID_ProgramFiles {905e63b6-c1bf-494e-b29c-65b732d3d21a}
    (
        guid(0x905E63B6, 0xC1BF, 0x494E, [0xB2, 0x9C, 0x65, 0xB7, 0x32, 0xD3, 0xD2, 0x1A]),
        csidl::PROGRAM_FILES,
    ),
    // FOLDERID_ProgramFilesX86 {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}
    (
        guid(0x7C5A40EF, 0xA0FB, 0x4BFC, [0x87, 0x4A, 0xC0, 0xF2, 0xE0, 0xB9, 0xFA, 0x8E]),
        csidl::PROGRAM_FILESX86,
    ),
    // FOLDERID_StartMenu {625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}
    (
        guid(0x625B53C3, 0xAB48, 0x4EC1, [0xBA, 0x1F, 0xA1, 0xEF, 0x41, 0x46, 0xFC, 0x19]),
        csidl::STARTMENU,
    ),
    // FOLDERID_Programs {A77F5D77-2E2B-44C3-A6A2-ABA601054A51}
    (
        guid(0xA77F5D77, 0x2E2B, 0x44C3, [0xA6, 0xA2, 0xAB, 0xA6, 0x01, 0x05, 0x4A, 0x51]),
        csidl::PROGRAMS,
    ),
    // FOLDERID_CommonStartMenu {A4115719-D62E-491D-AA7C-E74B8BE3B067}
    (
        guid(0xA4115719, 0xD62E, 0x491D, [0xAA, 0x7C, 0xE7, 0x4B, 0x8B, 0xE3, 0xB0, 0x67]),
        csidl::COMMON_STARTMENU,
    ),
    // FOLDERID_CommonPrograms {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}
    (
        guid(0x0139D44E, 0x6AFE, 0x49F2, [0x86, 0x90, 0x3D, 0xAF, 0xCA, 0xE6, 0xFF, 0xB8]),
        csidl::COMMON_PROGRAMS,
    ),
    // FOLDERID_PublicDesktop {C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}
    (
        guid(0xC4AA340D, 0xF20F, 0x4863, [0xAF, 0xEF, 0xF8, 0x7E, 0xF2, 0xE6, 0xBA, 0x25]),
        csidl::COMMON_DESKTOPDIRECTORY,
    ),
    // FOLDERID_PublicDocuments {ED4824AF-DCE4-45A8-81E2-FC7965083634}
    (
        guid(0xED4824AF, 0xDCE4, 0x45A8, [0x81, 0xE2, 0xFC, 0x79, 0x65, 0x08, 0x36, 0x34]),
        csidl::COMMON_DOCUMENTS,
    ),
];

/// The guest path for a `KNOWNFOLDERID`, or `None` if it is one exemu does not
/// model. `rfid` is the raw 16 bytes the guest passed by pointer.
pub fn known_folder_path(rfid: &KnownFolderId) -> Option<&'static str> {
    let csidl = KNOWN_FOLDERS.iter().find(|(g, _)| g == rfid).map(|(_, c)| *c)?;
    if csidl == u32::MAX {
        // Downloads has no CSIDL; it lives under the profile like the rest.
        return Some(concat!("C:\\Users\\exemu", "\\Downloads"));
    }
    csidl_path(csidl)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The security property.** Every path this module can return is a guest
    /// path anchored at `C:\`, so it can only ever resolve inside the sandbox.
    /// A future edit that returns a host path (`/Users/...`), a UNC path, or a
    /// different drive fails here — which is the point: the containment is a
    /// property of the table, not of a check someone has to remember to run.
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

    /// Installers routinely compare `%APPDATA%` with
    /// `SHGetFolderPath(CSIDL_APPDATA)` and take a different path if they differ,
    /// so the two tables must agree exactly.
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
        // `windir` is spelled `C:\Windows`; SYSTEM is its `system32` child.
        assert_eq!(csidl_path(csidl::WINDOWS).unwrap(), get("windir"));
        assert!(csidl_path(csidl::SYSTEM).unwrap().starts_with(&get("windir")));
    }

    /// Real callers pass `CSIDL_FLAG_CREATE`; the flag bits must not change which
    /// folder is named.
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

    /// A CSIDL exemu does not model is `None`, not a wrong path — a caller that
    /// gets a plausible-but-wrong directory writes files into it.
    #[test]
    fn unmodelled_csidl_is_none() {
        assert_eq!(csidl_path(0x3f), None, "CSIDL_COMPUTERSNEARME is not modelled");
        assert_eq!(csidl_path(0xfe), None);
        // And the flag bits alone are not a folder.
        assert_eq!(csidl_path(csidl::FLAG_CREATE | 0xfe), None);
    }

    /// The GUID byte order is the one a guest actually passes: Data1/2/3
    /// little-endian, Data4 in declaration order. Pinned against
    /// `FOLDERID_RoamingAppData` {3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}, whose
    /// byte layout is well known — a byte-order slip here would silently make
    /// every lookup miss.
    #[test]
    fn known_folder_guid_byte_order() {
        let roaming = guid(0x3EB685DB, 0x65F9, 0x4CF6, [0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D]);
        assert_eq!(
            roaming,
            [0xDB, 0x85, 0xB6, 0x3E, 0xF9, 0x65, 0xF6, 0x4C, 0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D]
        );
        assert_eq!(known_folder_path(&roaming).unwrap(), "C:\\Users\\exemu\\AppData\\Roaming");

        // An unknown GUID is None, not a default.
        assert_eq!(known_folder_path(&[0u8; 16]), None);
    }

    /// Every `KNOWNFOLDERID` maps to a distinct GUID (a copy-paste slip in the
    /// table would shadow one folder with another).
    #[test]
    fn known_folder_ids_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for (g, _) in KNOWN_FOLDERS {
            assert!(seen.insert(*g), "duplicate KNOWNFOLDERID in the table: {g:?}");
        }
        assert_eq!(seen.len(), KNOWN_FOLDERS.len());
    }

    /// The start-menu chain the 7-Zip installer walks must nest correctly —
    /// `Programs` under `Start Menu`, `Startup` under `Programs` — or a shortcut
    /// lands somewhere the shell never looks.
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

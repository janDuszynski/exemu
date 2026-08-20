//! Access tokens — `NtOpenProcessToken` / `NtQueryInformationToken` (roadmap W6.6).
//!
//! # Why this exists
//!
//! Found by elimination while chasing a W6.6 symptom: under `--wine-boot`, Wine's
//! `shell32` resolves every known folder but returns `C:\users\AppData\Roaming` —
//! lowercase `users`, **empty user component** — where exemu's profile is
//! `C:\Users\exemu`. Four candidate causes were ruled out by experiment (see
//! `knowledge/known-issues.know`): the environment block is seeded *and* Wine
//! demonstrably copies it, the `Shell Folders` registry keys made no difference,
//! and the NT/Win32 per-user hive mismatch was a real bug but not this one.
//!
//! What remained is that a guest had **no way to learn who the user is**: exemu
//! implemented none of the token surface, so `GetUserNameW`, "am I an admin?"
//! checks, and Wine's own profile derivation all had nothing to read. That is
//! what this module supplies.
//!
//! # Scope
//!
//! exemu models a **single, fixed, non-elevated interactive user**. There is no
//! multi-user support, no impersonation, and no real security enforcement — the
//! sandbox is the containment boundary, not the token. These services exist so a
//! guest that *asks* gets a coherent, stable answer instead of a failure, which
//! is what unblocks real installers; they are deliberately not a security model.
//! Anything that would grant a guest more host access must be enforced at the
//! sandbox, never here.
//!
//! # SSDT indices
//!
//! Recovered from the pinned Wine 11.0 `ntdll.dll` by reading each export's
//! `mov r10,rcx; mov eax,N` stub — the same method used for every other `Nt*`
//! group in this crate, not guessed from public tables.

use exemu_core::{CpuState, Memory, Result};

use crate::WinOs;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// The caller's buffer was too small; `ReturnLength` carries the size needed.
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;

// SSDT indices (pinned guest `ntdll.dll` `mov eax,N`).
/// `NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle)`.
pub(crate) const SSDT_NT_OPEN_PROCESS_TOKEN: u32 = 0xb5;
/// `NtOpenProcessTokenEx(ProcessHandle, DesiredAccess, HandleAttributes, TokenHandle)`.
pub(crate) const SSDT_NT_OPEN_PROCESS_TOKEN_EX: u32 = 0x30;
/// `NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle)`.
pub(crate) const SSDT_NT_OPEN_THREAD_TOKEN: u32 = 0x24;
/// `NtOpenThreadTokenEx(ThreadHandle, DesiredAccess, OpenAsSelf, HandleAttributes, TokenHandle)`.
pub(crate) const SSDT_NT_OPEN_THREAD_TOKEN_EX: u32 = 0x2f;
/// `NtQueryInformationToken(TokenHandle, Class, Buffer, Length, ReturnLength)`.
pub(crate) const SSDT_NT_QUERY_INFORMATION_TOKEN: u32 = 0x21;

/// The pseudo-handle every `NtOpenProcessToken`/`NtOpenThreadToken` returns.
/// A single fixed value is correct for the single-user model and makes an
/// unrecognised handle trivially detectable. Chosen well clear of the file
/// arena's 0x1000 handle base and the std-stream sentinels (0x0C/0x10/0x14).
pub const TOKEN_PSEUDO_HANDLE: u64 = 0x0000_0000_0000_0100;

/// The **constant** token pseudo-handles a caller may use *without* opening
/// anything: `NtCurrentProcessToken()` = `(HANDLE)-4`,
/// `NtCurrentThreadToken()` = `(HANDLE)-5`,
/// `NtCurrentThreadEffectiveToken()` = `(HANDLE)-6` (public `winnt.h`).
///
/// exemu models one user and one token, so all three denote the same object as
/// [`TOKEN_PSEUDO_HANDLE`]. Accepting them is not cosmetic: **ntdll's own
/// `RtlFormatCurrentUserKeyPath` asks for `TokenUser` on `(HANDLE)-6`**, and
/// rejecting it makes `RtlOpenCurrentUser` fail — which silently costs the guest
/// the whole of `HKEY_CURRENT_USER`, because its caller then proceeds with an
/// uninitialised root handle. Found by the W7.2 audio work: Wine's `mmdevapi`
/// registers each endpoint's GUID under `HKCU`, and without it every
/// `IMMDevice::Activate` failed with `AUDCLNT_E_DEVICE_INVALIDATED`.
fn is_token_handle(handle: u64) -> bool {
    handle == TOKEN_PSEUDO_HANDLE
        || handle == (-4i64) as u64
        || handle == (-5i64) as u64
        || handle == (-6i64) as u64
}

// ---- TOKEN_INFORMATION_CLASS (winnt.h), the ones a guest actually asks for ---
const TOKEN_USER: u32 = 1;
const TOKEN_GROUPS: u32 = 2;
const TOKEN_PRIVILEGES: u32 = 3;
const TOKEN_OWNER: u32 = 4;
const TOKEN_PRIMARY_GROUP: u32 = 5;
const TOKEN_TYPE: u32 = 8;
const TOKEN_STATISTICS: u32 = 10;
const TOKEN_ELEVATION_TYPE: u32 = 18;
const TOKEN_ELEVATION: u32 = 20;
const TOKEN_INTEGRITY_LEVEL: u32 = 25;

/// `TokenPrimary` — this is a real process token, not an impersonation one.
const TOKEN_TYPE_PRIMARY: u32 = 1;
/// `TokenElevationTypeDefault` — UAC is not in play, so the token is neither
/// split-limited nor elevated. Reporting *Default* (rather than Full) is the
/// honest answer for a machine with no UAC, and is what stops an installer
/// deciding it must re-launch itself elevated.
const TOKEN_ELEVATION_TYPE_DEFAULT: u32 = 1;

/// `SECURITY_NT_AUTHORITY` = S-1-5.
const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// The interactive user's RID. 1000 is the first non-builtin account, which is
/// what a single-user desktop install produces.
const USER_RID: u32 = 1000;
/// The machine-identifier sub-authorities of the account domain. Fixed rather
/// than random so a guest that persists a SID (installers write them into
/// registry ACLs) still recognises it on the next run — the same reasoning that
/// makes the corpus pins reproducible.
const DOMAIN_SUB_AUTHORITIES: [u32; 3] = [0x21ab_cdef, 0x1234_5678, 0x0fed_cba9];

/// `S-1-5-32-545` — the built-in **Users** group. The primary group and the sole
/// group membership: notably **not** Administrators, so an installer that checks
/// for elevation gets a truthful "no".
const BUILTIN_USERS_RID: u32 = 545;
/// `SECURITY_BUILTIN_DOMAIN_RID` (32) — the first sub-authority of `S-1-5-32-*`.
const BUILTIN_DOMAIN_RID: u32 = 32;

/// `SECURITY_MANDATORY_MEDIUM_RID` — the integrity level of an ordinary,
/// non-elevated interactive process (`S-1-16-8192`).
const INTEGRITY_MEDIUM_RID: u32 = 0x2000;
/// `SECURITY_MANDATORY_LABEL_AUTHORITY` = S-1-16.
const LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];

/// Serialise a SID: `Revision(1) SubAuthorityCount IdentifierAuthority[6]
/// SubAuthority[count]` (little-endian sub-authorities), per the documented
/// on-the-wire layout.
fn sid_bytes(authority: [u8; 6], sub: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + sub.len() * 4);
    out.push(1); // Revision
    out.push(sub.len() as u8); // SubAuthorityCount
    out.extend_from_slice(&authority);
    for s in sub {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

/// The interactive user's SID, `S-1-5-21-<domain>-1000`.
pub fn user_sid() -> Vec<u8> {
    let mut sub = vec![21u32];
    sub.extend_from_slice(&DOMAIN_SUB_AUTHORITIES);
    sub.push(USER_RID);
    sid_bytes(NT_AUTHORITY, &sub)
}

/// The user's SID in the canonical `S-1-5-21-…-1000` text form. This is the
/// spelling a registry key under `ProfileList` is named with, so the seed and
/// anything a guest computes from the binary SID agree.
pub fn user_sid_string() -> String {
    let mut s = String::from("S-1-5-21");
    for d in DOMAIN_SUB_AUTHORITIES {
        s.push_str(&format!("-{d}"));
    }
    s.push_str(&format!("-{USER_RID}"));
    s
}

/// `S-1-5-32-545`, the built-in Users group.
fn users_group_sid() -> Vec<u8> {
    sid_bytes(NT_AUTHORITY, &[BUILTIN_DOMAIN_RID, BUILTIN_USERS_RID])
}

/// `S-1-16-8192`, medium integrity.
fn medium_integrity_sid() -> Vec<u8> {
    sid_bytes(LABEL_AUTHORITY, &[INTEGRITY_MEDIUM_RID])
}

/// `SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY`.
const SE_GROUP_ENABLED_DEFAULT_MANDATORY: u32 = 0x4 | 0x2 | 0x1;
/// `SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED`.
const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x20 | 0x40;

/// Build the reply for one `TOKEN_INFORMATION_CLASS`, laid out exactly as the
/// guest expects to read it back, at the address it will live at.
///
/// The variable-length classes embed a pointer to a SID that follows the fixed
/// header **in the same buffer**, so the reply must be built for a known base
/// address — hence `base`. Returns `None` for a class exemu does not model, so
/// the caller can answer `STATUS_INVALID_INFO_CLASS` rather than hand back a
/// plausible-looking zero-filled struct (a guest given a wrong-but-parseable
/// token makes a wrong security decision, which is worse than a clean failure).
fn token_info(class: u32, base: u64) -> Option<Vec<u8>> {
    // A SID_AND_ATTRIBUTES header is {PSID Sid; DWORD Attributes;} = 16 bytes on
    // x64 (4 bytes of tail padding). The SID itself is appended after the
    // header block and pointed at from it.
    let sid_and_attrs = |sid: Vec<u8>, attrs: u32| -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(base + 16).to_le_bytes()); // Sid → just past this struct
        out.extend_from_slice(&attrs.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // padding
        out.extend_from_slice(&sid);
        out
    };

    Some(match class {
        // TOKEN_USER { SID_AND_ATTRIBUTES User; }
        TOKEN_USER => sid_and_attrs(user_sid(), 0),
        // TOKEN_OWNER { PSID Owner; } / TOKEN_PRIMARY_GROUP { PSID PrimaryGroup; }
        TOKEN_OWNER => {
            let mut out = (base + 8).to_le_bytes().to_vec();
            out.extend_from_slice(&user_sid());
            out
        }
        TOKEN_PRIMARY_GROUP => {
            let mut out = (base + 8).to_le_bytes().to_vec();
            out.extend_from_slice(&users_group_sid());
            out
        }
        // TOKEN_GROUPS { DWORD GroupCount; SID_AND_ATTRIBUTES Groups[]; }
        // One membership: the built-in Users group. Deliberately NOT
        // Administrators — an installer asking "am I elevated?" gets a truthful no.
        TOKEN_GROUPS => {
            let sid = users_group_sid();
            let hdr = 8u64; // GroupCount + padding
            let sid_at = base + hdr + 16;
            let mut out = Vec::new();
            out.extend_from_slice(&1u32.to_le_bytes()); // GroupCount
            out.extend_from_slice(&0u32.to_le_bytes()); // padding
            out.extend_from_slice(&sid_at.to_le_bytes());
            out.extend_from_slice(&SE_GROUP_ENABLED_DEFAULT_MANDATORY.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // padding
            out.extend_from_slice(&sid);
            out
        }
        // TOKEN_PRIVILEGES { DWORD PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[]; }
        // No privileges held. A guest that needs one must be told it does not
        // have it rather than being handed a fabricated grant.
        TOKEN_PRIVILEGES => 0u32.to_le_bytes().to_vec(),
        // TOKEN_TYPE — a primary (process) token.
        TOKEN_TYPE => TOKEN_TYPE_PRIMARY.to_le_bytes().to_vec(),
        // TOKEN_ELEVATION { DWORD TokenIsElevated; } — not elevated.
        TOKEN_ELEVATION => 0u32.to_le_bytes().to_vec(),
        TOKEN_ELEVATION_TYPE => TOKEN_ELEVATION_TYPE_DEFAULT.to_le_bytes().to_vec(),
        // TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label; } — medium integrity.
        TOKEN_INTEGRITY_LEVEL => sid_and_attrs(medium_integrity_sid(), SE_GROUP_INTEGRITY_ENABLED),
        // TOKEN_STATISTICS — a fixed, self-consistent record. The LUIDs are
        // stable across the process, which is what a guest caching them expects.
        TOKEN_STATISTICS => {
            let mut out = Vec::new();
            out.extend_from_slice(&0x0001_0000u64.to_le_bytes()); // TokenId (LUID)
            out.extend_from_slice(&0x0002_0000u64.to_le_bytes()); // AuthenticationId
            out.extend_from_slice(&i64::MAX.to_le_bytes()); // ExpirationTime: never
            out.extend_from_slice(&TOKEN_TYPE_PRIMARY.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // ImpersonationLevel
            out.extend_from_slice(&0u32.to_le_bytes()); // DynamicCharged
            out.extend_from_slice(&0u32.to_le_bytes()); // DynamicAvailable
            out.extend_from_slice(&1u32.to_le_bytes()); // GroupCount
            out.extend_from_slice(&0u32.to_le_bytes()); // PrivilegeCount
            out.extend_from_slice(&0x0001_0000u64.to_le_bytes()); // ModifiedId (LUID)
            out
        }
        _ => return None,
    })
}

impl WinOs {
    /// `NtOpenProcessToken` / `NtOpenProcessTokenEx` / `NtOpenThreadToken[Ex]`.
    ///
    /// All four hand back the same fixed [`TOKEN_PSEUDO_HANDLE`]: exemu has one
    /// user and no impersonation, so a thread token and a process token are the
    /// same object. `DesiredAccess` is not enforced — see the module note; the
    /// sandbox is the containment boundary, not the token.
    ///
    /// `out_arg` is the argument index holding `PHANDLE`, which differs per
    /// entry point (3 for the plain forms, 3 or 4 for the `Ex` ones).
    fn nt_open_token(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, out_arg: usize) -> Result<u32> {
        let out = self.syscall_arg(cpu, mem, out_arg)?;
        if out == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        mem.write_u64(out, TOKEN_PSEUDO_HANDLE)?;
        Ok(STATUS_SUCCESS)
    }

    /// `NtQueryInformationToken(TokenHandle, Class, Buffer, Length, ReturnLength)`.
    ///
    /// Implements the documented two-call protocol: a caller may pass a short (or
    /// zero-length) buffer to learn the size, receiving `STATUS_BUFFER_TOO_SMALL`
    /// with `ReturnLength` set. Guests rely on this — they call once with 0 to
    /// size an allocation, then again for real.
    fn nt_query_information_token(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)? as u32;
        let buf = self.syscall_arg(cpu, mem, 2)?;
        let len = self.syscall_arg(cpu, mem, 3)? as usize;
        let ret_len = self.syscall_arg(cpu, mem, 4)?;

        if !is_token_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let Some(info) = token_info(class, buf) else {
            return Ok(STATUS_INVALID_INFO_CLASS);
        };

        // ReturnLength is written on the too-small path too — that is the whole
        // point of the sizing call.
        if ret_len != 0 {
            mem.write_u32(ret_len, info.len() as u32)?;
        }
        if len < info.len() {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        if buf == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        mem.write(buf, &info)?;
        Ok(STATUS_SUCCESS)
    }
}

// ---- SSDT thunks -----------------------------------------------------------

pub(crate) fn ssdt_nt_open_process_token(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_token(cpu, mem, 2) // (Process, Access, *Token)
}
pub(crate) fn ssdt_nt_open_process_token_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_token(cpu, mem, 3) // (Process, Access, Attrs, *Token)
}
pub(crate) fn ssdt_nt_open_thread_token(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_token(cpu, mem, 3) // (Thread, Access, OpenAsSelf, *Token)
}
pub(crate) fn ssdt_nt_open_thread_token_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_token(cpu, mem, 4) // (Thread, Access, OpenAsSelf, Attrs, *Token)
}
pub(crate) fn ssdt_nt_query_information_token(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_information_token(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SID layout is the documented on-the-wire one. Pinned against
    /// `S-1-5-32-545` (built-in Users), whose bytes are short enough to state in
    /// full — a byte-order or field-order slip makes every guest SID comparison
    /// silently fail rather than error.
    #[test]
    fn sid_serialisation_matches_the_documented_layout() {
        let sid = users_group_sid();
        assert_eq!(
            sid,
            vec![
                1, // Revision
                2, // SubAuthorityCount
                0, 0, 0, 0, 0, 5, // IdentifierAuthority = NT (big-endian, per spec)
                32, 0, 0, 0, // SubAuthority[0] = 32 (BUILTIN), little-endian
                33, 2, 0, 0, // SubAuthority[1] = 545
            ]
        );
        // Length is 8 + 4*count, the documented formula.
        assert_eq!(sid.len(), 8 + 4 * 2);
        assert_eq!(user_sid().len(), 8 + 4 * 5, "S-1-5-21-a-b-c-1000 has 5 sub-authorities");
    }

    /// The binary SID and its text spelling must describe the same principal —
    /// the `ProfileList` key is named with the text form while a guest compares
    /// the binary one, so a mismatch means the profile is never found.
    #[test]
    fn user_sid_text_and_binary_agree() {
        let text = user_sid_string();
        let bin = user_sid();
        let parts: Vec<u32> = text.trim_start_matches("S-1-5-").split('-').map(|p| p.parse().unwrap()).collect();
        assert_eq!(parts.len(), 5, "21 + 3 domain + RID");
        for (i, want) in parts.iter().enumerate() {
            let off = 8 + i * 4;
            let got = u32::from_le_bytes(bin[off..off + 4].try_into().unwrap());
            assert_eq!(got, *want, "sub-authority {i}");
        }
        assert!(text.ends_with(&format!("-{USER_RID}")));
    }

    /// The embedded `PSID` pointers must point just past their own header, at
    /// the address the reply will actually live at — that is what makes the
    /// buffer self-contained when the guest reads it back.
    #[test]
    fn embedded_sid_pointers_are_relative_to_the_target_address() {
        const BASE: u64 = 0x4000_0000;
        let user = token_info(TOKEN_USER, BASE).unwrap();
        let ptr = u64::from_le_bytes(user[0..8].try_into().unwrap());
        assert_eq!(ptr, BASE + 16, "TOKEN_USER.User.Sid follows the 16-byte header");
        assert_eq!(&user[16..], &user_sid()[..], "and the SID is there");

        let owner = token_info(TOKEN_OWNER, BASE).unwrap();
        assert_eq!(u64::from_le_bytes(owner[0..8].try_into().unwrap()), BASE + 8);

        let groups = token_info(TOKEN_GROUPS, BASE).unwrap();
        assert_eq!(u32::from_le_bytes(groups[0..4].try_into().unwrap()), 1, "one group");
        assert_eq!(
            u64::from_le_bytes(groups[8..16].try_into().unwrap()),
            BASE + 24,
            "Groups[0].Sid follows the count + the SID_AND_ATTRIBUTES entry"
        );
        assert_eq!(&groups[24..], &users_group_sid()[..]);
    }

    /// The token must describe an ordinary, **non-elevated** user. An installer
    /// that believes it is already admin will skip its own elevation step and
    /// then fail doing something it cannot do — a confusing downstream failure
    /// rather than a clean one.
    #[test]
    fn the_modelled_user_is_not_elevated() {
        const BASE: u64 = 0x1000;
        assert_eq!(
            u32::from_le_bytes(token_info(TOKEN_ELEVATION, BASE).unwrap()[0..4].try_into().unwrap()),
            0,
            "TokenIsElevated must be false"
        );
        assert_eq!(
            u32::from_le_bytes(token_info(TOKEN_ELEVATION_TYPE, BASE).unwrap()[0..4].try_into().unwrap()),
            TOKEN_ELEVATION_TYPE_DEFAULT
        );
        assert_eq!(
            u32::from_le_bytes(token_info(TOKEN_PRIVILEGES, BASE).unwrap()[0..4].try_into().unwrap()),
            0,
            "no privileges are fabricated"
        );
        // The only group is BUILTIN\Users (545), never Administrators (544).
        let groups = token_info(TOKEN_GROUPS, BASE).unwrap();
        let rid = u32::from_le_bytes(groups[groups.len() - 4..].try_into().unwrap());
        assert_eq!(rid, BUILTIN_USERS_RID);
        assert_ne!(rid, 544, "must not claim membership of BUILTIN\\Administrators");
        // Medium integrity, not high.
        let label = token_info(TOKEN_INTEGRITY_LEVEL, BASE).unwrap();
        let il = u32::from_le_bytes(label[label.len() - 4..].try_into().unwrap());
        assert_eq!(il, INTEGRITY_MEDIUM_RID);
    }

    /// An unmodelled class is a clean failure, not a zero-filled struct: a guest
    /// handed a parseable-but-wrong token makes a wrong security decision.
    #[test]
    fn unmodelled_class_is_none() {
        assert!(token_info(0, 0x1000).is_none());
        assert!(token_info(999, 0x1000).is_none());
        // …but every class we claim to model produces something.
        for c in [
            TOKEN_USER,
            TOKEN_GROUPS,
            TOKEN_PRIVILEGES,
            TOKEN_OWNER,
            TOKEN_PRIMARY_GROUP,
            TOKEN_TYPE,
            TOKEN_STATISTICS,
            TOKEN_ELEVATION_TYPE,
            TOKEN_ELEVATION,
            TOKEN_INTEGRITY_LEVEL,
        ] {
            assert!(token_info(c, 0x1000).is_some(), "class {c} should be modelled");
        }
    }
}

use exemu_core::{CpuState, Memory, Result};

use crate::WinOs;

const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;

pub(crate) const SSDT_NT_OPEN_PROCESS_TOKEN: u32 = 0xb5;
pub(crate) const SSDT_NT_OPEN_PROCESS_TOKEN_EX: u32 = 0x30;
pub(crate) const SSDT_NT_OPEN_THREAD_TOKEN: u32 = 0x24;
pub(crate) const SSDT_NT_OPEN_THREAD_TOKEN_EX: u32 = 0x2f;
pub(crate) const SSDT_NT_QUERY_INFORMATION_TOKEN: u32 = 0x21;

pub const TOKEN_PSEUDO_HANDLE: u64 = 0x0000_0000_0000_0100;

pub const CURRENT_PROCESS_TOKEN: u64 = 0xFFFF_FFFF_FFFF_FFFC;
pub const CURRENT_THREAD_TOKEN: u64 = 0xFFFF_FFFF_FFFF_FFFB;
pub const CURRENT_THREAD_EFFECTIVE_TOKEN: u64 = 0xFFFF_FFFF_FFFF_FFFA;

pub(crate) fn is_current_token_handle(handle: u64) -> bool {
    matches!(
        handle,
        TOKEN_PSEUDO_HANDLE | CURRENT_PROCESS_TOKEN | CURRENT_THREAD_TOKEN | CURRENT_THREAD_EFFECTIVE_TOKEN
    )
}

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

const TOKEN_TYPE_PRIMARY: u32 = 1;
const TOKEN_ELEVATION_TYPE_DEFAULT: u32 = 1;

const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

const USER_RID: u32 = 1000;
const DOMAIN_SUB_AUTHORITIES: [u32; 3] = [0x21ab_cdef, 0x1234_5678, 0x0fed_cba9];

const BUILTIN_USERS_RID: u32 = 545;
const BUILTIN_DOMAIN_RID: u32 = 32;

const INTEGRITY_MEDIUM_RID: u32 = 0x2000;
const LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];

fn sid_bytes(authority: [u8; 6], sub: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + sub.len() * 4);
    out.push(1);
    out.push(sub.len() as u8);
    out.extend_from_slice(&authority);
    for s in sub {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

pub fn user_sid() -> Vec<u8> {
    let mut sub = vec![21u32];
    sub.extend_from_slice(&DOMAIN_SUB_AUTHORITIES);
    sub.push(USER_RID);
    sid_bytes(NT_AUTHORITY, &sub)
}

pub fn user_sid_string() -> String {
    let mut s = String::from("S-1-5-21");
    for d in DOMAIN_SUB_AUTHORITIES {
        s.push_str(&format!("-{d}"));
    }
    s.push_str(&format!("-{USER_RID}"));
    s
}

fn users_group_sid() -> Vec<u8> {
    sid_bytes(NT_AUTHORITY, &[BUILTIN_DOMAIN_RID, BUILTIN_USERS_RID])
}

fn medium_integrity_sid() -> Vec<u8> {
    sid_bytes(LABEL_AUTHORITY, &[INTEGRITY_MEDIUM_RID])
}

const SE_GROUP_ENABLED_DEFAULT_MANDATORY: u32 = 0x4 | 0x2 | 0x1;
const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x20 | 0x40;

fn token_info(class: u32, base: u64) -> Option<Vec<u8>> {
    let sid_and_attrs = |sid: Vec<u8>, attrs: u32| -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(base + 16).to_le_bytes());
        out.extend_from_slice(&attrs.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&sid);
        out
    };

    Some(match class {
        TOKEN_USER => sid_and_attrs(user_sid(), 0),
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
        TOKEN_GROUPS => {
            let sid = users_group_sid();
            let hdr = 8u64;
            let sid_at = base + hdr + 16;
            let mut out = Vec::new();
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&sid_at.to_le_bytes());
            out.extend_from_slice(&SE_GROUP_ENABLED_DEFAULT_MANDATORY.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&sid);
            out
        }
        TOKEN_PRIVILEGES => 0u32.to_le_bytes().to_vec(),
        TOKEN_TYPE => TOKEN_TYPE_PRIMARY.to_le_bytes().to_vec(),
        TOKEN_ELEVATION => 0u32.to_le_bytes().to_vec(),
        TOKEN_ELEVATION_TYPE => TOKEN_ELEVATION_TYPE_DEFAULT.to_le_bytes().to_vec(),
        TOKEN_INTEGRITY_LEVEL => sid_and_attrs(medium_integrity_sid(), SE_GROUP_INTEGRITY_ENABLED),
        TOKEN_STATISTICS => {
            let mut out = Vec::new();
            out.extend_from_slice(&0x0001_0000u64.to_le_bytes());
            out.extend_from_slice(&0x0002_0000u64.to_le_bytes());
            out.extend_from_slice(&i64::MAX.to_le_bytes());
            out.extend_from_slice(&TOKEN_TYPE_PRIMARY.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0x0001_0000u64.to_le_bytes());
            out
        }
        _ => return None,
    })
}

impl WinOs {
    fn nt_open_token(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory, out_arg: usize) -> Result<u32> {
        let out = self.syscall_arg(cpu, mem, out_arg)?;
        if out == 0 {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        mem.write_u64(out, TOKEN_PSEUDO_HANDLE)?;
        Ok(STATUS_SUCCESS)
    }

    fn nt_query_information_token(&mut self, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
        let handle = self.syscall_arg(cpu, mem, 0)?;
        let class = self.syscall_arg(cpu, mem, 1)? as u32;
        let buf = self.syscall_arg(cpu, mem, 2)?;
        let len = self.syscall_arg(cpu, mem, 3)? as usize;
        let ret_len = self.syscall_arg(cpu, mem, 4)?;

        if !is_current_token_handle(handle) {
            return Ok(STATUS_INVALID_HANDLE);
        }
        let Some(info) = token_info(class, buf) else {
            return Ok(STATUS_INVALID_INFO_CLASS);
        };

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

pub(crate) fn ssdt_nt_open_process_token(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_token(cpu, mem, 2)
}
pub(crate) fn ssdt_nt_open_process_token_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_token(cpu, mem, 3)
}
pub(crate) fn ssdt_nt_open_thread_token(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_token(cpu, mem, 3)
}
pub(crate) fn ssdt_nt_open_thread_token_ex(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_open_token(cpu, mem, 4)
}
pub(crate) fn ssdt_nt_query_information_token(os: &mut WinOs, cpu: &mut CpuState, mem: &mut dyn Memory) -> Result<u32> {
    os.nt_query_information_token(cpu, mem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_token_pseudo_handles_match_the_documented_negative_values() {
        assert_eq!(CURRENT_PROCESS_TOKEN, (-4i64) as u64);
        assert_eq!(CURRENT_THREAD_TOKEN, (-5i64) as u64);
        assert_eq!(CURRENT_THREAD_EFFECTIVE_TOKEN, (-6i64) as u64);
        let all = [TOKEN_PSEUDO_HANDLE, CURRENT_PROCESS_TOKEN, CURRENT_THREAD_TOKEN, CURRENT_THREAD_EFFECTIVE_TOKEN];
        let unique: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(unique.len(), all.len(), "the four token handles must be pairwise distinct");
    }

    #[test]
    fn is_current_token_handle_accepts_the_well_known_and_opened_handles() {
        assert!(is_current_token_handle(TOKEN_PSEUDO_HANDLE));
        assert!(is_current_token_handle(CURRENT_PROCESS_TOKEN));
        assert!(is_current_token_handle(CURRENT_THREAD_TOKEN));
        assert!(is_current_token_handle(CURRENT_THREAD_EFFECTIVE_TOKEN));
        assert!(is_current_token_handle(0xffff_ffff_ffff_fffa), "the exact handle observed live (-6)");

        assert!(!is_current_token_handle(0));
        assert!(!is_current_token_handle(0x1234));
        assert!(!is_current_token_handle((-1i64) as u64), "NtCurrentProcess(), not a token handle");
        assert!(!is_current_token_handle((-2i64) as u64), "NtCurrentThread(), not a token handle");
    }

    #[test]
    fn sid_serialisation_matches_the_documented_layout() {
        let sid = users_group_sid();
        assert_eq!(
            sid,
            vec![
                1,
                2,
                0, 0, 0, 0, 0, 5,
                32, 0, 0, 0,
                33, 2, 0, 0,
            ]
        );
        assert_eq!(sid.len(), 8 + 4 * 2);
        assert_eq!(user_sid().len(), 8 + 4 * 5, "S-1-5-21-a-b-c-1000 has 5 sub-authorities");
    }

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
        let groups = token_info(TOKEN_GROUPS, BASE).unwrap();
        let rid = u32::from_le_bytes(groups[groups.len() - 4..].try_into().unwrap());
        assert_eq!(rid, BUILTIN_USERS_RID);
        assert_ne!(rid, 544, "must not claim membership of BUILTIN\\Administrators");
        let label = token_info(TOKEN_INTEGRITY_LEVEL, BASE).unwrap();
        let il = u32::from_le_bytes(label[label.len() - 4..].try_into().unwrap());
        assert_eq!(il, INTEGRITY_MEDIUM_RID);
    }

    #[test]
    fn unmodelled_class_is_none() {
        assert!(token_info(0, 0x1000).is_none());
        assert!(token_info(999, 0x1000).is_none());
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

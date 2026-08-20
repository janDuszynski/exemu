//! Dynamic opcode-frequency profiling (roadmap W8.3) — **off by default**.
//!
//! The JIT's first slice should cover the instruction *shapes a real workload
//! actually executes*, not the ones that feel common. This module counts every
//! instruction the interpreter retires, keyed by the shape that matters for
//! code generation: the opcode byte, whether it came through the `0F` escape,
//! the operand-size prefixes (`REX.W` / `66`) and — for the ModRM-`reg`-dispatched
//! groups (`80`/`81`/`83`, the shifts, `F6`/`F7`, `FE`/`FF`, …) — the sub-opcode.
//!
//! It is compiled in only under the `profile` cargo feature, so the shipping
//! interpreter carries **zero** cost (not even a branch): every hook site is a
//! `#[cfg]`-gated block. That matters because the corpus pins are exact
//! instruction counts — an instrumented build must not be able to change them,
//! and the only way to guarantee that is for the instrumentation not to exist.
//!
//! Usage:
//! ```text
//! cargo build --release -p exemu-cli --features opcode-profile
//! ./target/release/exemu run --opcode-profile <file.exe>
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

/// Key layout (14 bits):
/// `[group_reg:3][p66:1][rex_w:1][esc0f:1][opcode:8]`
const KEY_BITS: usize = 14;
/// Number of distinct instruction shapes the table can hold.
pub const KEYS: usize = 1 << KEY_BITS;

static COUNTS: [AtomicU64; KEYS] = [const { AtomicU64::new(0) }; KEYS];

/// Build the table key for one decoded instruction shape.
#[inline]
pub fn key(opcode: u8, esc0f: bool, rex_w: bool, p66: bool, group_reg: u8) -> u16 {
    (opcode as u16)
        | ((esc0f as u16) << 8)
        | ((rex_w as u16) << 9)
        | ((p66 as u16) << 10)
        | (((group_reg & 7) as u16) << 11)
}

/// Count one retired instruction.
#[inline]
pub fn record(opcode: u8, esc0f: bool, rex_w: bool, p66: bool, group_reg: u8) {
    COUNTS[key(opcode, esc0f, rex_w, p66, group_reg) as usize].fetch_add(1, Ordering::Relaxed);
}

/// True when the ModRM `reg` field selects the operation for this opcode, so the
/// profile should keep them apart (`81 /5` = SUB is a different codegen problem
/// from `81 /0` = ADD).
#[inline]
pub fn is_group(opcode: u8, esc0f: bool) -> bool {
    if esc0f {
        matches!(opcode, 0x00 | 0x01 | 0xAE | 0xBA | 0xC7)
    } else {
        matches!(
            opcode,
            0x80 | 0x81 | 0x83 | 0x8F | 0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3 | 0xF6 | 0xF7 | 0xFE | 0xFF
        )
    }
}

/// Every shape seen at least once, as `(key, count)`, most frequent first.
pub fn snapshot() -> Vec<(u16, u64)> {
    let mut out: Vec<(u16, u64)> = COUNTS
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let n = c.load(Ordering::Relaxed);
            if n == 0 {
                None
            } else {
                Some((i as u16, n))
            }
        })
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

/// Total instructions counted.
pub fn total() -> u64 {
    COUNTS.iter().map(|c| c.load(Ordering::Relaxed)).sum()
}

/// Decompose a key back into `(opcode, esc0f, rex_w, p66, group_reg)`.
pub fn decode_key(k: u16) -> (u8, bool, bool, bool, u8) {
    (
        (k & 0xff) as u8,
        k & (1 << 8) != 0,
        k & (1 << 9) != 0,
        k & (1 << 10) != 0,
        ((k >> 11) & 7) as u8,
    )
}

/// A human-readable label for a profile key, e.g. `83 /5  sub r/m,imm8  [w]`.
pub fn label(k: u16) -> String {
    let (op, esc, w, p66, greg) = decode_key(k);
    let mut s = String::new();
    if esc {
        s.push_str("0f ");
    }
    s.push_str(&format!("{op:02x}"));
    if is_group(op, esc) {
        s.push_str(&format!(" /{greg}"));
    }
    let m = mnemonic(op, esc, greg);
    s.push_str(&format!("  {m}"));
    if w {
        s.push_str("  [rex.w]");
    }
    if p66 {
        s.push_str("  [66]");
    }
    s
}

const ALU_NAMES: [&str; 8] = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"];
const SHIFT_NAMES: [&str; 8] = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"];
const CC: [&str; 16] =
    ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"];

/// Best-effort mnemonic for the shape (enough to read a profile at a glance).
fn mnemonic(op: u8, esc: bool, greg: u8) -> &'static str {
    if esc {
        return match op {
            0x05 => "syscall",
            0x0B => "ud2",
            0x10 | 0x11 => "movups/movss/movsd",
            0x12..=0x17 => "movlps/movhps",
            0x1E => "endbr/nop",
            0x1F => "nop r/m",
            0x28 | 0x29 => "movaps/movapd",
            0x2A => "cvtsi2ss/sd",
            0x2C | 0x2D => "cvt(t)ss/sd2si",
            0x2E | 0x2F => "ucomis/comis",
            0x31 => "rdtsc",
            0x38 => "(0f 38 map)",
            0x3A => "(0f 3a map)",
            0x40..=0x4F => "cmovcc",
            0x54..=0x57 => "andps/andnps/orps/xorps",
            0x58..=0x5F => "add/mul/cvt/sub/min/div/max ps-sd",
            0x60..=0x6F => "punpck/movdq",
            0x70..=0x73 => "pshuf/psll-srl imm",
            0x74..=0x76 => "pcmpeq",
            0x77 => "emms/vzeroupper",
            0x7E | 0x7F => "movd/movq/movdq",
            0x80..=0x8F => "jcc rel32",
            0x90..=0x9F => "setcc",
            0xA2 => "cpuid",
            0xA3 => "bt",
            0xA4 | 0xA5 => "shld",
            0xAB => "bts",
            0xAC | 0xAD => "shrd",
            0xAE => "fence/fxsave/xsave",
            0xAF => "imul r,r/m",
            0xB0 | 0xB1 => "cmpxchg",
            0xB3 => "btr",
            0xB6 | 0xB7 => "movzx",
            0xBA => match greg {
                4 => "bt r/m,imm8",
                5 => "bts r/m,imm8",
                6 => "btr r/m,imm8",
                _ => "btc r/m,imm8",
            },
            0xBB => "btc",
            0xBC => "bsf/tzcnt",
            0xBD => "bsr/lzcnt",
            0xBE | 0xBF => "movsx",
            0xC0 | 0xC1 => "xadd",
            0xC3 => "movnti",
            0xC6 => "shufps",
            0xC7 => "cmpxchg8b/16b",
            0xC8..=0xCF => "bswap",
            0xD4..=0xDF => "padd/psub/pand..",
            0xE0..=0xEF => "pavg/pmul/pxor..",
            0xF0..=0xFF => "psll/padd/psub..",
            _ => "",
        };
    }
    match op {
        0x00..=0x3D if op & 7 < 6 => ALU_NAMES[(op >> 3) as usize],
        0x40..=0x47 => "inc r32 (32-bit mode)",
        0x48..=0x4F => "dec r32 (32-bit mode)",
        0x50..=0x57 => "push r",
        0x58..=0x5F => "pop r",
        0x63 => "movsxd",
        0x68 | 0x6A => "push imm",
        0x69 | 0x6B => "imul r,r/m,imm",
        0x70..=0x7F => CC[(op & 0xf) as usize], // rendered below as jcc
        0x80 | 0x81 | 0x83 => ALU_NAMES[(greg & 7) as usize],
        0x84 | 0x85 => "test r/m,r",
        0x86 | 0x87 => "xchg r/m,r",
        0x88 | 0x89 => "mov r/m,r",
        0x8A | 0x8B => "mov r,r/m",
        0x8D => "lea",
        0x8F => "pop r/m",
        0x90 => "nop/pause",
        0x91..=0x97 => "xchg rax,r",
        0x98 => "cwde/cdqe",
        0x99 => "cdq/cqo",
        0x9C => "pushf",
        0x9D => "popf",
        0xA4..=0xA7 => "movs/cmps",
        0xA8 | 0xA9 => "test al/eax,imm",
        0xAA..=0xAF => "stos/lods/scas",
        0xB0..=0xB7 => "mov r8,imm8",
        0xB8..=0xBF => "mov r,imm",
        0xC0 | 0xC1 => SHIFT_NAMES[(greg & 7) as usize],
        0xC2 | 0xC3 => "ret",
        0xC6 | 0xC7 => "mov r/m,imm",
        0xC9 => "leave",
        0xCC => "int3",
        0xD0..=0xD3 => SHIFT_NAMES[(greg & 7) as usize],
        0xE8 => "call rel32",
        0xE9 | 0xEB => "jmp rel",
        0xF6 | 0xF7 => match greg {
            0 | 1 => "test r/m,imm",
            2 => "not",
            3 => "neg",
            4 => "mul",
            5 => "imul",
            6 => "div",
            _ => "idiv",
        },
        0xFE => {
            if greg == 0 {
                "inc r/m8"
            } else {
                "dec r/m8"
            }
        }
        0xFF => match greg {
            0 => "inc r/m",
            1 => "dec r/m",
            2 => "call r/m",
            3 => "call far",
            4 => "jmp r/m",
            5 => "jmp far",
            _ => "push r/m",
        },
        _ => "",
    }
}

/// Render the top `n` shapes as a report, with cumulative coverage — the shape
/// of the answer the JIT needs ("how much of the stream do the top N opcodes
/// account for?").
pub fn report(n: usize) -> String {
    let snap = snapshot();
    let total = total();
    let mut out = String::new();
    out.push_str(&format!("opcode profile: {total} instructions, {} distinct shapes\n", snap.len()));
    out.push_str("     count      share   cum      shape\n");
    let mut cum = 0u64;
    for (k, c) in snap.iter().take(n) {
        cum += c;
        let (op, esc, _, _, _) = decode_key(*k);
        let mut lab = label(*k);
        if !esc && (0x70..=0x7F).contains(&op) {
            lab = format!("{op:02x}  j{}  rel8", mnemonic(op, false, 0));
        }
        out.push_str(&format!(
            "  {:>10}  {:>6.2}%  {:>6.2}%  {}\n",
            c,
            100.0 * *c as f64 / total.max(1) as f64,
            100.0 * cum as f64 / total.max(1) as f64,
            lab
        ));
    }
    out
}

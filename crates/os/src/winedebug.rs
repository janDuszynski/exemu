//! Wine's **debug channels** — the per-process option array every PE builtin
//! resolves its `TRACE`/`WARN`/`ERR`/`FIXME` guards against (roadmap W6.4).
//!
//! This is the unix side of a mechanism that is otherwise entirely inside
//! Wine's own binaries, and exemu has to supply it for the same reason it
//! supplies the NT syscalls: `ntdll.so` normally builds this array out of the
//! `WINEDEBUG` environment variable, and exemu is what stands in for
//! `ntdll.so`.
//!
//! # The mechanism, recovered from the pinned Wine 11.0 binaries
//!
//! **1. Every channel is a 16-byte object in the DLL's `.data`.**
//! `user32.dll`'s `__wine_dbch_win` (x86-64 rva 0x91da0) reads
//! `ff 77 69 6e 00 …` — i.e. `struct { unsigned char flags; char name[15]; }`
//! shipped as `{ 0xff, "win" }`. Bit 7 of `flags` is a "**not resolved yet**"
//! sentinel, not a class: the four classes are bits 0–3, and the class-name
//! table each builtin carries (i386 `user32.dll` 0x100b2180) spells their order
//! `fixme, err, warn, trace`.
//!
//! **2. A guard is a bare byte test.** `user32!SetWindowTextW` opens its warning
//! path with `f6 05 <disp32> 04` — `test byte [rip+d], 1<<WARN` — and
//! `user32!call_window_proc` brackets *every* window-procedure call with
//! `test byte [__wine_dbch_win32], 1<<TRACE`. There is no call in the fast path,
//! so a channel shipped as `0xff` reads as **every class on** and takes the
//! logging branch.
//!
//! **3. The logging branch resolves the byte once and writes the answer back.**
//! `ntdll!__wine_dbg_get_channel_flags` (rva 0x3f010) is
//! `movzbl (%rcx),%eax; test %al,%al; jns ret` — bit 7 clear means "already
//! resolved, use it" — and its slow half looks the channel up in the option
//! array, then `movb %r13b,(%r12)`: **the resolved flags are cached into the
//! channel object**, provided the answer itself has bit 7 clear. Every later
//! guard on that channel is then a single failing `testb`. `__wine_dbg_header`
//! (rva 0x3f150) does the same before deciding whether to emit a line, which is
//! how a `TRACE()` that went down the slow path still prints nothing.
//!
//! **4. The option array lives at a fixed offset from the PEB**, and the offset
//! is **different for the two bitnesses** — this is the part that cannot be
//! mirrored from one binary to the other:
//!
//! ```text
//!   ntdll.dll     (x86-64)  mov rcx,gs:[0x30]; mov r8,[rcx+0x60]; lea rdi,[r8+0x2000]
//!   ntdll.dll     (i386)    mov ecx,fs:[0x18]; mov esi,[ecx+0x30]; lea ecx,[esi+0x1000]
//! ```
//!
//! so the array is at **`PEB64 + 0x2000`** and **`PEB32 + 0x1000`**. Its shape
//! is the same 16-byte record as a channel: entries **sorted by name** (ntdll
//! binary-searches them with `strcmp`), terminated by an entry whose `name[0]`
//! is NUL — and **that terminator's `flags` byte is the default** every channel
//! not named in the array resolves to.
//!
//! **5. The default with no `WINEDEBUG` is `err+fixme`, not "all off".** Each
//! builtin also carries a *fallback* resolver for the case where ntdll's export
//! cannot be found (i386 `user32!fallback__wine_dbg_get_channel_flags`,
//! 0x10064a90): it reads `WINEDEBUG` with `GetEnvironmentVariableA`, parses it
//! against that same `fixme,err,warn,trace` table, and falls back to a
//! `default_flags` byte that **ships as `0x03`** (i386 `user32.dll` 0x1009798c)
//! = `(1<<FIXME)|(1<<ERR)`. That is the documented `wine(1)` default,
//! `err+all,fixme+all`, and it is the value [`Options::default`] uses.
//!
//! # What exemu has to do
//!
//! Write that array — for **both** PEBs of a WoW64 process — before any guest
//! code runs. Not poke the channel bytes: the channels are Wine's data, the
//! array is the interface Wine publishes for setting them, and going through it
//! is what makes `WINEDEBUG=+relay` work on exemu at all.

use exemu_core::{Memory, Result};

/// `sizeof(struct __wine_debug_channel)` — one flags byte plus `char name[15]`.
/// The option array is an array of exactly this record.
pub const OPTION_SIZE: u64 = 16;

/// Usable characters in an option's name: `char name[15]`, NUL-terminated,
/// because ntdll compares it with `strcmp`.
pub const OPTION_NAME_MAX: usize = 15 - 1;

/// Offset of the option array from a **64-bit** PEB (`ntdll.dll` x86-64
/// rva 0x3f0f0: `lea rdi,[r8+0x2000]`).
pub const OPTIONS_OFF_64: u64 = 0x2000;

/// Offset of the option array from a **32-bit** PEB (`ntdll.dll` i386
/// rva 0x3cd70: `lea ecx,[esi+0x1000]`). Deliberately *not* the 64-bit value.
pub const OPTIONS_OFF_32: u64 = 0x1000;

/// Offset of `__wine_dbg_strdup`'s per-thread string ring from a **64-bit**
/// TEB: a `u32` write position at `TEB+0x3000`, ring bytes from `TEB+0x3008`,
/// both bounded to `0x3fc` (`ntdll.dll` x86-64 rva 0x3f3c0).
pub const STRDUP_RING_OFF_64: u64 = 0x3000;

/// The same ring from a **32-bit** TEB (`ntdll.dll` i386 rva 0x3d020:
/// `mov edi,[esi+0x1000]` … `lea edx,[edi+esi+0x1008]`).
pub const STRDUP_RING_OFF_32: u64 = 0x1000;

/// Bytes of the ring, position word included — the bound both builds compare
/// against (`cmp $0x3fc`), plus the `0x8`-byte header the bytes start after.
pub const STRDUP_RING_SIZE: u64 = 0x8 + 0x3fc;

/// The four debug classes, in the bit order the builtins' own class-name table
/// spells (`fixme, err, warn, trace` — i386 `user32.dll` 0x100b2180).
pub const CLASSES: [&str; 4] = ["fixme", "err", "warn", "trace"];

/// Every class enabled — what a channel byte shipped as `0xff` reads as, once
/// the `0x80` "unresolved" sentinel is masked off.
pub const ALL_CLASSES: u8 = 0x0f;

/// The flags a channel resolves to with no `WINEDEBUG` set: `err` and `fixme`
/// on, `warn` and `trace` off. Recovered as the shipped `default_flags` byte of
/// the builtins' own fallback resolver (i386 `user32.dll` 0x1009798c = `0x03`),
/// and the documented `wine(1)` default `err+all,fixme+all`.
pub const DEFAULT_FLAGS: u8 = (1 << 1) | (1 << 0);

/// The "not resolved yet" sentinel a channel object ships with. An answer
/// carrying this bit is **not** cached back into the channel by
/// `__wine_dbg_get_channel_flags`, so it must never appear in the array.
pub const UNRESOLVED: u8 = 0x80;

/// A parsed `WINEDEBUG` specification, in the form the array wants: a default
/// for unnamed channels plus per-channel overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Flags for every channel not named below — the array's terminator entry.
    pub default_flags: u8,
    /// Per-channel overrides, **sorted by name** because ntdll binary-searches.
    pub channels: Vec<(String, u8)>,
}

impl Default for Options {
    fn default() -> Self {
        Options { default_flags: DEFAULT_FLAGS, channels: Vec::new() }
    }
}

impl Options {
    /// Parse a `WINEDEBUG` specification — the documented `wine(1)` syntax,
    /// `[class][+|-]channel[,…]`:
    ///
    /// * an omitted class applies the change to **all four** classes;
    /// * the channel `all` (or an empty channel) changes the **default**, and
    ///   with it every channel named so far, which is what makes the common
    ///   `WINEDEBUG=-all,+relay` mean "silence everything, then trace relay";
    /// * a named channel starts from the default in force when it is first
    ///   mentioned and is then adjusted.
    ///
    /// Unparseable items are skipped rather than failing the boot: a bad
    /// `WINEDEBUG` is a diagnostic setting, not a program input.
    pub fn from_spec(spec: &str) -> Options {
        let mut opts = Options::default();
        for item in spec.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            // Split at the sign. No sign at all is read as `+` on the whole
            // item, so `WINEDEBUG=relay` behaves like `WINEDEBUG=+relay`.
            let (head, set, name) = match item.find(['+', '-']) {
                Some(i) => (&item[..i], item.as_bytes()[i] == b'+', &item[i + 1..]),
                None => ("", true, item),
            };
            let mask = if head.is_empty() {
                ALL_CLASSES
            } else if let Some(c) = CLASSES.iter().position(|c| *c == head) {
                1u8 << c
            } else {
                continue; // an unknown class name: skip the item, keep booting
            };
            let apply = |f: u8| if set { f | mask } else { f & !mask };
            if name.is_empty() || name == "all" {
                opts.default_flags = apply(opts.default_flags);
                for (_, f) in opts.channels.iter_mut() {
                    *f = apply(*f);
                }
                continue;
            }
            let name: String = name.chars().take(OPTION_NAME_MAX).collect();
            match opts.channels.binary_search_by(|(n, _)| n.as_str().cmp(name.as_str())) {
                Ok(i) => opts.channels[i].1 = apply(opts.channels[i].1),
                Err(i) => opts.channels.insert(i, (name, apply(opts.default_flags))),
            }
        }
        opts
    }

    /// The specification this process was started with — host `WINEDEBUG`, or
    /// the [`Default`] (`err+fixme`) when it is unset.
    pub fn from_env() -> Options {
        match std::env::var("WINEDEBUG") {
            Ok(spec) => Options::from_spec(&spec),
            Err(_) => Options::default(),
        }
    }

    /// Encode the array exactly as `__wine_dbg_get_channel_flags` reads it:
    /// `channels` in name order, then a terminator whose name is empty and
    /// whose flags byte is [`Options::default_flags`].
    ///
    /// The `0x80` sentinel is masked out of every byte written: ntdll declines
    /// to cache an answer carrying it, which would leave every guard in the
    /// process paying the slow path for ever.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity((self.channels.len() + 1) * OPTION_SIZE as usize);
        let mut entry = |flags: u8, name: &str| {
            let mut rec = [0u8; OPTION_SIZE as usize];
            rec[0] = flags & !UNRESOLVED;
            for (i, b) in name.bytes().take(OPTION_NAME_MAX).enumerate() {
                rec[1 + i] = b;
            }
            out.extend_from_slice(&rec);
        };
        for (name, flags) in &self.channels {
            entry(*flags, name);
        }
        entry(self.default_flags, "");
        out
    }
}

/// Publish the option array at `peb + off` (see [`OPTIONS_OFF_64`] /
/// [`OPTIONS_OFF_32`]), truncated to `limit` bytes so it cannot run past the
/// page the caller reserved for it. The terminator is always written, even if
/// the named channels have to be dropped to make room — an array with no
/// terminator would make ntdll walk whatever follows it.
pub fn write_options(
    mem: &mut dyn Memory,
    peb: u64,
    off: u64,
    limit: u64,
    opts: &Options,
) -> Result<()> {
    let mut bytes = opts.encode();
    let max = (limit / OPTION_SIZE * OPTION_SIZE) as usize;
    if bytes.len() > max {
        // Keep the terminator, drop the overflowing named channels.
        let keep = max.saturating_sub(OPTION_SIZE as usize);
        bytes.truncate(keep);
        bytes.extend_from_slice(&Options { default_flags: opts.default_flags, channels: Vec::new() }.encode());
    }
    mem.write(peb + off, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record shape, and the terminator that carries the default.
    #[test]
    fn the_array_is_sixteen_byte_records_ending_in_the_default() {
        let enc = Options::default().encode();
        assert_eq!(enc.len(), OPTION_SIZE as usize, "no channels → the terminator alone");
        assert_eq!(enc[0], DEFAULT_FLAGS, "the terminator's flags byte IS the default");
        assert_eq!(enc[1], 0, "…and its name is empty, which is what ends the array");

        let opts = Options::from_spec("+relay");
        let enc = opts.encode();
        assert_eq!(enc.len(), 2 * OPTION_SIZE as usize);
        assert_eq!(&enc[1..6], b"relay");
        assert_eq!(enc[0], ALL_CLASSES, "a bare +chan turns on every class");
        assert_eq!(enc[OPTION_SIZE as usize], DEFAULT_FLAGS);
        assert_eq!(enc[OPTION_SIZE as usize + 1], 0);
    }

    /// With no `WINEDEBUG`, `err` and `fixme` are on and `warn`/`trace` are off
    /// — the value the pinned builtins' own fallback resolver ships.
    #[test]
    fn the_default_is_err_plus_fixme() {
        let d = Options::default();
        assert_eq!(d.default_flags, 0x03);
        assert_eq!(d.default_flags & (1 << 3), 0, "trace is off by default");
        assert_eq!(d.default_flags & (1 << 2), 0, "warn is off by default");
        assert_eq!(CLASSES, ["fixme", "err", "warn", "trace"], "the bit order is the table's");
    }

    /// `-all` silences everything, including channels named before it; a class
    /// prefix touches only that class.
    #[test]
    fn a_spec_composes_left_to_right() {
        let o = Options::from_spec("-all,+relay");
        assert_eq!(o.default_flags, 0, "-all clears the default");
        assert_eq!(o.channels, vec![("relay".to_string(), ALL_CLASSES)]);

        let o = Options::from_spec("+heap,-all");
        assert_eq!(o.default_flags, 0);
        assert_eq!(o.channels, vec![("heap".to_string(), 0)], "-all reaches back over +heap");

        let o = Options::from_spec("warn+heap");
        assert_eq!(o.default_flags, DEFAULT_FLAGS);
        assert_eq!(o.channels, vec![("heap".to_string(), DEFAULT_FLAGS | (1 << 2))]);

        let o = Options::from_spec("trace+seh,trace+file");
        assert_eq!(
            o.channels.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["file", "seh"],
            "entries come out sorted — ntdll binary-searches them"
        );

        // Junk is skipped, not fatal.
        assert_eq!(Options::from_spec("bogus+x").channels, vec![]);
        assert_eq!(Options::from_spec("").default_flags, DEFAULT_FLAGS);
    }

    /// The `0x80` sentinel never reaches the array: ntdll refuses to cache an
    /// answer carrying it, which would make every guard pay for ever.
    #[test]
    fn the_unresolved_sentinel_is_never_published() {
        let opts = Options { default_flags: 0xff, channels: vec![("x".into(), 0xff)] };
        let enc = opts.encode();
        assert_eq!(enc[0] & UNRESOLVED, 0);
        assert_eq!(enc[OPTION_SIZE as usize] & UNRESOLVED, 0);
    }

    /// A specification too long for its page keeps the terminator rather than
    /// letting ntdll walk off the end looking for one.
    #[test]
    fn an_oversized_spec_still_ends_in_a_terminator() {
        use exemu_core::{Perm, Region};
        use exemu_memory::VirtualMemory;
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("peb", 0x1000, 0x2000, Perm::RW)).unwrap();
        let spec: String =
            (0..300).map(|i| format!("+c{i}")).collect::<Vec<_>>().join(",");
        let opts = Options::from_spec(&spec);
        assert_eq!(opts.channels.len(), 300);
        write_options(&mut mem, 0x1000, 0x1000, 0x1000, &opts).unwrap();
        let last = 0x1000 + 0x1000 + 0x1000 - OPTION_SIZE;
        assert_eq!(mem.read_u8(last).unwrap(), DEFAULT_FLAGS, "the last record is the default");
        assert_eq!(mem.read_u8(last + 1).unwrap(), 0, "…with an empty name");
        // And nothing was written past the page.
        assert!(mem.read_u8(0x1000 + 0x2000).is_err());
    }
}

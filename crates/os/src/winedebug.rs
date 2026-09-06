use exemu_core::{Memory, Result};

pub const OPTION_SIZE: u64 = 16;

pub const OPTION_NAME_MAX: usize = 15 - 1;

pub const OPTIONS_OFF_64: u64 = 0x2000;

pub const OPTIONS_OFF_32: u64 = 0x1000;

pub const STRDUP_RING_OFF_64: u64 = 0x3000;

pub const STRDUP_RING_OFF_32: u64 = 0x1000;

pub const STRDUP_RING_SIZE: u64 = 0x8 + 0x3fc;

pub const CLASSES: [&str; 4] = ["fixme", "err", "warn", "trace"];

pub const ALL_CLASSES: u8 = 0x0f;

pub const DEFAULT_FLAGS: u8 = (1 << 1) | (1 << 0);

pub const UNRESOLVED: u8 = 0x80;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub default_flags: u8,
    pub channels: Vec<(String, u8)>,
}

impl Default for Options {
    fn default() -> Self {
        Options { default_flags: DEFAULT_FLAGS, channels: Vec::new() }
    }
}

impl Options {
    pub fn from_spec(spec: &str) -> Options {
        let mut opts = Options::default();
        for item in spec.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (head, set, name) = match item.find(['+', '-']) {
                Some(i) => (&item[..i], item.as_bytes()[i] == b'+', &item[i + 1..]),
                None => ("", true, item),
            };
            let mask = if head.is_empty() {
                ALL_CLASSES
            } else if let Some(c) = CLASSES.iter().position(|c| *c == head) {
                1u8 << c
            } else {
                continue;
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

    pub fn from_env() -> Options {
        match std::env::var("WINEDEBUG") {
            Ok(spec) => Options::from_spec(&spec),
            Err(_) => Options::default(),
        }
    }

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
        let keep = max.saturating_sub(OPTION_SIZE as usize);
        bytes.truncate(keep);
        bytes.extend_from_slice(&Options { default_flags: opts.default_flags, channels: Vec::new() }.encode());
    }
    mem.write(peb + off, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn the_default_is_err_plus_fixme() {
        let d = Options::default();
        assert_eq!(d.default_flags, 0x03);
        assert_eq!(d.default_flags & (1 << 3), 0, "trace is off by default");
        assert_eq!(d.default_flags & (1 << 2), 0, "warn is off by default");
        assert_eq!(CLASSES, ["fixme", "err", "warn", "trace"], "the bit order is the table's");
    }

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

        assert_eq!(Options::from_spec("bogus+x").channels, vec![]);
        assert_eq!(Options::from_spec("").default_flags, DEFAULT_FLAGS);
    }

    #[test]
    fn the_unresolved_sentinel_is_never_published() {
        let opts = Options { default_flags: 0xff, channels: vec![("x".into(), 0xff)] };
        let enc = opts.encode();
        assert_eq!(enc[0] & UNRESOLVED, 0);
        assert_eq!(enc[OPTION_SIZE as usize] & UNRESOLVED, 0);
    }

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
        assert!(mem.read_u8(0x1000 + 0x2000).is_err());
    }
}

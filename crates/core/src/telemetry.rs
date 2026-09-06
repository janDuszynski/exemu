use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissRecord {
    pub opcode: String,
    pub rip: u64,
    pub exe: String,
}

impl MissRecord {
    pub fn to_line(&self) -> String {
        format!("{}\t{:#x}\t{}", self.opcode, self.rip, self.exe)
    }

    pub fn parse(line: &str) -> Option<MissRecord> {
        let mut it = line.split('\t');
        let opcode = it.next()?.trim();
        let rip_s = it.next()?.trim();
        let exe = it.next()?.trim();
        if opcode.is_empty() || it.next().is_some() {
            return None;
        }
        let rip = rip_s
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .or_else(|| rip_s.parse().ok())?;
        Some(MissRecord { opcode: opcode.to_string(), rip, exe: exe.to_string() })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcodeRank {
    pub opcode: String,
    pub count: usize,
    pub exes: Vec<String>,
    pub example_rip: u64,
}

pub fn rank<I: IntoIterator<Item = MissRecord>>(records: I) -> Vec<OpcodeRank> {
    let mut by_op: BTreeMap<String, (usize, u64, std::collections::BTreeSet<String>)> =
        BTreeMap::new();
    for r in records {
        let e = by_op.entry(r.opcode).or_insert((0, r.rip, std::collections::BTreeSet::new()));
        e.0 += 1;
        if !r.exe.is_empty() {
            e.2.insert(r.exe);
        }
    }
    let mut ranked: Vec<OpcodeRank> = by_op
        .into_iter()
        .map(|(opcode, (count, example_rip, exes))| OpcodeRank {
            opcode,
            count,
            exes: exes.into_iter().collect(),
            example_rip,
        })
        .collect();
    ranked.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.opcode.cmp(&b.opcode)));
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_line_round_trips() {
        let r = MissRecord { opcode: "0f 38 0x12".into(), rip: 0x1_4000_1abc, exe: "app.exe".into() };
        let line = r.to_line();
        assert_eq!(line, "0f 38 0x12\t0x14000_1abc\tapp.exe".replace('_', ""));
        assert_eq!(MissRecord::parse(&line), Some(r));
    }

    #[test]
    fn parse_rejects_malformed() {
        assert_eq!(MissRecord::parse(""), None);
        assert_eq!(MissRecord::parse("only\ttwo"), None);
        assert_eq!(MissRecord::parse("op\t0x1\texe\textra"), None);
        assert_eq!(MissRecord::parse("op\tnothex\texe"), None);
    }

    #[test]
    fn parse_accepts_empty_exe() {
        let r = MissRecord::parse("0x1a\t0x400000\t").unwrap();
        assert_eq!(r.exe, "");
        assert_eq!(r.opcode, "0x1a");
    }

    #[test]
    fn ranking_orders_by_count_then_opcode() {
        let recs = vec![
            MissRecord { opcode: "0f 0x1a".into(), rip: 0x1000, exe: "a.exe".into() },
            MissRecord { opcode: "0f 0x1a".into(), rip: 0x2000, exe: "b.exe".into() },
            MissRecord { opcode: "0f 0x1a".into(), rip: 0x3000, exe: "a.exe".into() },
            MissRecord { opcode: "0x1a".into(), rip: 0x4000, exe: "c.exe".into() },
            MissRecord { opcode: "0f 38 0x12".into(), rip: 0x5000, exe: "d.exe".into() },
        ];
        let ranked = rank(recs);
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].opcode, "0f 0x1a");
        assert_eq!(ranked[0].count, 3);
        assert_eq!(ranked[0].exes, vec!["a.exe".to_string(), "b.exe".to_string()]);
        assert_eq!(ranked[0].example_rip, 0x1000);
        assert_eq!(ranked[1].opcode, "0f 38 0x12");
        assert_eq!(ranked[2].opcode, "0x1a");
    }

    #[test]
    fn empty_input_ranks_empty() {
        assert!(rank(std::iter::empty()).is_empty());
    }
}

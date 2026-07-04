//! Missing-opcode telemetry (roadmap P0.5).
//!
//! When the decoder meets bytes it cannot decode it returns
//! [`crate::EmuError::Decode`], which carries the faulting `rip` and a
//! normalized opcode key (e.g. `"0x1a"`, `"0f 0x1a"`, `"0f 38 0x12"`). Each
//! blocked run contributes one such *miss* — the first instruction that stopped
//! it. Recording those across a whole corpus of real `.exe`s and ranking them
//! by frequency yields a **most-wanted list**: fix the top opcode and you
//! unblock the most programs (each to its *next* blocker).
//!
//! This module is the pure, dependency-free core of that feature: the on-disk
//! record format and the aggregation/ranking. The actual file I/O (appending a
//! miss when a run ends, reading the log back) lives in the presentation layer,
//! keeping the domain crate free of side effects.

use std::collections::BTreeMap;

/// One recorded decode miss: the opcode key, where it faulted, and which
/// executable hit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissRecord {
    /// Normalized opcode key exactly as [`crate::EmuError::Decode`] formats it
    /// (may contain spaces, never a tab — which is what makes TSV safe).
    pub opcode: String,
    /// Guest instruction pointer at the faulting instruction.
    pub rip: u64,
    /// Short name of the executable that hit the miss (typically the filename).
    pub exe: String,
}

impl MissRecord {
    /// Serialize to one tab-separated log line (no trailing newline).
    pub fn to_line(&self) -> String {
        format!("{}\t{:#x}\t{}", self.opcode, self.rip, self.exe)
    }

    /// Parse one log line produced by [`MissRecord::to_line`]. Returns `None`
    /// for blank or malformed lines so a partially-written log still aggregates.
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

/// An aggregated entry in the most-wanted ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcodeRank {
    /// The opcode key.
    pub opcode: String,
    /// Total misses recorded for this opcode (≈ how many runs it blocked).
    pub count: usize,
    /// Distinct executables that hit it, sorted.
    pub exes: Vec<String>,
    /// A representative faulting `rip` (the first one seen).
    pub example_rip: u64,
}

/// Aggregate raw miss records into a deterministic most-wanted ranking:
/// highest `count` first, ties broken by opcode key so output is stable.
pub fn rank<I: IntoIterator<Item = MissRecord>>(records: I) -> Vec<OpcodeRank> {
    // Keyed by opcode for deterministic grouping; exes de-duplicated via a set.
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
    // Primary key count desc, secondary opcode asc (a stable sort keeps the
    // BTreeMap's opcode order for equal counts).
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
        assert_eq!(MissRecord::parse("only\ttwo"), None); // missing exe field
        assert_eq!(MissRecord::parse("op\t0x1\texe\textra"), None); // too many fields
        assert_eq!(MissRecord::parse("op\tnothex\texe"), None); // bad rip
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
            MissRecord { opcode: "0f 0x1a".into(), rip: 0x3000, exe: "a.exe".into() }, // dup exe
            MissRecord { opcode: "0x1a".into(), rip: 0x4000, exe: "c.exe".into() },
            MissRecord { opcode: "0f 38 0x12".into(), rip: 0x5000, exe: "d.exe".into() },
        ];
        let ranked = rank(recs);
        // "0f 0x1a" has the most hits; the two single-hit opcodes tie on count
        // and break by opcode key ("0f 38 0x12" < "0x1a").
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].opcode, "0f 0x1a");
        assert_eq!(ranked[0].count, 3);
        assert_eq!(ranked[0].exes, vec!["a.exe".to_string(), "b.exe".to_string()]); // deduped + sorted
        assert_eq!(ranked[0].example_rip, 0x1000); // first seen
        assert_eq!(ranked[1].opcode, "0f 38 0x12");
        assert_eq!(ranked[2].opcode, "0x1a");
    }

    #[test]
    fn empty_input_ranks_empty() {
        assert!(rank(std::iter::empty()).is_empty());
    }
}

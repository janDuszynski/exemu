use std::fmt::Write;

use exemu_core::Region;

pub(crate) fn locate<'a>(regions: impl IntoIterator<Item = &'a Region>, addr: u64) -> String {
    let mut below: Option<&Region> = None;
    let mut above: Option<&Region> = None;
    for r in regions {
        if r.contains(addr) {
            return format!("in {} at offset {:#x}", describe(r), addr - r.base);
        }
        if r.end() <= addr && below.is_none_or(|b| r.end() > b.end()) {
            below = Some(r);
        }
        if r.base > addr && above.is_none_or(|a| r.base < a.base) {
            above = Some(r);
        }
    }
    let side = |r: Option<&Region>| r.map_or_else(|| "nothing".to_string(), describe);
    format!("unmapped, between {} and {}", side(below), side(above))
}

pub(crate) fn dump<'a>(regions: impl IntoIterator<Item = &'a Region>) -> String {
    let mut sorted: Vec<&Region> = regions.into_iter().collect();
    sorted.sort_by_key(|r| r.base);
    let mut o = format!("  memory map ({} regions):", sorted.len());
    for r in sorted {
        let _ = write!(o, "\n    {:#018x}..{:#018x}  {}", r.base, r.end(), r.name);
    }
    o
}

fn describe(r: &Region) -> String {
    format!("{:?} {:#x}+{:#x}", r.name, r.base, r.size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::Perm;

    fn map() -> Vec<Region> {
        vec![
            Region::new("heap", 0x40_0000, 0x10_0000, Perm::RW),
            Region::new("headers", 0x1000, 0x1000, Perm::READ),
            Region::new("thread-stack", 0x40_0003_0000, 0x10_0000, Perm::RW),
            Region::new("stack32", 0x18_0000, 0x2_0000, Perm::RW),
        ]
    }

    #[test]
    fn an_address_inside_a_region_names_it_and_the_offset() {
        assert_eq!(locate(&map(), 0x18_0010), "in \"stack32\" 0x180000+0x20000 at offset 0x10");
    }

    #[test]
    fn an_address_in_a_gap_names_the_nearest_region_on_each_side() {
        assert_eq!(
            locate(&map(), 0x12_fef4),
            "unmapped, between \"headers\" 0x1000+0x1000 and \"stack32\" 0x180000+0x20000"
        );
        assert_eq!(
            locate(&map(), 0x50_0000),
            "unmapped, between \"heap\" 0x400000+0x100000 and \"thread-stack\" 0x4000030000+0x100000"
        );
    }

    #[test]
    fn an_address_past_either_end_of_the_map_says_so() {
        assert_eq!(locate(&map(), 0x10), "unmapped, between nothing and \"headers\" 0x1000+0x1000");
        assert!(locate(&map(), u64::MAX).ends_with("and nothing"));
        assert_eq!(locate(&[], 0x1234), "unmapped, between nothing and nothing");
    }

    #[test]
    fn the_dump_lists_every_region_in_address_order() {
        let d = dump(&map());
        let names: Vec<&str> = d.lines().skip(1).filter_map(|l| l.split_whitespace().nth(1)).collect();
        assert_eq!(names, ["headers", "stack32", "heap", "thread-stack"]);
        assert!(d.starts_with("  memory map (4 regions):"));
    }
}

use exemu_core::debug::{DebugControl, WatchKind};
use exemu_core::{EmuError, Memory, Perm, Region};
use exemu_memory::VirtualMemory;

fn mem_with(debug: &DebugControl) -> VirtualMemory {
    let mut m = VirtualMemory::new();
    m.map(Region::new("data", 0x1000, 0x1000, Perm::RW)).unwrap();
    m.map(Region::new("code", 0x40_0000, 0x1000, Perm::RX)).unwrap();
    m.set_debug(debug.clone());
    m
}

fn rwx_with(debug: &DebugControl) -> VirtualMemory {
    let mut m = VirtualMemory::new();
    m.map(Region::new("data", 0x1000, 0x1000, Perm::RW)).unwrap();
    m.map(Region::new("code", 0x40_0000, 0x4000, Perm::RWX)).unwrap();
    m.set_debug(debug.clone());
    m
}

#[test]
fn a_guest_read_in_a_read_range_is_recorded() {
    let d = DebugControl::attached();
    d.arm_watch(0x1100, 8, WatchKind::Read);
    let mut m = mem_with(&d);
    m.write_u64(0x1100, 0x1122_3344_5566_7788).unwrap();
    assert_eq!(d.take_watch_hit(), None, "a write must not trip a Read watch");

    assert_eq!(m.read_u64(0x1100).unwrap(), 0x1122_3344_5566_7788);
    assert_eq!(d.take_watch_hit(), Some((0x1100, WatchKind::Read)));
    assert_eq!(d.take_watch_hit(), None);
}

#[test]
fn a_guest_write_in_a_write_range_is_recorded() {
    let d = DebugControl::attached();
    d.arm_watch(0x1200, 4, WatchKind::Write);
    let mut m = mem_with(&d);

    m.read_u32(0x1200).unwrap();
    assert_eq!(d.take_watch_hit(), None, "a read must not trip a Write watch");

    m.write_u32(0x1200, 0xdead_beef).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1200, WatchKind::Write)));
}

#[test]
fn a_readwrite_range_catches_both_directions() {
    let d = DebugControl::attached();
    d.arm_watch(0x1300, 16, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    m.write_u16(0x1304, 0xbeef).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1304, WatchKind::Write)));

    assert_eq!(m.read_u16(0x1304).unwrap(), 0xbeef);
    assert_eq!(d.take_watch_hit(), Some((0x1304, WatchKind::Read)));

    d.disarm_watch(0x1300);
    d.arm_watch(0x1300, 16, WatchKind::ReadWrite);
    m.write_u8(0x130f, 1).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x130f, WatchKind::Write)));
}

#[test]
fn the_recorded_address_is_the_accessed_address_not_the_range_base() {
    let d = DebugControl::attached();
    d.arm_watch(0x1400, 0x40, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    for off in [0u64, 1, 7, 0x3f] {
        m.write_u8(0x1400 + off, 0xAA).unwrap();
        assert_eq!(
            d.take_watch_hit(),
            Some((0x1400 + off, WatchKind::Write)),
            "offset {off:#x} must report where the guest pointed"
        );
    }
}

#[test]
fn an_access_straddling_a_range_boundary_is_recorded_at_its_own_address() {
    let d = DebugControl::attached();
    d.arm_watch(0x1500, 8, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    m.write_u32(0x14fe, 0x1111_2222).unwrap();
    assert_eq!(
        d.take_watch_hit(),
        Some((0x14fe, WatchKind::Write)),
        "an access starting below the base still hits, and reports its own address"
    );

    m.read_u32(0x14fe).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x14fe, WatchKind::Read)));

    m.write_u32(0x1506, 0x3333_4444).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1506, WatchKind::Write)));

    m.write(0x14ff, &[1, 2, 3, 4]).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x14ff, WatchKind::Write)));

    let mut buf = [0u8; 4];
    m.read(0x14ff, &mut buf).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x14ff, WatchKind::Read)));
}

#[test]
fn an_access_adjacent_to_but_outside_a_range_records_nothing() {
    let d = DebugControl::attached();
    d.arm_watch(0x1600, 8, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    m.write_u8(0x15ff, 1).unwrap();
    assert_eq!(d.take_watch_hit(), None, "one byte below the base misses");
    m.read_u8(0x15ff).unwrap();
    assert_eq!(d.take_watch_hit(), None);

    m.write_u32(0x15fc, 0).unwrap();
    assert_eq!(d.take_watch_hit(), None, "an access ending at the base misses");

    m.write_u8(0x1608, 1).unwrap();
    assert_eq!(d.take_watch_hit(), None, "one byte past the end misses");
    m.read_u8(0x1608).unwrap();
    assert_eq!(d.take_watch_hit(), None);

    m.write_u64(0x1a00, 0).unwrap();
    assert_eq!(d.take_watch_hit(), None);

    m.write_u8(0x1600, 1).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1600, WatchKind::Write)));
    m.write_u8(0x1607, 1).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1607, WatchKind::Write)));
}

#[test]
fn a_detached_handle_records_nothing_and_is_not_even_retained() {
    let d = DebugControl::detached();
    d.arm_watch(0x1100, 8, WatchKind::ReadWrite);
    let mut m = mem_with(&d);
    assert!(m.debug().is_none(), "a detached handle collapses to None");

    m.write_u64(0x1100, 0x42).unwrap();
    assert_eq!(m.read_u64(0x1100).unwrap(), 0x42);
    let mut buf = [0u8; 8];
    m.read(0x1100, &mut buf).unwrap();
    m.write(0x1100, &buf).unwrap();
    assert_eq!(d.take_watch_hit(), None);
    assert!(!d.any_watchpoints());
    assert_eq!(d.generation(), 0, "a detached handle never bumps its generation");
}

#[test]
fn memory_with_no_handle_at_all_behaves_identically() {
    let mut m = VirtualMemory::new();
    m.map(Region::new("data", 0x1000, 0x1000, Perm::RW)).unwrap();
    assert!(m.debug().is_none());
    m.write_u64(0x1100, 0x99).unwrap();
    assert_eq!(m.read_u64(0x1100).unwrap(), 0x99);
}

#[test]
fn an_attached_but_unarmed_handle_records_nothing() {
    let d = DebugControl::attached();
    let mut m = mem_with(&d);
    assert!(m.debug().is_some());
    assert!(!d.any_watchpoints(), "nothing armed");

    m.write_u32(0x1100, 7).unwrap();
    assert_eq!(m.read_u32(0x1100).unwrap(), 7);
    assert_eq!(d.take_watch_hit(), None);
}

#[test]
fn disarming_stops_the_recording() {
    let d = DebugControl::attached();
    d.arm_watch(0x1100, 8, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    m.write_u32(0x1100, 1).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1100, WatchKind::Write)));

    d.disarm_watch(0x1100);
    assert!(!d.any_watchpoints());
    m.write_u32(0x1100, 2).unwrap();
    m.read_u32(0x1100).unwrap();
    assert_eq!(d.take_watch_hit(), None, "a disarmed range is silent again");
}

#[test]
fn arming_mid_run_is_seen_by_the_next_access() {
    let d = DebugControl::attached();
    let mut m = mem_with(&d);
    m.write_u32(0x1100, 1).unwrap();
    assert_eq!(d.take_watch_hit(), None);

    d.arm_watch(0x1100, 4, WatchKind::Write);
    m.write_u32(0x1100, 2).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1100, WatchKind::Write)));
}

#[test]
fn instruction_fetch_is_not_a_watched_data_access() {
    let d = DebugControl::attached();
    d.arm_watch(0x40_0000, 0x100, WatchKind::ReadWrite);
    let m = mem_with(&d);

    let mut buf = [0u8; 4];
    m.fetch(0x40_0000, &mut buf).unwrap();
    assert_eq!(d.take_watch_hit(), None, "fetch is code, not data");

    m.read(0x40_0000, &mut buf).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x40_0000, WatchKind::Read)));
}

#[test]
fn the_loaders_privileged_poke_is_not_a_guest_write() {
    let d = DebugControl::attached();
    d.arm_watch(0x40_0000, 0x100, WatchKind::ReadWrite);
    let mut m = rwx_with(&d);

    m.poke(0x40_0010, &[0xcc, 0xcc]).unwrap();
    assert_eq!(d.take_watch_hit(), None, "an IAT fill is the host writing, not the guest");
    assert_eq!(m.code_generation(), 1);
}

#[test]
fn a_faulting_access_records_nothing() {
    let d = DebugControl::attached();
    d.arm_watch(0x40_0000, 0x10, WatchKind::ReadWrite);
    d.arm_watch(0x9999_0000, 0x10, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    assert!(matches!(m.write_u32(0x40_0000, 1), Err(EmuError::Permission { .. })));
    assert_eq!(d.take_watch_hit(), None, "a permission fault preempts the watchpoint");

    assert!(matches!(m.read_u32(0x9999_0000), Err(EmuError::Unmapped { .. })));
    assert!(matches!(m.write_u32(0x9999_0000, 1), Err(EmuError::Unmapped { .. })));
    assert_eq!(d.take_watch_hit(), None);

    d.arm_watch(0x1ffc, 8, WatchKind::ReadWrite);
    assert!(m.read_u64(0x1ffc).is_err());
    assert_eq!(d.take_watch_hit(), None);
}

#[test]
fn a_zero_length_access_records_nothing() {
    let d = DebugControl::attached();
    d.arm_watch(0x1100, 8, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    m.write(0x1100, &[]).unwrap();
    let empty: &mut [u8] = &mut [];
    m.read(0x1100, empty).unwrap();
    assert_eq!(d.take_watch_hit(), None);
}

#[test]
fn arming_a_watchpoint_does_not_move_the_self_modifying_code_counters() {
    let d = DebugControl::attached();
    let mut m = rwx_with(&d);
    assert_eq!((m.code_generation(), m.code_page_generation(0x40_0000)), (0, 0));

    d.arm_watch(0x40_0000, 0x1000, WatchKind::ReadWrite);
    d.arm_watch(0x1000, 0x100, WatchKind::Write);
    assert_eq!(m.code_generation(), 0, "arming is not a guest write");
    assert_eq!(m.code_page_generation(0x40_0000), 0);

    m.write_u32(0x40_0040, 0x9090_9090).unwrap();
    assert_eq!(m.code_generation(), 1);
    assert_eq!(m.code_page_generation(0x40_0000), 1);
    assert_eq!(d.take_watch_hit(), Some((0x40_0040, WatchKind::Write)));

    d.disarm_watch(0x40_0000);
    assert_eq!(m.code_generation(), 1, "disarming is not a guest write either");
}

#[test]
fn the_last_access_of_an_instruction_wins() {
    let d = DebugControl::attached();
    d.arm_watch(0x1100, 0x20, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    m.write_u32(0x1100, 1).unwrap();
    m.write_u32(0x1110, 2).unwrap();
    m.read_u32(0x1118).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1118, WatchKind::Read)));
    assert_eq!(d.take_watch_hit(), None);
}

#[test]
fn several_ranges_are_watched_at_once() {
    let d = DebugControl::attached();
    d.arm_watch(0x1000, 4, WatchKind::Read);
    d.arm_watch(0x1400, 4, WatchKind::Write);
    d.arm_watch(0x1800, 4, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    m.read_u32(0x1000).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1000, WatchKind::Read)));
    m.write_u32(0x1000, 0).unwrap();
    assert_eq!(d.take_watch_hit(), None, "the 0x1000 range is read-only");

    m.write_u32(0x1400, 0).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1400, WatchKind::Write)));
    m.read_u32(0x1400).unwrap();
    assert_eq!(d.take_watch_hit(), None, "the 0x1400 range is write-only");

    m.read_u32(0x1800).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1800, WatchKind::Read)));
    m.write_u32(0x1800, 0).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1800, WatchKind::Write)));
}

#[test]
fn every_access_width_and_both_slice_paths_report_the_same_address() {
    let d = DebugControl::attached();
    d.arm_watch(0x1000, 0x1000, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    for size in [1u8, 2, 4, 8] {
        m.write_uint(0x1100, size, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(d.take_watch_hit(), Some((0x1100, WatchKind::Write)), "write_uint {size}");
        m.read_uint(0x1100, size).unwrap();
        assert_eq!(d.take_watch_hit(), Some((0x1100, WatchKind::Read)), "read_uint {size}");
    }

    assert!(m.read_uint(0x1100, 3).is_err());
    assert!(m.write_uint(0x1100, 3, 0).is_err());
    assert_eq!(d.take_watch_hit(), None);

    m.write(0x1200, &[1, 2, 3, 4, 5]).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1200, WatchKind::Write)));
    let mut buf = [0u8; 5];
    m.read(0x1200, &mut buf).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1200, WatchKind::Read)));
    assert_eq!(buf, [1, 2, 3, 4, 5]);

    m.write(0x1300, b"hi\0").unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1300, WatchKind::Write)));
    assert_eq!(m.read_cstr(0x1300, 16).unwrap(), b"hi".to_vec());
    let (addr, kind) = d.take_watch_hit().expect("a C-string read is still a read");
    assert_eq!(kind, WatchKind::Read);
    assert!((0x1300..=0x1302).contains(&addr), "reported {addr:#x}");
}

#[test]
fn a_watchpoint_survives_the_region_lookup_cache_being_invalidated() {
    let d = DebugControl::attached();
    d.arm_watch(0x1100, 8, WatchKind::ReadWrite);
    let mut m = mem_with(&d);

    m.write_u64(0x1100, 1).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1100, WatchKind::Write)));

    m.map(Region::new("low", 0x100, 0x100, Perm::RW)).unwrap();
    m.write_u8(0x180, 0x5A).unwrap();
    assert_eq!(d.take_watch_hit(), None, "the new region is not watched");

    m.read_u64(0x1100).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x1100, WatchKind::Read)));
}

#[test]
fn a_watch_spanning_many_pages_still_reports_the_accessed_address() {
    let d = DebugControl::attached();
    let mut m = VirtualMemory::new();
    m.map(Region::new("big", 0x1_0000, 0x40_0000, Perm::RW)).unwrap();
    m.set_debug(d.clone());
    d.arm_watch(0x2_0000, 0x20_0000, WatchKind::Write);

    m.write_u8(0x2_0000, 1).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x2_0000, WatchKind::Write)));
    m.write_u8(0x2_0000 + 0x20_0000 - 1, 1).unwrap();
    assert_eq!(d.take_watch_hit(), Some((0x2_0000 + 0x20_0000 - 1, WatchKind::Write)));
    m.write_u8(0x2_0000 + 0x20_0000, 1).unwrap();
    assert_eq!(d.take_watch_hit(), None, "one past the end of a wide range still misses");
    m.write_u8(0x1_ffff, 1).unwrap();
    assert_eq!(d.take_watch_hit(), None, "one before the start of a wide range still misses");
}

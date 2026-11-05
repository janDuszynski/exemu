use exemu_core::{Memory, Result};

mod wndclassexw {
    pub(super) const STYLE: u64 = 0x04;
    pub(super) const WNDPROC: u64 = 0x08;
    pub(super) const CLS_EXTRA: u64 = 0x10;
    pub(super) const WND_EXTRA: u64 = 0x14;
    pub(super) const INSTANCE: u64 = 0x18;
    pub(super) const ICON: u64 = 0x20;
    pub(super) const CURSOR: u64 = 0x28;
    pub(super) const BACKGROUND: u64 = 0x30;
    pub(super) const MENU_NAME: u64 = 0x38;
    pub(super) const CLASS_NAME: u64 = 0x40;
    pub(super) const ICON_SM: u64 = 0x48;
}

mod client_menu_name {
    pub(super) const NAME_A: u64 = 0x00;
    pub(super) const NAME_W: u64 = 0x08;
    pub(super) const NAME_US: u64 = 0x10;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClientMenuName {
    pub(crate) name_a: u64,
    pub(crate) name_w: u64,
    pub(crate) name_us: u64,
}

impl ClientMenuName {
    pub(crate) fn read(mem: &dyn Memory, at: u64) -> Result<Self> {
        if at == 0 {
            return Ok(Self::default());
        }
        Ok(Self {
            name_a: mem.read_u64(at + client_menu_name::NAME_A)?,
            name_w: mem.read_u64(at + client_menu_name::NAME_W)?,
            name_us: mem.read_u64(at + client_menu_name::NAME_US)?,
        })
    }

    pub(crate) fn write(&self, mem: &mut dyn Memory, at: u64) -> Result<()> {
        mem.write_u64(at + client_menu_name::NAME_A, self.name_a)?;
        mem.write_u64(at + client_menu_name::NAME_W, self.name_w)?;
        mem.write_u64(at + client_menu_name::NAME_US, self.name_us)
    }

    pub(crate) fn for_charset(&self, ansi: bool) -> u64 {
        if ansi {
            self.name_a
        } else {
            self.name_w
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WndClassEx {
    pub(crate) style: u32,
    pub(crate) wndproc: u64,
    pub(crate) cls_extra: u32,
    pub(crate) wnd_extra: u32,
    pub(crate) instance: u64,
    pub(crate) icon: u64,
    pub(crate) cursor: u64,
    pub(crate) background: u64,
    pub(crate) menu_name: u64,
    pub(crate) class_name: u64,
    pub(crate) icon_sm: u64,
}

impl WndClassEx {
    pub(crate) fn read(mem: &dyn Memory, at: u64) -> Result<Self> {
        Ok(Self {
            style: mem.read_u32(at + wndclassexw::STYLE)?,
            wndproc: mem.read_u64(at + wndclassexw::WNDPROC)?,
            cls_extra: mem.read_u32(at + wndclassexw::CLS_EXTRA)?,
            wnd_extra: mem.read_u32(at + wndclassexw::WND_EXTRA)?,
            instance: mem.read_u64(at + wndclassexw::INSTANCE)?,
            icon: mem.read_u64(at + wndclassexw::ICON)?,
            cursor: mem.read_u64(at + wndclassexw::CURSOR)?,
            background: mem.read_u64(at + wndclassexw::BACKGROUND)?,
            menu_name: mem.read_u64(at + wndclassexw::MENU_NAME)?,
            class_name: mem.read_u64(at + wndclassexw::CLASS_NAME)?,
            icon_sm: mem.read_u64(at + wndclassexw::ICON_SM)?,
        })
    }

    pub(crate) fn write(&self, mem: &mut dyn Memory, at: u64) -> Result<()> {
        mem.write_u32(at + wndclassexw::STYLE, self.style)?;
        mem.write_u64(at + wndclassexw::WNDPROC, self.wndproc)?;
        mem.write_u32(at + wndclassexw::CLS_EXTRA, self.cls_extra)?;
        mem.write_u32(at + wndclassexw::WND_EXTRA, self.wnd_extra)?;
        mem.write_u64(at + wndclassexw::INSTANCE, self.instance)?;
        mem.write_u64(at + wndclassexw::ICON, self.icon)?;
        mem.write_u64(at + wndclassexw::CURSOR, self.cursor)?;
        mem.write_u64(at + wndclassexw::BACKGROUND, self.background)?;
        mem.write_u64(at + wndclassexw::MENU_NAME, self.menu_name)?;
        mem.write_u64(at + wndclassexw::CLASS_NAME, self.class_name)?;
        mem.write_u64(at + wndclassexw::ICON_SM, self.icon_sm)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClassClient {
    pub(crate) cls_extra: u32,
    pub(crate) instance: u64,
    pub(crate) icon: u64,
    pub(crate) cursor: u64,
    pub(crate) icon_sm: u64,
    pub(crate) menu_name: ClientMenuName,
}

impl ClassClient {
    pub(crate) fn registered(wc: &WndClassEx, menu_name: ClientMenuName) -> Self {
        Self {
            cls_extra: wc.cls_extra,
            instance: wc.instance,
            icon: wc.icon,
            cursor: wc.cursor,
            icon_sm: wc.icon_sm,
            menu_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::{Perm, Region};
    use exemu_memory::VirtualMemory;

    #[test]
    fn a_wndclassexw_round_trips_through_its_64bit_layout() {
        let mut mem = VirtualMemory::new();
        mem.map(Region::new("wc", 0x1_0000, 0x1000, Perm::RW)).unwrap();
        mem.write(0x1_0000, &[0xA5; 0x50]).unwrap();
        let wc = WndClassEx {
            style: 0x0b,
            wndproc: 0x0040_1005,
            cls_extra: 8,
            wnd_extra: 16,
            instance: 0x0040_0000,
            icon: 0x0001_0042,
            cursor: 0x0001_0043,
            background: 6,
            menu_name: 0x77,
            class_name: 0x0040_2000,
            icon_sm: 0x0001_0044,
        };
        wc.write(&mut mem, 0x1_0000).unwrap();
        assert_eq!(WndClassEx::read(&mem, 0x1_0000).unwrap(), wc);
        assert_eq!(mem.read_u32(0x1_0000).unwrap(), 0xA5A5_A5A5, "cbSize belongs to the caller");
        assert_eq!(mem.read_u64(0x1_0000 + 0x38).unwrap(), 0x77, "lpszMenuName is at 0x38");
        assert_eq!(mem.read_u64(0x1_0000 + 0x48).unwrap(), 0x0001_0044, "hIconSm is the last field");
    }

    #[test]
    fn a_client_menu_name_answers_the_charset_it_is_asked_for() {
        let m = ClientMenuName { name_a: 0x10, name_w: 0x20, name_us: 0x30 };
        assert_eq!(m.for_charset(true), 0x10);
        assert_eq!(m.for_charset(false), 0x20);
        let mem = VirtualMemory::new();
        assert_eq!(ClientMenuName::read(&mem, 0).unwrap(), ClientMenuName::default(), "a NULL menu name is none");
    }
}

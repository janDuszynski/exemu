//! The domain model of a loaded PE image.
//!
//! This is deliberately a *parsed*, byte-order-neutral representation — not
//! the on-disk headers. The `exemu-loader` crate turns raw file bytes into
//! one of these; the `app` layer maps it into [`crate::Memory`]. Nothing
//! here knows how the bytes were read or where they will be mapped.

/// A section to be mapped into the guest address space.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    /// Relative virtual address (offset from the image base).
    pub rva: u32,
    /// Size the section occupies in memory (may exceed `data.len()`; the
    /// remainder is zero-filled, e.g. `.bss`).
    pub virtual_size: u32,
    /// The initialized bytes from the file (already trimmed/padded to
    /// `SizeOfRawData`).
    pub data: Vec<u8>,
    /// Whether the section is readable/writable/executable, as three bools
    /// derived from the section characteristics.
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// How an imported symbol is identified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSymbol {
    /// Imported by name (the common case).
    Named(String),
    /// Imported by ordinal number.
    Ordinal(u16),
}

/// A single entry in a module's import table.
#[derive(Debug, Clone)]
pub struct Import {
    /// The DLL the symbol comes from, lower-cased (e.g. `"kernel32.dll"`).
    pub dll: String,
    pub symbol: ImportSymbol,
    /// RVA of the Import Address Table slot that must be filled with the
    /// resolved function address.
    pub iat_rva: u32,
}

/// A fully parsed PE image, ready to be mapped and run.
#[derive(Debug, Clone)]
pub struct PeImage {
    /// True for PE32+ (x86-64), false for PE32 (32-bit x86).
    pub is_64bit: bool,
    /// Preferred load address from the optional header.
    pub image_base: u64,
    /// Entry point as an RVA (add `image_base` for the virtual address).
    pub entry_rva: u32,
    /// Total virtual size of the image, page-aligned.
    pub size_of_image: u32,
    /// Size of all headers, used to map the header page.
    pub size_of_headers: u32,
    /// Windows subsystem (2 = GUI, 3 = console).
    pub subsystem: u16,
    /// Amount of stack the image asks the loader to reserve.
    pub stack_reserve: u64,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    /// The raw header bytes, mapped read-only at the image base so guests
    /// that walk their own headers (via the PEB) see something sane.
    pub headers: Vec<u8>,
}

impl PeImage {
    /// Virtual address of the entry point.
    #[inline]
    pub fn entry_va(&self) -> u64 {
        self.image_base + self.entry_rva as u64
    }
}

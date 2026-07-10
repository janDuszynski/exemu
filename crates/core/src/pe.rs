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

/// A single exported symbol from a module's export directory.
#[derive(Debug, Clone)]
pub struct Export {
    /// The export name, if the symbol is exported by name.
    pub name: Option<String>,
    /// The export ordinal (biased by the directory's ordinal base).
    pub ordinal: u16,
    /// RVA of the exported function/variable within the module. Meaningless
    /// (points inside the export directory) when this is a forwarder — see
    /// [`Export::forwarder`].
    pub rva: u32,
    /// A forwarder target string when this export re-exports a symbol from
    /// another module. Per the PE/COFF spec, an export whose address RVA lands
    /// *inside* the export directory is not code — it is an ASCIIZ string of
    /// the form `"OTHERDLL.FuncName"` or `"OTHERDLL.#Ordinal"`. Resolving the
    /// export means loading that other module and looking the target up there
    /// (recursively, since a forwarder may point at another forwarder).
    pub forwarder: Option<String>,
}

/// The parsed thread-local-storage directory (`IMAGE_TLS_DIRECTORY`).
///
/// This is the load-time TLS support described by the PE/COFF spec's `.tls`
/// section: an initialization template, the location where the loader writes
/// the allocated TLS index, and a null-terminated array of per-thread
/// initialization/termination callbacks.
///
/// The four address fields on disk are **virtual addresses** (`image_base +
/// rva`), not RVAs — the linker bakes in the preferred base, so they are
/// subject to base relocations. They are stored here exactly as they appear
/// in the image; callers that need an RVA subtract the (possibly relocated)
/// image base. The callback list, however, has already been walked and each
/// entry converted to an RVA relative to `image_base` for the caller's
/// convenience.
#[derive(Debug, Clone)]
pub struct Tls {
    /// VA of the start of the TLS initialization template
    /// (`StartAddressOfRawData`).
    pub start_address_of_raw_data: u64,
    /// VA of the end of the TLS initialization template
    /// (`EndAddressOfRawData`). The template is `[start, end)`.
    pub end_address_of_raw_data: u64,
    /// VA of the `DWORD` slot where the loader stores the allocated TLS index
    /// (`AddressOfIndex`).
    pub address_of_index: u64,
    /// VA of the null-terminated array of callback pointers
    /// (`AddressOfCallBacks`). Zero if there are no callbacks.
    pub address_of_callbacks: u64,
    /// Number of extra zero-filled bytes appended to the template
    /// (`SizeOfZeroFill`).
    pub size_of_zero_fill: u32,
    /// Reserved characteristics flags (`Characteristics`), including the
    /// alignment field in the high bits.
    pub characteristics: u32,
    /// The raw TLS template bytes copied from `[start, end)`, ready to be
    /// duplicated per thread. Empty if the template is empty or unreadable.
    pub raw_template: Vec<u8>,
    /// Each TLS callback as an RVA relative to `image_base` (the null
    /// terminator is dropped). Empty if `address_of_callbacks` is zero.
    pub callback_rvas: Vec<u32>,
}

/// A base-relocation fixup: apply the load delta to the value at `rva`.
#[derive(Debug, Clone, Copy)]
pub struct Reloc {
    pub rva: u32,
    /// IMAGE_REL_BASED_* type (3 = HIGHLOW/32-bit, 10 = DIR64/64-bit).
    pub kind: u8,
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
    /// Exported symbols (populated for DLLs; usually empty for exes).
    pub exports: Vec<Export>,
    /// Base relocations, used to load a DLL away from its preferred base.
    pub relocations: Vec<Reloc>,
    /// The parsed thread-local-storage directory, if the image has one.
    pub tls: Option<Tls>,
    /// The module's own name from the export directory, if present.
    pub dll_name: Option<String>,
    /// The raw header bytes, mapped read-only at the image base so guests
    /// that walk their own headers (via the PEB) see something sane.
    pub headers: Vec<u8>,
    /// The x64 exception function table (`.pdata`/`.xdata`), sorted by
    /// `begin_rva`. Empty for 32-bit images (x86 uses the `fs:[0]` SEH chain)
    /// and for images without an exception directory.
    pub function_table: Vec<crate::unwind::UnwindEntry>,
}

impl PeImage {
    /// Virtual address of the entry point.
    #[inline]
    pub fn entry_va(&self) -> u64 {
        self.image_base + self.entry_rva as u64
    }

    /// The unwind entry covering the given RVA, if any — the emulator-side
    /// equivalent of `RtlLookupFunctionEntry`.
    pub fn find_unwind(&self, rva: u32) -> Option<&crate::unwind::UnwindEntry> {
        crate::unwind::lookup(&self.function_table, rva)
    }
}

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

// ---------------------------------------------------------------------------
// SxS / activation-context types (W0.8)
// ---------------------------------------------------------------------------

/// Identity fields from an `<assemblyIdentity>` element in an application
/// manifest. All fields are taken verbatim from the XML attributes; unknown
/// attributes are ignored. Absent optional attributes are left empty or `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssemblyIdentity {
    /// `name` attribute — the assembly's logical name, e.g.
    /// `"7-Zip.7-Zip.7zipInstall"` or `"Microsoft.Windows.Common-Controls"`.
    pub name: String,
    /// `version` attribute — four-part dotted string, e.g. `"6.0.0.0"`.
    pub version: String,
    /// `type` attribute — nearly always `"win32"`.
    pub type_: String,
    /// `processorArchitecture` — `"x86"`, `"amd64"`, `"*"`, etc.
    pub processor_architecture: String,
    /// `publicKeyToken` — hex string identifying the publisher; absent for
    /// private assemblies (most exe identities).
    pub public_key_token: Option<String>,
    /// `language` — locale or `"*"` for language-neutral.
    pub language: Option<String>,
}

/// The parsed information from an application (or DLL) manifest. Derived from
/// either the embedded `RT_MANIFEST` resource or a side-by-side `.manifest`
/// file. This is the minimum needed to seed an activation context the OS layer
/// can answer queries against (real consumers arrive with Wine ntdll in W3).
#[derive(Debug, Clone)]
pub struct ManifestInfo {
    /// The identity declared by the `<assemblyIdentity>` element at the top
    /// level of the manifest (the *this* assembly).
    pub identity: AssemblyIdentity,
    /// All `<assemblyIdentity>` elements found inside `<dependentAssembly>`
    /// elements — the assemblies this image requires. For most Windows apps the
    /// only interesting entry is the `Microsoft.Windows.Common-Controls`
    /// dependency that gates comctl32 v6 themed controls.
    pub dependencies: Vec<AssemblyIdentity>,
}

/// A minimal activation context, seeded from the parsed manifest. The query
/// surface is stubbed (real consumers arrive in W3 when Wine's ntdll calls
/// `RtlQueryActivationContextApplicationSettings` et al.). Its purpose here
/// is to hold the parsed identity/dependency information so later phases do
/// not need to re-parse the manifest.
///
/// Per the Windows SxS design, an executable has exactly one default
/// activation context (the "process default"); its contents determine which
/// side-by-side assembly versions are activated — most importantly whether
/// comctl32 v6 (themed controls) is enabled.
#[derive(Debug, Clone)]
pub struct ActivationContext {
    /// The manifest that seeded this context.
    pub manifest: ManifestInfo,
    /// True when the manifest declares a dependency on
    /// `Microsoft.Windows.Common-Controls` version `6.*`. This is the flag
    /// later phases check to decide whether comctl32 v6 is in effect.
    pub comctl32_v6: bool,
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
    /// The activation context seeded from the image's embedded `RT_MANIFEST`
    /// resource (resource ID 1 for executables, ID 2 for DLLs) or, if absent,
    /// from the external `<exe>.manifest` sidecar file. `None` if no manifest
    /// was found or if the manifest contained no usable identity.
    pub activation_context: Option<ActivationContext>,
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

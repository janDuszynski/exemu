#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub data: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSymbol {
    Named(String),
    Ordinal(u16),
}

#[derive(Debug, Clone)]
pub struct Import {
    pub dll: String,
    pub symbol: ImportSymbol,
    pub iat_rva: u32,
}

#[derive(Debug, Clone)]
pub struct Export {
    pub name: Option<String>,
    pub ordinal: u16,
    pub rva: u32,
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Tls {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub raw_template: Vec<u8>,
    pub callback_rvas: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct Reloc {
    pub rva: u32,
    pub kind: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssemblyIdentity {
    pub name: String,
    pub version: String,
    pub type_: String,
    pub processor_architecture: String,
    pub public_key_token: Option<String>,
    pub language: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ManifestInfo {
    pub identity: AssemblyIdentity,
    pub dependencies: Vec<AssemblyIdentity>,
}

#[derive(Debug, Clone)]
pub struct ActivationContext {
    pub manifest: ManifestInfo,
    pub comctl32_v6: bool,
}

#[derive(Debug, Clone)]
pub struct PeImage {
    pub is_64bit: bool,
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub stack_reserve: u64,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Reloc>,
    pub tls: Option<Tls>,
    pub dll_name: Option<String>,
    pub headers: Vec<u8>,
    pub function_table: Vec<crate::unwind::UnwindEntry>,
    pub activation_context: Option<ActivationContext>,
}

impl PeImage {
    #[inline]
    pub fn entry_va(&self) -> u64 {
        self.image_base + self.entry_rva as u64
    }

    pub fn find_unwind(&self, rva: u32) -> Option<&crate::unwind::UnwindEntry> {
        crate::unwind::lookup(&self.function_table, rva)
    }
}

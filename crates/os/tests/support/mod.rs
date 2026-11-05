use exemu_core::{ImageLoader, ImportSymbol, ModuleExports, PeImage, Reloc, Result, Section};

pub struct LoaderImages;

impl ImageLoader for LoaderImages {
    fn parse(&self, bytes: &[u8]) -> Result<PeImage> {
        exemu_loader::parse(bytes)
    }

    fn apply_relocations(
        &self,
        sections: &mut [Section],
        relocations: &[Reloc],
        preferred_base: u64,
        actual_base: u64,
    ) -> Result<()> {
        exemu_loader::apply_relocations(sections, relocations, preferred_base, actual_base)
    }

    fn api_set_host(&self, name: &str) -> Option<&'static str> {
        exemu_loader::resolve_api_set(name)
    }

    fn resolve_export(
        &self,
        modules: &dyn ModuleExports,
        dll: &str,
        symbol: &ImportSymbol,
    ) -> Option<u64> {
        match exemu_loader::resolve_import(&Modules(modules), dll, symbol) {
            exemu_loader::Resolved::GuestCode(addr) => Some(addr),
            exemu_loader::Resolved::Fallback => None,
        }
    }
}

struct Modules<'a>(&'a dyn ModuleExports);

impl exemu_loader::ModuleSet for Modules<'_> {
    fn module(&self, dll: &str) -> Option<exemu_loader::LoadedModule<'_>> {
        let (base, exports) = self.0.module_exports(dll)?;
        Some(exemu_loader::LoadedModule { base, exports })
    }
}

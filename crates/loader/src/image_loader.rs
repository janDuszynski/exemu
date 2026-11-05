use exemu_core::{ImageLoader, ImportSymbol, ModuleExports, PeImage, Reloc, Result, Section};

use crate::resolve::{LoadedModule, ModuleSet, Resolved};

pub struct PeImageLoader;

impl ImageLoader for PeImageLoader {
    fn parse(&self, bytes: &[u8]) -> Result<PeImage> {
        crate::parse(bytes)
    }

    fn apply_relocations(
        &self,
        sections: &mut [Section],
        relocations: &[Reloc],
        preferred_base: u64,
        actual_base: u64,
    ) -> Result<()> {
        crate::reloc::apply(sections, relocations, preferred_base, actual_base)
    }

    fn api_set_host(&self, name: &str) -> Option<&'static str> {
        crate::api_set::resolve(name)
    }

    fn resolve_export(
        &self,
        modules: &dyn ModuleExports,
        dll: &str,
        symbol: &ImportSymbol,
    ) -> Option<u64> {
        match crate::resolve::resolve(&Modules(modules), dll, symbol) {
            Resolved::GuestCode(addr) => Some(addr),
            Resolved::Fallback => None,
        }
    }
}

struct Modules<'a>(&'a dyn ModuleExports);

impl ModuleSet for Modules<'_> {
    fn module(&self, dll: &str) -> Option<LoadedModule<'_>> {
        let (base, exports) = self.0.module_exports(dll)?;
        Some(LoadedModule { base, exports })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exemu_core::Export;

    struct FakeModules(Vec<(&'static str, u64, Vec<Export>)>);

    impl ModuleExports for FakeModules {
        fn module_exports(&self, dll: &str) -> Option<(u64, &[Export])> {
            let (_, base, exports) = self.0.iter().find(|(name, _, _)| *name == dll)?;
            Some((*base, exports.as_slice()))
        }
    }

    fn export(name: &str, rva: u32, forwarder: Option<&str>) -> Export {
        Export { name: Some(name.into()), ordinal: 1, rva, forwarder: forwarder.map(Into::into) }
    }

    #[test]
    fn a_forwarded_export_resolves_to_the_target_modules_code() {
        let modules = FakeModules(vec![
            ("kernel32.dll", 0x1000_0000, vec![export("HeapAlloc", 0x10, Some("ntdll.RtlAllocateHeap"))]),
            ("ntdll.dll", 0x2000_0000, vec![export("RtlAllocateHeap", 0x1234, None)]),
        ]);
        let forwarded = ImportSymbol::Named("HeapAlloc".into());
        assert_eq!(PeImageLoader.resolve_export(&modules, "kernel32.dll", &forwarded), Some(0x2000_1234));
        let missing = ImportSymbol::Named("HeapFree".into());
        assert_eq!(PeImageLoader.resolve_export(&modules, "kernel32.dll", &missing), None);
    }

    #[test]
    fn an_api_set_contract_names_its_host_dll() {
        assert_eq!(PeImageLoader.api_set_host("api-ms-win-crt-runtime-l1-1-0.dll"), Some("ucrtbase"));
        assert_eq!(PeImageLoader.api_set_host("kernel32.dll"), None);
    }
}

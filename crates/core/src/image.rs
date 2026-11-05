use crate::error::{EmuError, Result};
use crate::pe::{Export, ImportSymbol, PeImage, Reloc, Section};

pub trait ModuleExports {
    fn module_exports(&self, dll: &str) -> Option<(u64, &[Export])>;
}

pub trait ImageLoader {
    fn parse(&self, bytes: &[u8]) -> Result<PeImage>;

    fn apply_relocations(
        &self,
        sections: &mut [Section],
        relocations: &[Reloc],
        preferred_base: u64,
        actual_base: u64,
    ) -> Result<()>;

    fn api_set_host(&self, name: &str) -> Option<&'static str>;

    fn resolve_export(
        &self,
        modules: &dyn ModuleExports,
        dll: &str,
        symbol: &ImportSymbol,
    ) -> Option<u64>;
}

pub struct NoImageLoader;

impl ImageLoader for NoImageLoader {
    fn parse(&self, _bytes: &[u8]) -> Result<PeImage> {
        Err(EmuError::Unsupported("no PE image loader is wired in".into()))
    }

    fn apply_relocations(
        &self,
        _sections: &mut [Section],
        _relocations: &[Reloc],
        _preferred_base: u64,
        _actual_base: u64,
    ) -> Result<()> {
        Err(EmuError::Unsupported("no PE image loader is wired in".into()))
    }

    fn api_set_host(&self, _name: &str) -> Option<&'static str> {
        None
    }

    fn resolve_export(
        &self,
        _modules: &dyn ModuleExports,
        _dll: &str,
        _symbol: &ImportSymbol,
    ) -> Option<u64> {
        None
    }
}

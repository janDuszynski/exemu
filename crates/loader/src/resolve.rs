//! Import resolution across a set of co-loaded guest modules.
//!
//! Static and delay-load imports name a `(DLL, symbol)` pair. When the target
//! DLL is itself a loaded guest image (another PE mapped into the address
//! space), the import must resolve to the **real code address of that export**
//! — not to an OS thunk — so the two images call each other's actual code.
//!
//! The wrinkle is **forwarders**: an export whose address RVA lands inside its
//! module's export directory is not code but an ASCIIZ string `"OTHER.Sym"`
//! (or `"OTHER.#Ordinal"`). Resolving it means re-resolving `Sym` in `OTHER` —
//! which may itself be a forwarder, so the walk recurses. A forwarder chain
//! can (in a malformed image) loop; the walk is therefore cycle-guarded by a
//! bounded hop count so a corrupt table can never wedge the loader.
//!
//! This module is pure: it knows nothing about how modules were mapped or how
//! OS thunks are minted. The caller supplies a [`ModuleSet`] view and a
//! fallback for symbols whose target DLL is not a loaded guest image.

use exemu_core::{Export, ImportSymbol};

/// A single loaded guest module the resolver can look symbols up in.
pub struct LoadedModule<'a> {
    /// Where the image is mapped (its actual, possibly relocated, base).
    pub base: u64,
    /// The module's export table.
    pub exports: &'a [Export],
}

impl LoadedModule<'_> {
    /// Find the export matching `symbol` (by name or by ordinal).
    fn find(&self, symbol: &ImportSymbol) -> Option<&Export> {
        match symbol {
            ImportSymbol::Named(name) => {
                self.exports.iter().find(|e| e.name.as_deref() == Some(name.as_str()))
            }
            ImportSymbol::Ordinal(ord) => self.exports.iter().find(|e| e.ordinal == *ord),
        }
    }
}

/// The set of currently-loaded guest modules, keyed by lower-cased base name
/// (e.g. `"a.dll"`). Implemented by the OS loader over its live module map.
pub trait ModuleSet {
    /// The loaded module with the given lower-cased base name, if any.
    fn module(&self, dll: &str) -> Option<LoadedModule<'_>>;
}

/// The result of resolving one imported symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// The symbol is a real export of a co-loaded guest module; this is its
    /// absolute code address (`module_base + export_rva`).
    GuestCode(u64),
    /// The target DLL is not a loaded guest image (an emulated system DLL, or
    /// simply not present). The caller should fall back to an OS thunk.
    Fallback,
}

/// Maximum forwarder hops before giving up (cycle / corruption guard). A real
/// chain is one or two hops (`kernel32.foo → ntdll.bar`); anything deeper is a
/// malformed or looping table.
const MAX_FORWARDER_HOPS: usize = 16;

/// Resolve `(dll, symbol)` against `modules`, chasing forwarders.
///
/// Returns [`Resolved::GuestCode`] with the export's absolute address when the
/// target DLL is a loaded guest module and the symbol resolves (through any
/// number of forwarder hops) to real code there. Returns [`Resolved::Fallback`]
/// when the (final) target DLL is not a loaded guest image, or the symbol is
/// missing, or a forwarder chain loops / exceeds [`MAX_FORWARDER_HOPS`].
pub fn resolve(modules: &dyn ModuleSet, dll: &str, symbol: &ImportSymbol) -> Resolved {
    let mut cur_dll = normalize_dll(dll);
    let mut cur_symbol = symbol.clone();

    for _ in 0..MAX_FORWARDER_HOPS {
        let Some(module) = modules.module(&cur_dll) else {
            // Target DLL isn't a loaded guest image — fall back to a thunk.
            return Resolved::Fallback;
        };
        let Some(export) = module.find(&cur_symbol) else {
            // Named/ordinal export not present in the module.
            return Resolved::Fallback;
        };
        match &export.forwarder {
            None => return Resolved::GuestCode(module.base + export.rva as u64),
            Some(target) => {
                // Re-point at the forwarder's `OTHER.Sym` target and loop.
                let Some((next_dll, next_symbol)) = parse_forwarder(target) else {
                    return Resolved::Fallback;
                };
                cur_dll = next_dll;
                cur_symbol = next_symbol;
            }
        }
    }

    // Hop budget exhausted → treat as unresolvable (cycle guard).
    Resolved::Fallback
}

/// Normalize a DLL name for the module map: lower-case and ensure a `.dll`
/// extension (forwarder strings and import descriptors both omit it sometimes).
fn normalize_dll(dll: &str) -> String {
    let mut n = dll.to_ascii_lowercase();
    if !n.contains('.') {
        n.push_str(".dll");
    }
    n
}

/// Split a forwarder string `"DLL.Symbol"` into its target module and symbol.
/// The symbol is by-ordinal when it begins with `#` (`"DLL.#42"`), else
/// by-name. The DLL part is normalized (lower-cased, `.dll` ensured). Returns
/// `None` if the string has no `.` separator or an unparsable ordinal.
fn parse_forwarder(s: &str) -> Option<(String, ImportSymbol)> {
    // Split on the *last* '.' so a dotted DLL name still works: the target is
    // the trailing symbol token. e.g. "NTDLL.RtlbAr" or "api-ms-...-l1-1-0.foo"
    // — Windows forwarders name a bare DLL then ".Symbol", and the symbol
    // itself never contains a '.'.
    let dot = s.rfind('.')?;
    let (dll_part, sym_part) = s.split_at(dot);
    let sym_part = &sym_part[1..]; // drop the '.'
    if dll_part.is_empty() || sym_part.is_empty() {
        return None;
    }
    let dll = normalize_dll(dll_part);
    let symbol = if let Some(ord) = sym_part.strip_prefix('#') {
        ImportSymbol::Ordinal(ord.parse::<u16>().ok()?)
    } else {
        ImportSymbol::Named(sym_part.to_string())
    };
    Some((dll, symbol))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A trivial in-memory module set for tests.
    struct Modules {
        map: HashMap<String, (u64, Vec<Export>)>,
    }
    impl ModuleSet for Modules {
        fn module(&self, dll: &str) -> Option<LoadedModule<'_>> {
            self.map.get(dll).map(|(base, exports)| LoadedModule { base: *base, exports })
        }
    }

    fn named(name: &str, ordinal: u16, rva: u32) -> Export {
        Export { name: Some(name.into()), ordinal, rva, forwarder: None }
    }
    fn forward(name: &str, ordinal: u16, target: &str) -> Export {
        Export { name: Some(name.into()), ordinal, rva: 0, forwarder: Some(target.into()) }
    }

    #[test]
    fn direct_export_resolves_to_guest_code() {
        let mut map = HashMap::new();
        map.insert("a.dll".to_string(), (0x1000_0000u64, vec![named("f", 1, 0x1234)]));
        let modules = Modules { map };
        let r = resolve(&modules, "a.dll", &ImportSymbol::Named("f".into()));
        assert_eq!(r, Resolved::GuestCode(0x1000_0000 + 0x1234));
    }

    #[test]
    fn ordinal_export_resolves() {
        let mut map = HashMap::new();
        map.insert("a.dll".to_string(), (0x2000_0000u64, vec![named("f", 7, 0x40)]));
        let modules = Modules { map };
        let r = resolve(&modules, "a", &ImportSymbol::Ordinal(7));
        assert_eq!(r, Resolved::GuestCode(0x2000_0000 + 0x40));
    }

    #[test]
    fn forwarder_chases_to_the_real_module() {
        // b.g forwards to a.f. Importing b.g must land on a's real code.
        let mut map = HashMap::new();
        map.insert("a.dll".to_string(), (0x1000_0000u64, vec![named("f", 1, 0x1234)]));
        map.insert("b.dll".to_string(), (0x3000_0000u64, vec![forward("g", 1, "A.f")]));
        let modules = Modules { map };
        let r = resolve(&modules, "b.dll", &ImportSymbol::Named("g".into()));
        assert_eq!(r, Resolved::GuestCode(0x1000_0000 + 0x1234));
    }

    #[test]
    fn forwarder_by_ordinal_target() {
        let mut map = HashMap::new();
        map.insert("a.dll".to_string(), (0x1000_0000u64, vec![named("f", 42, 0x99)]));
        map.insert("b.dll".to_string(), (0x3000_0000u64, vec![forward("g", 1, "a.#42")]));
        let modules = Modules { map };
        let r = resolve(&modules, "b.dll", &ImportSymbol::Named("g".into()));
        assert_eq!(r, Resolved::GuestCode(0x1000_0000 + 0x99));
    }

    #[test]
    fn multi_hop_forwarder_chain() {
        // c.h → b.g → a.f
        let mut map = HashMap::new();
        map.insert("a.dll".to_string(), (0x1000_0000u64, vec![named("f", 1, 0x10)]));
        map.insert("b.dll".to_string(), (0x2000_0000u64, vec![forward("g", 1, "a.f")]));
        map.insert("c.dll".to_string(), (0x3000_0000u64, vec![forward("h", 1, "b.g")]));
        let modules = Modules { map };
        let r = resolve(&modules, "c.dll", &ImportSymbol::Named("h".into()));
        assert_eq!(r, Resolved::GuestCode(0x1000_0000 + 0x10));
    }

    #[test]
    fn forwarder_to_unloaded_module_falls_back() {
        // b.g forwards to ntdll.bar, which isn't a loaded guest image.
        let mut map = HashMap::new();
        map.insert("b.dll".to_string(), (0x3000_0000u64, vec![forward("g", 1, "ntdll.bar")]));
        let modules = Modules { map };
        let r = resolve(&modules, "b.dll", &ImportSymbol::Named("g".into()));
        assert_eq!(r, Resolved::Fallback);
    }

    #[test]
    fn unloaded_target_dll_falls_back() {
        let modules = Modules { map: HashMap::new() };
        let r = resolve(&modules, "kernel32.dll", &ImportSymbol::Named("ExitProcess".into()));
        assert_eq!(r, Resolved::Fallback);
    }

    #[test]
    fn missing_export_falls_back() {
        let mut map = HashMap::new();
        map.insert("a.dll".to_string(), (0x1000_0000u64, vec![named("f", 1, 0x10)]));
        let modules = Modules { map };
        let r = resolve(&modules, "a.dll", &ImportSymbol::Named("nope".into()));
        assert_eq!(r, Resolved::Fallback);
    }

    #[test]
    fn cyclic_forwarders_are_guarded() {
        // a.f → b.g → a.f → … must terminate as Fallback, not loop forever.
        let mut map = HashMap::new();
        map.insert("a.dll".to_string(), (0x1000_0000u64, vec![forward("f", 1, "b.g")]));
        map.insert("b.dll".to_string(), (0x2000_0000u64, vec![forward("g", 1, "a.f")]));
        let modules = Modules { map };
        let r = resolve(&modules, "a.dll", &ImportSymbol::Named("f".into()));
        assert_eq!(r, Resolved::Fallback);
    }

    #[test]
    fn malformed_forwarder_without_dot_falls_back() {
        let mut map = HashMap::new();
        map.insert("b.dll".to_string(), (0x3000_0000u64, vec![forward("g", 1, "nodot")]));
        let modules = Modules { map };
        let r = resolve(&modules, "b.dll", &ImportSymbol::Named("g".into()));
        assert_eq!(r, Resolved::Fallback);
    }
}

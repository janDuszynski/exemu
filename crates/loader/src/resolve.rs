use exemu_core::{Export, ImportSymbol};

pub struct LoadedModule<'a> {
    pub base: u64,
    pub exports: &'a [Export],
}

impl LoadedModule<'_> {
    fn find(&self, symbol: &ImportSymbol) -> Option<&Export> {
        match symbol {
            ImportSymbol::Named(name) => {
                self.exports.iter().find(|e| e.name.as_deref() == Some(name.as_str()))
            }
            ImportSymbol::Ordinal(ord) => self.exports.iter().find(|e| e.ordinal == *ord),
        }
    }
}

pub trait ModuleSet {
    fn module(&self, dll: &str) -> Option<LoadedModule<'_>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    GuestCode(u64),
    Fallback,
}

const MAX_FORWARDER_HOPS: usize = 16;

pub fn resolve(modules: &dyn ModuleSet, dll: &str, symbol: &ImportSymbol) -> Resolved {
    let mut cur_dll = normalize_dll(dll);
    let mut cur_symbol = symbol.clone();

    for _ in 0..MAX_FORWARDER_HOPS {
        let Some(module) = modules.module(&cur_dll) else {
            return Resolved::Fallback;
        };
        let Some(export) = module.find(&cur_symbol) else {
            return Resolved::Fallback;
        };
        match &export.forwarder {
            None => return Resolved::GuestCode(module.base + export.rva as u64),
            Some(target) => {
                let Some((next_dll, next_symbol)) = parse_forwarder(target) else {
                    return Resolved::Fallback;
                };
                cur_dll = next_dll;
                cur_symbol = next_symbol;
            }
        }
    }

    Resolved::Fallback
}

fn normalize_dll(dll: &str) -> String {
    let mut n = dll.to_ascii_lowercase();
    if !n.contains('.') {
        n.push_str(".dll");
    }
    n
}

fn parse_forwarder(s: &str) -> Option<(String, ImportSymbol)> {
    let dot = s.rfind('.')?;
    let (dll_part, sym_part) = s.split_at(dot);
    let sym_part = &sym_part[1..];
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

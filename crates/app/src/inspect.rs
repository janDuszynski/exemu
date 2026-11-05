use std::collections::{BTreeMap, HashMap};

use exemu_core::{DialogTemplate, PeImage, Result};

pub struct ResourceTypeCount {
    pub label: String,
    pub count: usize,
}

pub struct ImageInfo {
    pub image: PeImage,
    pub resource_entries: usize,
    pub resource_types: Vec<ResourceTypeCount>,
    pub file_version: Option<(u16, u16, u16, u16)>,
    pub dialogs: HashMap<u32, DialogTemplate>,
}

pub fn inspect(bytes: &[u8]) -> Result<ImageInfo> {
    let image = exemu_loader::parse(bytes)?;

    let entries = exemu_loader::list_resources(bytes);
    let mut by_type: BTreeMap<u32, (Option<String>, usize)> = BTreeMap::new();
    for e in &entries {
        let entry = by_type.entry(e.type_id).or_insert_with(|| (e.type_name.clone(), 0));
        entry.1 += 1;
    }
    let resource_types = by_type
        .into_iter()
        .map(|(tid, (tname, count))| {
            let label = match tname {
                Some(n) => format!("named:{n}"),
                None => exemu_loader::rt_name(tid)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("type#{tid}")),
            };
            ResourceTypeCount { label, count }
        })
        .collect();

    let file_version = if entries.is_empty() {
        None
    } else {
        exemu_loader::find_version_info(bytes).map(|info| info.file_version())
    };

    Ok(ImageInfo {
        image,
        resource_entries: entries.len(),
        resource_types,
        file_version,
        dialogs: exemu_loader::parse_dialogs(bytes),
    })
}

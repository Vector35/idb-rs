use crate::{dump_dirtree::print_dirtree, get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::{ID0Section, Id0AddressKey, Id0Section};
use idb_rs::IdbKind;

pub fn dump_dirtree_names(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        Id0Section::U32(id0) => dump(id0),
        Id0Section::U64(id0) => dump(id0),
    }
}

fn dump<K: IdbKind>(id0: ID0Section<K>) -> Result<()> {
    let dirtree = id0.dirtree_names()?;
    print_dirtree(
        |address| {
            print!("{:#x}:", address.as_u64());
            let label = id0.label_at(*address);
            if let Some(name) = label.unwrap() {
                print!("{}", String::from_utf8_lossy(&name));
            } else {
                print!("[Label Not Found]");
            }
        },
        &dirtree,
    );

    Ok(())
}

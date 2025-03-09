use crate::{get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::{ID0Section, Id0Section};
use idb_rs::IdbKind;

pub fn dump_dirtree_enums(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        Id0Section::U32(id0) => dump(id0),
        Id0Section::U64(id0) => dump(id0),
    }
}

fn dump<K: IdbKind>(id0: ID0Section<K>) -> Result<()> {
    let dirtree = id0.dirtree_enums()?;
    println!("{:?}", dirtree);

    Ok(())
}

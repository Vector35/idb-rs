use crate::{get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::ID0Section;
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_segstrings(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        IDAVariants::IDA32(id0) => dump(id0),
        IDAVariants::IDA64(id0) => dump(id0),
    }
}

fn dump<K: IDAKind>(id0: ID0Section<K>) -> Result<()> {
    println!("Segment strings AKA `$ segstrings`: ");
    let Some(idx) = id0.segment_strings_idx() else {
        return Ok(());
    };
    for entry in id0.segment_strings(idx) {
        let (name_idx, name) = entry?;
        println!("  {} {}", name_idx.0, String::from_utf8_lossy(name));
    }

    Ok(())
}

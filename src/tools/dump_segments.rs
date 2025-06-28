use crate::{get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::ID0Section;
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_segments(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        IDAVariants::IDA32(id0) => dump(id0),
        IDAVariants::IDA64(id0) => dump(id0),
    }
}

fn dump<K: IDAKind>(id0: ID0Section<K>) -> Result<()> {
    if let Some(segs_idx) = id0.segments_idx()? {
        println!("Segments AKA `$ segs`: ");
        for entry in id0.segments(segs_idx) {
            println!("  {:x?}", entry?);
        }
    }

    // TODO create a function for that in ida_info
    let version = id0.ida_info(id0.root_node()?)?.version;
    if let Ok(idx) = id0.file_regions_idx() {
        println!();
        println!("Segments AKA `$ fileregions`: ");
        for entry in id0.file_regions(idx, version) {
            println!("  {:x?}", entry?);
        }
    }
    Ok(())
}

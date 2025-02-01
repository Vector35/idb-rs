use crate::{get_id0_section, Args};

use anyhow::Result;

pub fn dump_segments(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let id0 = get_id0_section(args)?;

    println!("Segments AKA `$ segs`: ");
    for entry in id0.segments()? {
        println!("  {:x?}", entry?);
    }

    // TODO create a function for that in ida_info
    let version = match id0.ida_info()? {
        idb_rs::id0::IDBParam::V1(idb_rs::id0::IDBParam1 {
            version, ..
        }) => version,
        idb_rs::id0::IDBParam::V2(idb_rs::id0::IDBParam2 {
            version, ..
        }) => version,
    };
    if let Some(idx) = id0.file_regions_idx() {
        println!();
        println!("Segments AKA `$ fileregions`: ");
        for entry in id0.file_regions(idx, version) {
            println!("  {:x?}", entry?);
        }
    }
    Ok(())
}

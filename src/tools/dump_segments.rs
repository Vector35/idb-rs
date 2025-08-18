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

    if let Some(idx) = id0.srareas_idx()? {
        let info_idx = id0.root_node()?;
        let info = id0.ida_info(info_idx)?;
        let proc = idb_rs::processors::get_processor(
            info.version,
            &info.target.processor,
        )
        .unwrap();
        for (sreg_idx, sreg) in proc.segment_register_names().iter().enumerate()
        {
            println!();
            println!(
                "segment registers `$ srareas` for segreg {sreg_idx} {sreg:?}: "
            );
            for entry in id0.srareas(idx, sreg_idx.try_into().unwrap()) {
                println!("  {:x?}", entry?);
            }
        }
    }
    Ok(())
}

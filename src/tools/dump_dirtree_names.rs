use crate::dump_dirtree::print_dirtree;
use crate::{get_id0_id1_id2_sections, Args, Id0Id1Id2Variant};

use anyhow::Result;

use idb_rs::addr_info::AddressInfo;
use idb_rs::{Address, IDAKind, IDAVariants};

pub fn dump_dirtree_names(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_id1_id2_sections(args)? {
        IDAVariants::IDA32(kind) => dump(kind),
        IDAVariants::IDA64(kind) => dump(kind),
    }
}

fn dump<K: IDAKind>((id0, id1, id2): Id0Id1Id2Variant<K>) -> Result<()> {
    let root_info_idx = id0.root_node()?;
    let root_info = id0.ida_info(root_info_idx)?;
    let image_base = root_info.netdelta();
    if let Some(dirtree) = id0.dirtree_names()? {
        print_dirtree(
            |address| {
                print!("{address:#x}:");
                let info = AddressInfo::new(
                    &id0,
                    &id1,
                    id2.as_ref(),
                    image_base,
                    Address::from_raw(*address),
                )
                .unwrap();
                let label = info.label();
                if let Some(name) = label.unwrap() {
                    print!("{name}");
                } else {
                    print!("[Label Not Found]");
                }
            },
            &dirtree,
        );
    }

    Ok(())
}

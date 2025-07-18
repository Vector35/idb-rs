use crate::dump_dirtree::print_dirtree;
use crate::{get_id0_id1_id2_sections, Args};

use anyhow::Result;
use idb_rs::addr_info::AddressInfo;
use idb_rs::id0::ID0Section;
use idb_rs::id1::ID1Section;
use idb_rs::id2::ID2Section;
use idb_rs::{Address, IDAKind, IDAVariants};

pub fn dump_dirtree_funcs(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let (id0, id1, id2) = get_id0_id1_id2_sections(args)?;
    match (id0, id2) {
        (IDAVariants::IDA32(id0), Some(IDAVariants::IDA32(id2))) => {
            dump_inner(&id0, &id1, Some(&id2))
        }
        (IDAVariants::IDA32(id0), None) => dump_inner(&id0, &id1, None),
        (IDAVariants::IDA64(id0), Some(IDAVariants::IDA64(id2))) => {
            dump_inner(&id0, &id1, Some(&id2))
        }
        (IDAVariants::IDA64(id0), None) => dump_inner(&id0, &id1, None),
        (_, _) => unreachable!(),
    }
}

fn dump_inner<K: IDAKind>(
    id0: &ID0Section<K>,
    id1: &ID1Section,
    id2: Option<&ID2Section<K>>,
) -> Result<()> {
    if let Some(dirtree) = id0.dirtree_function_address()? {
        print_dirtree(
            |entry| {
                print_function(id0, id1, id2, Address::from_raw(*entry))
                    .unwrap()
            },
            &dirtree,
        );
    }

    Ok(())
}

pub fn print_function<K: IDAKind>(
    id0: &ID0Section<K>,
    id1: &ID1Section,
    id2: Option<&ID2Section<K>>,
    address: Address<K>,
) -> Result<()> {
    let root_info_idx = id0.root_node()?;
    let root_info = id0.ida_info(root_info_idx)?;
    let image_base = root_info.netdelta();
    let info = AddressInfo::new(id0, id1, id2, image_base, address).unwrap();
    let name_raw = info.label()?;
    let ty = info.tinfo()?;
    let name = name_raw.as_ref().map(|name| String::from_utf8_lossy(name));

    print!("{:#x}:", address.into_raw());
    match (name, ty) {
        (Some(name), Some(ty)) => print!("\"{name}\":{ty:?}"),
        (None, None) => print!("NO_INFO"),
        (None, Some(ty)) => print!("UNAMED:{ty:?}"),
        (Some(name), None) => print!("\"{name}\""),
    }
    println!();
    Ok(())
}

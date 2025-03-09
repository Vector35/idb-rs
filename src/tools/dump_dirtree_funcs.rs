use crate::{dump_dirtree::print_dirtree, get_id0_section, Args};

use anyhow::{ensure, Result};
use idb_rs::id0::{ID0Section, Id0Address, Id0AddressKey};
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_dirtree_funcs(args: &Args) -> Result<()> {
    // parse the id0 sector/file    match get_id0_section(args)? {
    match get_id0_section(args)? {
        IDAVariants::IDA32(id0) => dump(id0),
        IDAVariants::IDA64(id0) => dump(id0),
    }
}

fn dump<K: IDAKind>(id0: ID0Section<K>) -> Result<()> {
    let dirtree = id0.dirtree_function_address()?;
    print_dirtree(|entry| print_function(&id0, *entry).unwrap(), &dirtree);

    Ok(())
}

pub fn print_function<K: IDAKind>(
    id0: &ID0Section<K>,
    address: Id0Address<K>,
) -> Result<()> {
    let infos = id0.address_info_at(address)?;
    let mut name = None;
    let mut ty = None;
    for info in infos {
        match info? {
            idb_rs::id0::AddressInfo::Comment(_)
            | idb_rs::id0::AddressInfo::DefinedStruct(_)
            | idb_rs::id0::AddressInfo::Other { .. } => {}
            idb_rs::id0::AddressInfo::Label(label) => {
                if let Some(_old) = name.replace(label) {
                    panic!("Multiple labels can't be return for address")
                }
            }
            idb_rs::id0::AddressInfo::TilType(addr_ty) => {
                ensure!(
                    matches!(
                        &addr_ty.type_variant,
                        idb_rs::til::TypeVariant::Function(_)
                    ),
                    "Type for function at {address:#?} is invalid"
                );
                if let Some(_old) = ty.replace(addr_ty) {
                    panic!("Multiple types can't be return for address")
                }
            }
        }
    }
    print!("{:#x}:", address.as_u64());
    match (name, ty) {
        (Some(name), Some(ty)) => print!("\"{name}\":{ty:?}"),
        (None, None) => print!("NO_INFO"),
        (None, Some(ty)) => print!("UNAMED:{ty:?}"),
        (Some(name), None) => print!("\"{name}\""),
    }
    println!();
    Ok(())
}

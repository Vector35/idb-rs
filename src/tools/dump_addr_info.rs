use crate::{get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::ID0Section;
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_addr_info(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        IDAVariants::IDA32(id0) => dump(id0),
        IDAVariants::IDA64(id0) => dump(id0),
    }
}

fn dump<K: IDAKind>(id0: ID0Section<K>) -> Result<()> {
    // TODO create a function for that in ida_info
    let root_netnode = id0.root_node()?;
    let version = match id0.ida_info(root_netnode.into())? {
        idb_rs::id0::IDBParam::V1(idb_rs::id0::IDBParam1 {
            version, ..
        }) => version,
        idb_rs::id0::IDBParam::V2(idb_rs::id0::IDBParam2 {
            version, ..
        }) => version,
    };
    for entry in id0.address_info(version)? {
        let (addr, info) = entry?;
        print!("{addr:#010x}:");
        match info {
            idb_rs::id0::AddressInfo::Other {
                key: [key_type, rest @ ..],
                value,
            } if (*key_type as char).is_ascii_graphic() => {
                println!(
                    "Other('{}':{rest:02x?}:{value:02x?})",
                    *key_type as char
                );
            }
            idb_rs::id0::AddressInfo::Other { key, value } => {
                println!("Other({key:02x?}:{value:02x?})",);
            }
            other => {
                println!("{other:?}");
            }
        }
    }

    Ok(())
}

use std::fs::File;
use std::io::BufReader;

use crate::{Args, FileType};

use anyhow::{anyhow, Result};
use idb_rs::IDBParser;

pub fn dump_addr_info(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let id0 = match args.input_type() {
        FileType::Til => return Err(anyhow!("TIL don't contains any ID0 data")),
        FileType::Idb => {
            let input = BufReader::new(File::open(&args.input)?);
            let mut parser = IDBParser::new(input)?;
            let id0_offset = parser
                .id0_section_offset()
                .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
            parser.read_id0_section(id0_offset)?
        }
    };

    // TODO create a function for that in ida_info
    let version = match id0.ida_info()? {
        idb_rs::id0::IDBParam::V1(idb_rs::id0::IDBParam1 { version, .. }) => version,
        idb_rs::id0::IDBParam::V2(idb_rs::id0::IDBParam2 { version, .. }) => version,
    };
    for entry in id0.address_info(version)? {
        let (addr, info) = entry?;
        print!("{addr:#010x}:");
        match info {
            idb_rs::id0::AddressInfo::Other {
                key: [key_type, rest @ ..],
                value,
            } if (*key_type as char).is_ascii_graphic() => {
                println!("Other('{}':{rest:02x?}:{value:02x?})", *key_type as char);
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

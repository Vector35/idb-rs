use std::fs::File;
use std::io::BufReader;

use crate::{dump_dirtree::print_dirtree, Args, FileType};

use anyhow::{anyhow, Result};

use idb_rs::id0::{ID0Section, Id0Section, Id0TilOrd};
use idb_rs::til::section::TILSection;
use idb_rs::{IdbKind, IdbParser};

pub fn dump_dirtree_types(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match args.input_type() {
        FileType::Til => {
            return Err(anyhow!("TIL don't contains any ID0 data"))
        }
        FileType::Idb => {
            let input = BufReader::new(File::open(&args.input)?);
            let mut parser = IdbParser::new(input)?;
            let id0_offset = parser.id0_section_offset().ok_or_else(|| {
                anyhow!("IDB file don't contains a ID0 sector")
            })?;
            let til_offset = parser.til_section_offset().ok_or_else(|| {
                anyhow!("IDB file don't contains a TIL sector")
            })?;
            let id0 = parser.read_id0_section(id0_offset)?;
            let til = parser.read_til_section(til_offset)?;
            match id0 {
                Id0Section::U32(id0) => dump(&id0, &til),
                Id0Section::U64(id0) => dump(&id0, &til),
            }
        }
    }
}

fn dump<K: IdbKind>(id0: &ID0Section<K>, til: &TILSection) -> Result<()> {
    let dirtree = id0.dirtree_tinfos()?;
    let print_til = |id0ord: &Id0TilOrd| {
        if let Some(til) = til.get_ord(*id0ord) {
            print!("{til:?}");
        } else {
            print!("NonExisting til");
        }
    };
    print_dirtree(print_til, &dirtree);

    Ok(())
}

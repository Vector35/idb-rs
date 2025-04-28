use std::fs::File;
use std::io::{BufReader, Cursor};

use crate::{dump_dirtree::print_dirtree, Args, FileType};

use anyhow::{anyhow, Result};

use idb_rs::id0::{ID0Section, Id0TilOrd};
use idb_rs::til::section::TILSection;
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_dirtree_types(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match args.input_type() {
        FileType::Til => Err(anyhow!("TIL don't contains any ID0 data")),
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            let format = idb_rs::IDBFormat::identify_file(&mut input)?;
            let (id0, til) = match format {
                idb_rs::IDBFormat::SeparatedSections(sections) => {
                    let id0 =
                        idb_rs::read_id0_separated(&mut input, &sections)?
                            .ok_or_else(|| {
                                anyhow!("IDB file don't contains a ID0 sector")
                            })?;
                    let til =
                        idb_rs::read_til_separated(&mut input, &sections)?
                            .ok_or_else(|| {
                                anyhow!("IDB file don't contains a TIL sector")
                            })?;
                    (id0, til)
                }
                idb_rs::IDBFormat::InlineSections(
                    idb_rs::InlineSectionsTypes::Uncompressed(sections),
                ) => {
                    let id0 = idb_rs::read_id0_inlined(&mut input, &sections)?
                        .ok_or_else(|| {
                            anyhow!("IDB file don't contains a ID0 sector")
                        })?;
                    let til = idb_rs::read_til_inlined(&mut input, &sections)?
                        .ok_or_else(|| {
                            anyhow!("IDB file don't contains a TIL sector")
                        })?;
                    (id0, til)
                }
                idb_rs::IDBFormat::InlineSections(
                    idb_rs::InlineSectionsTypes::Compressed(compressed),
                ) => {
                    let mut decompressed = Vec::new();
                    let sections = compressed
                        .decompress_into_memory(input, &mut decompressed)
                        .unwrap();
                    let mut decompressed = Cursor::new(decompressed);
                    let id0 =
                        idb_rs::read_id0_inlined(&mut decompressed, &sections)?
                            .ok_or_else(|| {
                                anyhow!("IDB file don't contains a ID0 sector")
                            })?;
                    let til =
                        idb_rs::read_til_inlined(&mut decompressed, &sections)?
                            .ok_or_else(|| {
                                anyhow!("IDB file don't contains a TIL sector")
                            })?;
                    (id0, til)
                }
            };
            match id0 {
                IDAVariants::IDA32(id0) => dump(&id0, &til),
                IDAVariants::IDA64(id0) => dump(&id0, &til),
            }
        }
    }
}

fn dump<K: IDAKind>(id0: &ID0Section<K>, til: &TILSection) -> Result<()> {
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

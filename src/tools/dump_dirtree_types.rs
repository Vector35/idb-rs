use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek};

use crate::{dump_dirtree::print_dirtree, Args, FileType};

use anyhow::{anyhow, Result};

use idb_rs::id0::{ID0Section, Id0TilOrd};
use idb_rs::til::section::TILSection;
use idb_rs::{IDAKind, IDAVariants, IDBFormat};

pub fn dump_dirtree_types(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match args.input_type() {
        FileType::Til => Err(anyhow!("TIL don't contains any ID0 data")),
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            let format = idb_rs::IDBFormats::identify_file(&mut input)?;
            match format {
                idb_rs::IDBFormats::Separated(sections) => {
                    dump_sections(sections, input)
                }
                idb_rs::IDBFormats::InlineUncompressed(sections) => {
                    dump_sections(sections, input)
                }
                idb_rs::IDBFormats::InlineCompressed(compressed) => {
                    let mut decompressed = Vec::new();
                    let sections = compressed
                        .decompress_into_memory(input, &mut decompressed)
                        .unwrap();
                    dump_sections(sections, Cursor::new(decompressed))
                }
            }
        }
    }
}

fn dump_sections<R: IDBFormat, I: BufRead + Seek>(
    read: R,
    mut input: I,
) -> Result<()> {
    let id0_location = read
        .id0_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a ID0 sector"))?;
    let til_location = read
        .til_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
    let id0 = read.read_id0(&mut input, id0_location)?;
    let til = read.read_til(&mut input, til_location)?;
    match id0 {
        IDAVariants::IDA32(id0) => dump(&id0, &til),
        IDAVariants::IDA64(id0) => dump(&id0, &til),
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

use std::fs::File;
use std::io::{BufReader, Cursor};

use anyhow::{anyhow, Result};
use idb_rs::til::section::TILSection;

use crate::{Args, DecompressTilArgs, FileType};

pub fn decompress_til(args: &Args, til_args: &DecompressTilArgs) -> Result<()> {
    // parse the til sector/file
    let mut output = std::io::BufWriter::new(File::create(&til_args.output)?);
    match args.input_type() {
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            let format = idb_rs::IDBFormat::identify_file(&mut input)?;
            match format {
                idb_rs::IDBFormat::SeparatedSections(sections) => {
                    idb_rs::decompress_til_separated(
                        &mut input,
                        &mut output,
                        &sections,
                    )?
                    .ok_or_else(|| {
                        anyhow!("IDB file don't contains a TIL sector")
                    })?;
                    Ok(())
                }
                idb_rs::IDBFormat::InlineSections(
                    idb_rs::InlineSectionsTypes::Uncompressed(sections),
                ) => {
                    idb_rs::decompress_til_inlined(
                        &mut input,
                        &mut output,
                        &sections,
                    )?
                    .ok_or_else(|| {
                        anyhow!("IDB file don't contains a TIL sector")
                    })?;
                    Ok(())
                }
                idb_rs::IDBFormat::InlineSections(
                    idb_rs::InlineSectionsTypes::Compressed(compressed),
                ) => {
                    let mut decompressed = Vec::new();
                    let sections = compressed
                        .decompress_into_memory(input, &mut decompressed)?;
                    idb_rs::decompress_til_inlined(
                        &mut Cursor::new(decompressed),
                        &mut output,
                        &sections,
                    )?
                    .ok_or_else(|| {
                        anyhow!("IDB file don't contains a TIL sector")
                    })
                }
            }
        }
        FileType::Til => {
            let mut input = BufReader::new(File::open(&args.input)?);
            // TODO make decompress til public
            TILSection::decompress(&mut input, &mut output)
        }
    }
}

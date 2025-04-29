use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek, Write};

use anyhow::{anyhow, Result};
use idb_rs::til::section::TILSection;
use idb_rs::IDBFormat;

use crate::{Args, DecompressTilArgs, FileType};

pub fn decompress_til(args: &Args, til_args: &DecompressTilArgs) -> Result<()> {
    // parse the til sector/file
    let mut output = std::io::BufWriter::new(File::create(&til_args.output)?);
    match args.input_type() {
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            let format = idb_rs::IDBFormats::identify_file(&mut input)?;
            match format {
                idb_rs::IDBFormats::Separated(sections) => {
                    decompress_til_fmt(sections, input, &mut output)
                }
                idb_rs::IDBFormats::InlineUncompressed(sections) => {
                    decompress_til_fmt(sections, input, &mut output)
                }
                idb_rs::IDBFormats::InlineCompressed(compressed) => {
                    let mut decompressed = Vec::new();
                    let sections = compressed
                        .decompress_into_memory(input, &mut decompressed)?;
                    decompress_til_fmt(
                        sections,
                        Cursor::new(decompressed),
                        &mut output,
                    )
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

fn decompress_til_fmt<R: IDBFormat, I: BufRead + Seek, O: Write>(
    sections: R,
    input: I,
    output: O,
) -> Result<()> {
    let til_location = sections
        .til_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
    sections.decompress_til(input, output, til_location)
}

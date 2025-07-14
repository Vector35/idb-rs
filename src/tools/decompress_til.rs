use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek, Write};

use anyhow::{anyhow, Result};
use idb_rs::til::section::TILSection;
use idb_rs::{IDAKind, IDAVariants, IDBFormat};

use crate::{Args, DecompressTilArgs, FileType};

pub fn decompress_til(args: &Args, til_args: &DecompressTilArgs) -> Result<()> {
    // parse the til sector/file
    let mut output = std::io::BufWriter::new(File::create(&til_args.output)?);
    match args.input_type() {
        FileType::Idb => {
            let mut input = BufReader::new(File::open(&args.input)?);
            let kind = idb_rs::identify_idb_file(&mut input)?;
            decompress_til_kind(kind, input, output)
        }
        FileType::Til => {
            let mut input = BufReader::new(File::open(&args.input)?);
            // TODO make decompress til public
            TILSection::decompress(&mut input, &mut output)
        }
    }
}

pub fn decompress_til_kind<I: BufRead + Seek, O: Write>(
    format: idb_rs::IDBFormats,
    input: I,
    output: O,
) -> Result<()> {
    match format {
        idb_rs::IDBFormats::Separated(IDAVariants::IDA32(sections)) => {
            decompress_til_fmt(sections, input, output)
        }
        idb_rs::IDBFormats::Separated(IDAVariants::IDA64(sections)) => {
            decompress_til_fmt(sections, input, output)
        }
        idb_rs::IDBFormats::InlineUncompressed(sections) => {
            decompress_til_fmt(sections, input, output)
        }
        idb_rs::IDBFormats::InlineCompressed(compressed) => {
            let mut decompressed = Vec::new();
            let sections =
                compressed.decompress_into_memory(input, &mut decompressed)?;
            decompress_til_fmt(sections, Cursor::new(decompressed), output)
        }
    }
}

fn decompress_til_fmt<K, R, I, O>(
    sections: R,
    input: I,
    output: O,
) -> Result<()>
where
    K: IDAKind,
    R: IDBFormat<K>,
    I: BufRead + Seek,
    O: Write,
{
    let til_location = sections
        .til_location()
        .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
    sections.decompress_til(input, output, til_location)
}

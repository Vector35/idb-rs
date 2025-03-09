use std::fs::File;
use std::io::BufReader;

use anyhow::{anyhow, Result};
use idb_rs::{til::section::TILSection, IdbParser};

use crate::{Args, DecompressTilArgs, FileType};

pub fn decompress_til(args: &Args, til_args: &DecompressTilArgs) -> Result<()> {
    // parse the til sector/file
    let mut output = std::io::BufWriter::new(File::create(&til_args.output)?);
    match args.input_type() {
        FileType::Idb => {
            let input = BufReader::new(File::open(&args.input)?);
            let mut parser = IdbParser::new(input)?;
            let til_offset = parser.til_section_offset().ok_or_else(|| {
                anyhow!("IDB file don't contains a TIL sector")
            })?;
            // TODO make decompress til public
            parser.decompress_til_section(til_offset, &mut output)
        }
        FileType::Til => {
            let mut input = BufReader::new(File::open(&args.input)?);
            // TODO make decompress til public
            TILSection::decompress(
                &mut input,
                &mut output,
                idb_rs::IDBSectionCompression::None,
            )
        }
    }
}

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};

use anyhow::{anyhow, Result};
use idb_rs::til::section::{TILSection, TILSizes};
use idb_rs::IDBParser;

use crate::{Args, DecompressTilArgs, FileType};

pub fn decompress_til(args: &Args, til_args: &DecompressTilArgs) -> Result<()> {
    // parse the til sector/file
    let til = match args.input_type() {
        FileType::IDB => {
            let input = BufReader::new(File::open(&args.input)?);
            let mut parser = IDBParser::new(input)?;
            let til_offset = parser
                .til_section_offset()
                .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
            // TODO make decompress til public
            todo!();
        }
        FileType::TIL => {
            let input = BufReader::new(File::open(&args.input)?);
            // TODO make decompress til public
            todo!();
        }
    };
    todo!();
}

use std::{fs::File, io::BufReader};

use crate::{Args, FileType, SplitIDBArgs};

use anyhow::{anyhow, Result};
use idb_rs::IDBParser;

pub fn split_idb(args: &Args, id0_args: &SplitIDBArgs) -> Result<()> {
    // parse the id0 sector/file
    let parser = match args.input_type() {
        FileType::IDB => {
            let input = BufReader::new(File::open(&args.input)?);
            IDBParser::new(input)?
        }
        FileType::TIL => return Err(anyhow!("TIL don't contains any Sections")),
    };
    // TODO implement uncompressed raw-section read capability
    todo!();
}

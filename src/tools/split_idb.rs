use std::fs::File;
use std::io::BufReader;

use crate::{Args, SplitIDBArgs};

use anyhow::Result;

pub fn split_idb(args: &Args, id0_args: &SplitIDBArgs) -> Result<()> {
    // parse the id0 sector/file
    let id0 = get_id0_section(args)?;

    // TODO implement uncompressed raw-section read capability
    todo!();
}

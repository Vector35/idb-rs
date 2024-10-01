use crate::{get_id0_section, Args};

use anyhow::Result;

pub fn dump_dirtree_bookmarks_structplace(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let id0 = get_id0_section(args)?;

    let dirtree = id0.dirtree_bookmarks_structplace()?;
    println!("{:?}", dirtree);

    Ok(())
}

use crate::{get_id2_section, Args};

use anyhow::Result;

pub fn dump_id2(args: &Args) -> Result<()> {
    // parse the id2 sector/file
    let id2 = get_id2_section(args)?;
    println!("{id2:02X?}");
    Ok(())
}

use crate::{get_id0_section, Args};

use anyhow::Result;

pub fn dump_root_info(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let id0 = get_id0_section(args)?;

    println!("Segments AKA `Root Node`: ");
    for entry in id0.root_info()? {
        println!("  {:x?}", entry?);
    }

    Ok(())
}

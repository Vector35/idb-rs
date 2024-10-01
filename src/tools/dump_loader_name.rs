use crate::{get_id0_section, Args};

use anyhow::Result;

pub fn dump_loader_name(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let id0 = get_id0_section(args)?;

    println!("Loader Name AKA `$ loader name`: ");
    for name in id0.loader_name()? {
        println!("  {}", name?);
    }

    Ok(())
}

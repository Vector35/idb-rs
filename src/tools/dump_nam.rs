use crate::{get_nam_section, Args};

use anyhow::Result;

pub fn dump_nam(args: &Args) -> Result<()> {
    let nam = get_nam_section(args)?;

    for (i, name) in nam.names.iter().enumerate() {
        print!("{i:04X}: {name:#010X} ");

        println!();
    }
    Ok(())
}

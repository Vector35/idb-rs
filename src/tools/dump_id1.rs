use crate::{get_id1_section, Args};

use anyhow::Result;

pub fn dump_id1(args: &Args) -> Result<()> {
    // parse the id1 sector/file
    let id1 = get_id1_section(args)?;

    for entry in &id1.seglist {
        let mut offset = entry.offset;
        for byte in &entry.data {
            println!("{offset:08X}: {byte:#04X}");
            offset += 1;
        }
    }
    Ok(())
}

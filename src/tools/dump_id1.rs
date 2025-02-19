use crate::{get_id1_section, Args};

use anyhow::Result;

pub fn dump_id1(args: &Args) -> Result<()> {
    // parse the id1 sector/file
    let id1 = get_id1_section(args)?;

    for entry in &id1.seglist {
        let mut offset = entry.offset;
        for byte_info in &entry.data {
            println!(
                "{offset:08X}: {:#04X} {:#010X}",
                byte_info.value_raw(),
                byte_info.flag_raw()
            );
            offset += 1;
        }
    }
    Ok(())
}

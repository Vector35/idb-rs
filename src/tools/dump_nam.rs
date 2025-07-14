use anyhow::Result;

use crate::{get_nam_section, Args};

use idb_rs::nam::NamSection;
use idb_rs::IDAKind;

pub fn dump_nam(args: &Args) -> Result<()> {
    match get_nam_section(args)? {
        idb_rs::IDAVariants::IDA32(kind) => dump_nam_kind(kind),
        idb_rs::IDAVariants::IDA64(kind) => dump_nam_kind(kind),
    }
}

fn dump_nam_kind<K: IDAKind>(nam: NamSection<K>) -> Result<()> {
    for (i, name) in nam.names.iter().enumerate() {
        print!("{i:04X}: {name:#010X} ");

        println!();
    }
    Ok(())
}

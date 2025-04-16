use crate::{get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::ID0Section;
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_loader_name(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        IDAVariants::IDA32(id0) => dump(id0),
        IDAVariants::IDA64(id0) => dump(id0),
    }
}

fn dump<K: IDAKind>(id0: ID0Section<K>) -> Result<()> {
    if let Some(loader_name) = id0.loader_name()? {
        println!("Loader Name AKA `$ loader name`: ");
        for name in loader_name {
            println!("  {}", name?);
        }
    } else {
        println!("No Loader Name AKA `$ loader name` present");
    }

    Ok(())
}

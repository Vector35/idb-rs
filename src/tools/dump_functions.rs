use crate::{get_id0_section, Args};

use anyhow::Result;
use idb_rs::id0::EntryPoint;

pub fn dump_functions(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let id0 = get_id0_section(args)?;

    println!("Function and Comments AKA `$ funcs`: ");
    for entry in id0.functions_and_comments()? {
        match entry? {
            idb_rs::id0::FunctionsAndComments::Name => {}
            idb_rs::id0::FunctionsAndComments::Function(idbfunction) => {
                println!(
                    "  Function at {:#x}..{:#x}",
                    idbfunction.address.start, idbfunction.address.end
                );
            }
            idb_rs::id0::FunctionsAndComments::Comment { address, value } => {
                println!("  Comment at {address:#x}: `{value}`",);
            }
            idb_rs::id0::FunctionsAndComments::RepeatableComment { address, value } => {
                println!("  RepeatableComment at {address:#x}: `{value}`",);
            }
            idb_rs::id0::FunctionsAndComments::Unknown { .. } => {}
        }
    }

    println!();
    println!("Entry points, AKA `$ entry points`");
    for entry in id0.entry_points()? {
        let EntryPoint {
            name,
            address,
            forwarded,
            entry_type,
        } = entry;
        print!("  {address:#x}:{name}");
        if let Some(forwarded) = forwarded {
            print!(",forwarded:`{forwarded}`");
        }
        if let Some(entry_type) = entry_type {
            print!(",type:`{entry_type:?}`");
        }
        println!();
    }
    Ok(())
}

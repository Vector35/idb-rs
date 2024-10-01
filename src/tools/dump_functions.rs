use std::fs::File;
use std::io::BufReader;

use crate::{Args, FileType};

use anyhow::{anyhow, Result};
use idb_rs::{id0::EntryPoint, IDBParser};

pub fn dump_functions(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let id0 = match args.input_type() {
        FileType::Til => return Err(anyhow!("TIL don't contains any ID0 data")),
        FileType::Idb => {
            let input = BufReader::new(File::open(&args.input)?);
            let mut parser = IDBParser::new(input)?;
            let id0_offset = parser
                .id0_section_offset()
                .ok_or_else(|| anyhow!("IDB file don't contains a TIL sector"))?;
            parser.read_id0_section(id0_offset)?
        }
    };
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

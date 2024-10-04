use crate::{dump_dirtree_funcs::print_function, get_id0_section, Args};

use anyhow::Result;
use idb_rs::id0::{Comments, EntryPoint};

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
            idb_rs::id0::FunctionsAndComments::Comment {
                address,
                comment: Comments::Comment(value),
            } => {
                println!(
                    "  Comment at {address:#x}: `{}`",
                    String::from_utf8_lossy(value)
                );
            }
            idb_rs::id0::FunctionsAndComments::Comment {
                address,
                comment: Comments::RepeatableComment(value),
            } => {
                println!(
                    "  RepeatableComment at {address:#x}: `{}`",
                    String::from_utf8_lossy(value)
                );
            }
            // There is no Pre/Post comments on funcs
            idb_rs::id0::FunctionsAndComments::Comment {
                address: _,
                comment: Comments::PreComment(_) | Comments::PostComment(_),
            } => {
                unreachable!()
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

    println!();
    println!("dirtree functions, AKA `$ dirtree/funcs`");
    let dirtree = id0.dirtree_function_address()?;
    let mut buffer = dirtree.entries;
    while !buffer.is_empty() {
        let entry = buffer.pop().unwrap();
        match entry {
            idb_rs::id0::DirTreeEntry::Leaf(address) => {
                print!("  {address:#x}:");
                print_function(&id0, address)?
            }
            idb_rs::id0::DirTreeEntry::Directory { name: _, entries } => buffer.extend(entries),
        }
    }

    Ok(())
}

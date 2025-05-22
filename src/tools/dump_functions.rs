use crate::{dump_dirtree_funcs::print_function, get_id0_section, Args};

use anyhow::Result;

use idb_rs::id0::function::{EntryPoint, FunctionsAndComments};
use idb_rs::id0::{Comments, ID0Section, Id0AddressKey};
use idb_rs::{IDAKind, IDAVariants};

pub fn dump_functions(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_section(args)? {
        IDAVariants::IDA32(id0) => dump(id0),
        IDAVariants::IDA64(id0) => dump(id0),
    }
}

fn dump<K: IDAKind>(id0: ID0Section<K>) -> Result<()> {
    println!("Function and Comments AKA `$ funcs`: ");
    let Some(idx) = id0.funcs_idx()? else {
        return Ok(());
    };
    for entry in id0.functions_and_comments(idx)? {
        match entry? {
            FunctionsAndComments::Name => {}
            FunctionsAndComments::Function(idbfunction) => {
                println!(
                    "  Function at {:#x}..{:#x}",
                    idbfunction.address.start, idbfunction.address.end
                );
            }
            FunctionsAndComments::Comment {
                address,
                comment: Comments::Comment(value),
            } => {
                println!(
                    "  Comment at {address:#x}: `{}`",
                    String::from_utf8_lossy(value)
                );
            }
            FunctionsAndComments::Comment {
                address,
                comment: Comments::RepeatableComment(value),
            } => {
                println!(
                    "  RepeatableComment at {address:#x}: `{}`",
                    String::from_utf8_lossy(value)
                );
            }
            // There is no Pre/Post comments on funcs
            FunctionsAndComments::Comment {
                address: _,
                comment: Comments::PreComment(_) | Comments::PostComment(_),
            } => {
                unreachable!()
            }
            FunctionsAndComments::Unknown { .. } => {}
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
    while let Some(entry) = buffer.pop() {
        match entry {
            idb_rs::id0::DirTreeEntry::Leaf(address) => {
                print!("  {:#x}:", address.as_u64());
                print_function(&id0, address)?
            }
            idb_rs::id0::DirTreeEntry::Directory { name: _, entries } => {
                buffer.extend(entries)
            }
        }
    }

    Ok(())
}

use crate::{dump_dirtree_funcs::print_function, Args};
use crate::{get_id0_id1_id2_sections, Id0Id1Id2Variant};

use anyhow::Result;

use idb_rs::id0::function::{Comments, EntryPoint, FunctionsAndComments};
use idb_rs::{Address, IDAKind, IDAVariants};

pub fn dump_functions(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_id1_id2_sections(args)? {
        IDAVariants::IDA32(kind) => dump(kind),
        IDAVariants::IDA64(kind) => dump(kind),
    }
}

fn dump<K: IDAKind>((id0, id1, id2): Id0Id1Id2Variant<K>) -> Result<()> {
    println!("Function and Comments AKA `$ funcs`: ");
    let Some(idx) = id0.funcs_idx()? else {
        return Ok(());
    };
    for entry in id0.functions_and_comments(idx) {
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
                println!("  Comment at {address:#x}: `{value}`",);
            }
            FunctionsAndComments::Comment {
                address,
                comment: Comments::RepeatableComment(value),
            } => {
                println!("  RepeatableComment at {address:#x}: `{value}`",);
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
    if let Some(dirtree) = id0.dirtree_function_address()? {
        let mut buffer = dirtree.entries;
        while let Some(entry) = buffer.pop() {
            match entry {
                idb_rs::id0::DirTreeEntry::Leaf(address) => {
                    print!("  {address:#x}:");
                    print_function(
                        &id0,
                        &id1,
                        id2.as_ref(),
                        Address::from_raw(address),
                    )?
                }
                idb_rs::id0::DirTreeEntry::Directory { name: _, entries } => {
                    buffer.extend(entries)
                }
            }
        }
    }

    Ok(())
}

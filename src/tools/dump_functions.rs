use crate::get_id0_id1_id2_sections;
use crate::{dump_dirtree_funcs::print_function, Args};

use anyhow::Result;

use idb_rs::id0::function::{Comments, EntryPoint, FunctionsAndComments};
use idb_rs::id0::ID0Section;
use idb_rs::id1::ID1Section;
use idb_rs::id2::ID2Section;
use idb_rs::{Address, IDAKind, IDAVariants};

pub fn dump_functions(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let (id0, id1, id2) = get_id0_id1_id2_sections(args)?;
    match (id0, id2) {
        (IDAVariants::IDA32(id0), Some(IDAVariants::IDA32(id2))) => {
            dump(&id0, &id1, Some(&id2))
        }
        (IDAVariants::IDA32(id0), None) => dump(&id0, &id1, None),
        (IDAVariants::IDA64(id0), Some(IDAVariants::IDA64(id2))) => {
            dump(&id0, &id1, Some(&id2))
        }
        (IDAVariants::IDA64(id0), None) => dump(&id0, &id1, None),
        (_, _) => unreachable!(),
    }
}

fn dump<K: IDAKind>(
    id0: &ID0Section<K>,
    id1: &ID1Section,
    id2: Option<&ID2Section<K>>,
) -> Result<()> {
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
                    print_function(id0, id1, id2, Address::from_raw(address))?
                }
                idb_rs::id0::DirTreeEntry::Directory { name: _, entries } => {
                    buffer.extend(entries)
                }
            }
        }
    }

    Ok(())
}

use crate::{dump_dirtree_funcs::print_function, Args};
use crate::{get_id0_id1_id2_sections, Id0Id1Id2Variant};

use anyhow::Result;

use idb_rs::id0::function::{EntryPoint, IDBFunctionType};
use idb_rs::{Address, IDAKind, IDAVariants};

pub fn dump_functions(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    match get_id0_id1_id2_sections(args)? {
        IDAVariants::IDA32(kind) => dump(kind),
        IDAVariants::IDA64(kind) => dump(kind),
    }
}

fn dump<K: IDAKind>((id0, id1, id2): Id0Id1Id2Variant<K>) -> Result<()> {
    let root_info_idx = id0.root_node()?;
    let root_info = id0.ida_info(root_info_idx)?;
    let netdelta = root_info.netdelta();

    let funcords_idx = id0.funcords_idx()?;
    if let Some(idx) = funcords_idx {
        println!("Functions addresses AKA `$ funcords`: ");
        for address in id0.funcords(idx)? {
            println!("  {:#016X?}", address?.into_raw());
        }
    };

    let funcs_idx = id0.funcs_idx()?;
    if let Some(funcs_idx) = funcs_idx {
        println!();
        println!("Function Chunks at `$ funcs`: ");
        for idbfunction in id0.fchunks(funcs_idx) {
            let idbfunction = idbfunction?;
            println!(
                "  Function at {:#x}..{:#x}: {idbfunction:X?}",
                idbfunction.address.start, idbfunction.address.end
            );

            if let IDBFunctionType::NonTail(func_data) = &idbfunction.extra {
                let regs = id0
                    .function_defined_registers(
                        netdelta,
                        &idbfunction,
                        func_data,
                    )
                    .collect::<Result<Vec<_>>>()?;
                if !regs.is_empty() {
                    println!("Functions register values: {regs:02X?}");
                }
            }
        }

        if let Some(funcords_idx) = funcords_idx {
            println!();
            println!("Function Comments at `$ funcs`: ");
            for address in id0.funcords(funcords_idx)? {
                let address = address?;
                if let Some(value) =
                    id0.func_cmt(funcs_idx, netdelta, address)?
                {
                    println!("  Comment at {address:#x}: `{value}`",);
                }
                if let Some(value) =
                    id0.func_repeatable_cmt(funcs_idx, netdelta, address)?
                {
                    println!("  RepeatableComment at {address:#x}: `{value}`",);
                }
            }
        }
    }

    println!();
    println!("Entry points, AKA `$ entry points`");
    for entry in id0.entry_points(&root_info)? {
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

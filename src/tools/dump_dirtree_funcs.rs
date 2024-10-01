use crate::{get_id0_section, Args};

use anyhow::{ensure, Result};
use idb_rs::id0::{DirTreeEntry, ID0Section};

pub fn dump_dirtree_funcs(args: &Args) -> Result<()> {
    // parse the id0 sector/file
    let id0 = get_id0_section(args)?;

    let dirtree = id0.dirtree_function_address()?;
    print_folder(&id0, 0, &dirtree.entries)?;

    Ok(())
}

fn print_folder(id0: &ID0Section, identation: usize, dirs: &[DirTreeEntry<u64>]) -> Result<()> {
    for dir in dirs {
        print_ident(identation);
        match dir {
            DirTreeEntry::Leaf(fun_addr) => {
                let infos = id0.address_info_at(*fun_addr)?;
                let mut name = None;
                let mut ty = None;
                for info in infos {
                    match info? {
                        idb_rs::id0::AddressInfo::Comment(_)
                        | idb_rs::id0::AddressInfo::Other { .. } => {}
                        idb_rs::id0::AddressInfo::Label(label) => {
                            if let Some(_old) = name.replace(label) {
                                panic!("Multiple labels can't be return for address")
                            }
                        }
                        idb_rs::id0::AddressInfo::TilType(addr_ty) => {
                            ensure!(
                                matches!(&addr_ty, idb_rs::til::Type::Function(_)),
                                "Type for function at {fun_addr:#?} is invalid"
                            );
                            if let Some(_old) = ty.replace(addr_ty) {
                                panic!("Multiple types can't be return for address")
                            }
                        }
                    }
                }
                match (name, ty) {
                    (Some(name), Some(ty)) => println!("\"{name}\":{ty:?}"),
                    (None, None) => println!("NO_INFO"),
                    (None, Some(ty)) => println!("UNAMED:{ty:?}"),
                    (Some(name), None) => println!("\"{name}\""),
                }
            }
            DirTreeEntry::Directory { name, entries } => {
                println!("{name}:");
                print_folder(id0, identation + 1, entries)?;
            }
        }
    }
    Ok(())
}

fn print_ident(ident: usize) {
    let data = vec![b' '; ident];
    print!("{}", String::from_utf8(data).unwrap());
}

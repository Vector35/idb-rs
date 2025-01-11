use idb_rs::id0::{DirTreeEntry, DirTreeRoot};

pub fn print_dirtree<T>(
    mut handle_print: impl FnMut(&T),
    dirtree: &DirTreeRoot<T>,
) {
    inner_print_dirtree(&mut handle_print, &dirtree.entries, 0);
}

fn inner_print_dirtree<T>(
    handle_print: &mut impl FnMut(&T),
    dirtree: &[DirTreeEntry<T>],
    ident: usize,
) {
    for entry in dirtree {
        match entry {
            idb_rs::id0::DirTreeEntry::Leaf(leaf) => {
                print_ident(ident);
                handle_print(leaf);
                println!()
            }
            idb_rs::id0::DirTreeEntry::Directory { name, entries } => {
                print_ident(ident);
                println!("{}", String::from_utf8_lossy(name));
                inner_print_dirtree(handle_print, entries, ident + 1);
            }
        }
    }
}

fn print_ident(ident: usize) {
    print!("{}", (0..ident).map(|_| ' ').collect::<String>());
}

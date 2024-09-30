use std::collections::HashMap;

use anyhow::{anyhow, ensure, Result};

use crate::id0::{unpack_dd, unpack_usize};
use crate::read_c_string;

#[derive(Clone, Debug)]
pub enum DirTreeEntry<T> {
    Leaf(T),
    Directory {
        name: String,
        sub_dirs: Vec<DirTreeEntry<T>>,
    },
}

pub(crate) trait FromDirTreeNumber {
    fn from_number(value: u64) -> Self;
}

impl FromDirTreeNumber for u64 {
    #[inline]
    fn from_number(value: u64) -> Self {
        value
    }
}

pub(crate) fn parse_dirtree<'a, T: FromDirTreeNumber>(
    mut sub_values: impl Iterator<Item = Result<(u64, &'a [u8])>>,
    is_64: bool,
) -> Result<DirTreeEntry<T>> {
    // parse all the raw entries
    let mut expected_entries = 1;
    // TODO is root always 0 or just the first?
    let mut root_idx = None;
    let mut entries = HashMap::with_capacity(sub_values.size_hint().0);
    loop {
        let Some(entry) = sub_values.next() else {
            return Err(anyhow!("Missing entries for dirtree"));
        };
        // TODO map error?
        let (entry_idx, entry_value) = entry?;
        if root_idx.is_none() {
            root_idx = Some(entry_idx);
        }
        let entry = DirTreeEntryRaw::from_raw(entry_value, &mut expected_entries, is_64)?;
        if let Some(_old) = entries.insert(entry_idx, Some(entry)) {
            return Err(anyhow!("Duplicated index dirtree entry"));
        };
        expected_entries -= 1;
        if expected_entries == 0 {
            break;
        }
    }

    // assemble the raw_entries into a tree
    // first entry is always the root
    let root = entries.get_mut(&root_idx.unwrap()).unwrap().take().unwrap();
    let name = root.name;
    ensure!(name.is_empty(), "DirTree With a named root");
    ensure!(root.parent == 0, "Dirtree Root with parent");
    let sub_dirs = dirtree_directory_from_raw(&mut entries, 0, root.entries)?;

    Ok(DirTreeEntry::Directory { name, sub_dirs })
}

fn dirtree_directory_from_raw<T: FromDirTreeNumber>(
    raw: &mut HashMap<u64, Option<DirTreeEntryRaw>>,
    parent_idx: u64,
    entries: Vec<DirTreeEntryChildRaw>,
) -> Result<Vec<DirTreeEntry<T>>> {
    let sub_dirs = entries
        .into_iter()
        .map(|DirTreeEntryChildRaw { number, is_value }| {
            if is_value {
                // simple value, just make a leaf
                return Ok(DirTreeEntry::Leaf(T::from_number(number)));
            }
            // otherwise create the dirtree for the entry at "number"
            let sub_entry = raw
                .get_mut(&number)
                .ok_or_else(|| anyhow!("Invalid dirtree subfolder index"))?
                .take()
                .ok_or_else(|| anyhow!("Same entry in dirtree is owned by multiple parents"))?;
            ensure!(
                sub_entry.parent == parent_idx,
                "Invalid parent idx for entry in dirtree"
            );
            Ok(DirTreeEntry::Directory {
                name: sub_entry.name,
                sub_dirs: dirtree_directory_from_raw(raw, number, sub_entry.entries)?,
            })
        })
        .collect::<Result<_>>()?;
    Ok(sub_dirs)
}

#[derive(Clone, Debug)]
struct DirTreeEntryRaw {
    name: String,
    parent: u64,
    entries: Vec<DirTreeEntryChildRaw>,
}

impl DirTreeEntryRaw {
    fn from_raw(data: &[u8], extra_entries: &mut usize, is_64: bool) -> Result<Self> {
        let mut data = data;
        let _unknown_always_1: u8 = bincode::deserialize_from(&mut data)?;
        ensure!(_unknown_always_1 == 1);
        let name = read_c_string(&mut data)?;
        // TODO maybe just a unpack_dd followed by \x00
        let parent = unpack_usize(&mut data, is_64)?;
        // this value had known values of 0 and 4, as long it's smaller then 0x80 there no
        // much of a problem, otherwise this could be a unpack_dw/unpack_dd
        let _unknown: u8 = bincode::deserialize_from(&mut data)?;
        ensure!(_unknown < 0x80);
        // TODO unpack_dw/u8?
        let entries_len = unpack_dd(&mut data)?;

        // populate the value part of the entries
        let mut last_value = 0i64;
        let mut entries: Vec<_> = (0..entries_len)
            .map(|_| {
                let value = unpack_usize(&mut data, is_64)?;
                last_value = last_value.wrapping_add(value as i64);
                Ok(DirTreeEntryChildRaw {
                    number: last_value as u64,
                    is_value: false,
                })
            })
            .collect::<Result<_>>()?;

        let mut current_entry = &mut entries[..];
        let mut read_entries = 0;
        // read the number of folders followed by the number of files, until all entries are
        // read and no extra data is left
        for is_value in core::iter::successors(Some(false), |x| Some(!(*x))) {
            // TODO unpack_dw/u8?
            let num = unpack_dd(&mut data)?;
            read_entries += num;
            let num = usize::try_from(num).map_err(|_| anyhow!("Invalid number of entries"))?;
            ensure!(
                current_entry.len() >= num,
                "Invalid number of entry of type in dirtree"
            );
            if is_value {
                for i in 0..num {
                    current_entry[i].is_value = true;
                }
            } else {
                // NOTE there is no need to write false to the entry because it's false by default

                // there will be at least this number of entries after this one, one for each folder
                *extra_entries += num;
            }
            current_entry = &mut current_entry[num..];
            match read_entries.cmp(&entries_len) {
                // continue because there is more entries
                std::cmp::Ordering::Less => {}
                // read all the entries, finish reading
                std::cmp::Ordering::Equal => break,
                std::cmp::Ordering::Greater => {
                    return Err(anyhow!(
                        "More listed dirtree entries that the number of elements"
                    ))
                }
            }
        }

        ensure!(data.is_empty(), "Entra data after dirtree Entry");
        Ok(Self {
            name,
            parent,
            entries,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct DirTreeEntryChildRaw {
    number: u64,
    is_value: bool,
}

use std::collections::HashMap;

use anyhow::{anyhow, ensure, Result};

use crate::id0::{unpack_dd, unpack_usize};
use crate::read_c_string;
use crate::til::section::TILSection;
use crate::til::TILTypeInfo;

use super::ID0Section;

#[derive(Clone, Debug)]
pub struct DirTreeRoot<T> {
    pub entries: Vec<DirTreeEntry<T>>,
}

#[derive(Clone, Debug)]
pub enum DirTreeEntry<T> {
    Leaf(T),
    Directory {
        name: String,
        entries: Vec<DirTreeEntry<T>>,
    },
}

pub(crate) trait FromDirTreeNumber {
    type Output;
    fn build(&mut self, value: u64) -> Result<Self::Output>;
}

pub(crate) struct U64FromDirTree;
impl FromDirTreeNumber for U64FromDirTree {
    type Output = u64;
    #[inline]
    fn build(&mut self, value: u64) -> Result<Self::Output> {
        Ok(value)
    }
}

pub(crate) struct LabelFromDirTree<'a> {
    pub(crate) id0: &'a ID0Section,
}
impl<'a> FromDirTreeNumber for LabelFromDirTree<'a> {
    type Output = (u64, &'a str);
    #[inline]
    fn build(&mut self, address: u64) -> Result<Self::Output> {
        let name = self.id0.label_at(address).and_then(|label| {
            label.ok_or_else(|| anyhow!("Missing label entry on ID0 for address {address:#x}"))
        })?;
        Ok((address, name))
    }
}

pub(crate) struct TilFromDirTree<'a> {
    pub(crate) til: &'a TILSection,
}
impl<'a> FromDirTreeNumber for TilFromDirTree<'a> {
    type Output = &'a TILTypeInfo;
    #[inline]
    fn build(&mut self, value: u64) -> Result<Self::Output> {
        self.til
            .types
            .iter()
            .find(|ty| ty.ordinal == value)
            .ok_or_else(|| anyhow!("Could not find a TIL type with ordinal {value}"))
    }
}

/// Dirtree example:
/// "\x2e\xff\x00\x00\x31\x53\x00\x00\x00\x00":"\x01\x00\x00\x00\x05\x90\x80\xff\xff\xff\xef\x81\x8f\xff\xff\xff\xff\xf0\x02\x94\xea\x00\x01\x01\x01\x01\x01"
/// "\x2e\xff\x00\x00\x31\x53\x00\x01\x00\x00":"\x01\x61\x00\x00\x00\x0c\xc0\x00\x40\x20\x04\x04\x04\x04\x04\x04\xff\xff\xff\xcf\xf8\x10\x10\x10\x10\x00\x0c"
/// "\x2e\xff\x00\x00\x31\x53\x00\x02\x00\x00":"\x01\x62\x00\x00\x00\x0d\x90\x20\x80\x88\x08\x10\x80\xe9\x04\x80\xe7\x82\x36\x06\xff\xff\xff\xfc\xd0\xff\xff\xff\xff\x60\x50\x83\x0a\x00\x0d"
/// ...
/// "N$ dirtree/funcs":"\x31\x00\x00\xff"
pub(crate) fn parse_dirtree<'a, T, I>(
    sub_values: I,
    mut builder: T,
    is_64: bool,
) -> Result<DirTreeRoot<T::Output>>
where
    T: FromDirTreeNumber,
    I: IntoIterator<Item = Result<(u64, &'a [u8])>>,
{
    // parse all the raw entries
    let sub_values = sub_values.into_iter();
    let mut entries = HashMap::with_capacity(sub_values.size_hint().0);
    // TODO is root always 0 or just the first?
    // This is assuming the first entry is the root, because this is more general
    let mut root_idx = None;
    for entry in sub_values {
        let (entry_idx, entry_value) = entry?;
        root_idx.get_or_insert(entry_idx);

        let entry = DirTreeEntryRaw::from_raw(entry_value, is_64)?;
        if let Some(_old) = entries.insert(entry_idx, Some(entry)) {
            return Err(anyhow!("Duplicated dirtree index entry"));
        };
    }

    // assemble the raw_entries into a tree
    // first entry is always the root
    let root = entries.get_mut(&root_idx.unwrap()).unwrap().take().unwrap();
    let name = root.name;
    ensure!(name.is_empty(), "DirTree With a named root");
    ensure!(root.parent == 0, "Dirtree Root with parent");
    let dirs = dirtree_directory_from_raw(&mut entries, &mut builder, 0, root.entries)?;

    Ok(DirTreeRoot { entries: dirs })
}

fn dirtree_directory_from_raw<T: FromDirTreeNumber>(
    raw: &mut HashMap<u64, Option<DirTreeEntryRaw>>,
    builder: &mut T,
    parent_idx: u64,
    entries: Vec<DirTreeEntryChildRaw>,
) -> Result<Vec<DirTreeEntry<T::Output>>> {
    let sub_dirs = entries
        .into_iter()
        .map(|DirTreeEntryChildRaw { number, is_value }| {
            if is_value {
                // simple value, just make a leaf
                return Ok(DirTreeEntry::Leaf(builder.build(number)?));
            }
            // otherwise create the dirtree for the entry at "number"
            let raw_entry = raw
                .get_mut(&number)
                .ok_or_else(|| anyhow!("Invalid dirtree subfolder index"))?
                .take()
                .ok_or_else(|| anyhow!("Same entry in dirtree is owned by multiple parents"))?;
            let DirTreeEntryRaw {
                name,
                parent,
                entries,
            } = raw_entry;
            ensure!(
                parent == parent_idx,
                "Invalid parent idx for entry in dirtree"
            );
            let entries = dirtree_directory_from_raw(raw, &mut *builder, number, entries)?;
            Ok(DirTreeEntry::Directory { name, entries })
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
    fn from_raw(data: &[u8], is_64: bool) -> Result<Self> {
        let mut data = data;
        // part 1: header
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

        // part 2: populate the value part of the entries
        let mut last_value: Option<u64> = None;
        let mut entries: Vec<_> = (0..entries_len)
            .map(|_| {
                let rel_value = unpack_usize(&mut data, is_64)?;
                let value = match last_value {
                    // first value is absolute
                    None => rel_value,
                    // other are relative from the previous
                    Some(last_value_old) => {
                        let mut value = last_value_old.wrapping_add_signed(rel_value as i64);
                        // NOTE that in 32bits it wrapps using the u32 limit
                        if !is_64 {
                            value = value & (u32::MAX as u64);
                        }
                        value
                    }
                };
                last_value = Some(value);
                Ok(DirTreeEntryChildRaw {
                    number: value,
                    is_value: false,
                })
            })
            .collect::<Result<_>>()?;

        // part 3: Classification for entries
        let mut current_entry = &mut entries[..];
        // classify the entries on this folder as `sub_folder` or `leaf` (value), the data is in the format:
        // [`number of folders` `number of leafs`..], that repeats until all the entries are classified as
        // one or the other.
        // NOTE in case the folder have 0 elements, there will be a 0 value, but don't take that for granted
        for is_value in core::iter::successors(Some(false), |x| Some(!(*x))) {
            // TODO unpack_dw/u8?
            let num = match unpack_dd(&mut data) {
                Ok(num) => num,
                // this is an empty folder, so the last value is optional
                Err(_) if entries_len == 0 => break,
                Err(e) => return Err(e),
            };
            let num = usize::try_from(num).map_err(|_| anyhow!("Invalid number of entries"))?;
            ensure!(
                current_entry.len() >= num,
                "Invalid number of entry of type in dirtree"
            );
            if is_value {
                current_entry[0..num]
                    .iter_mut()
                    .for_each(|entry| entry.is_value = true);
            } else {
                // NOTE there is no need to write false to the entry because it's false by default
            }
            current_entry = &mut current_entry[num..];
            if current_entry.is_empty() {
                // read all the entries, finish reading
                break;
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

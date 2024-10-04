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

/// Each id0 entry is folder, the first entry is always the root, it's unclear if its always 0,
/// but that seems to be the rule.
///
/// The id0 entry key contains the index, it's always shitfted 16 bits to
/// the left (both in 32/64 bits), the meaning for the value in the lower 16 bits of the key
/// is is the sub-index in case the folder need to be split into multiple entries.
///
/// The value of the entry is described by [DirTreeEntryRaw::from_raw]. Each entry is one folder
/// or the continuation of a previous folder, if it's too big.
///
/// ### Example
/// "\x2e\xff\x00\x00\x31\x53\x00\x00\x00\x00":"\x01\x00\x00\x00\x05\x90\x80\xff\xff\xff\xef\x81\x8f\xff\xff\xff\xff\xf0\x02\x94\xea\x00\x01\x01\x01\x01\x01"
/// "\x2e\xff\x00\x00\x31\x53\x00\x01\x00\x00":"\x01\x61\x00\x00\x00\x0c\xc0\x00\x40\x20\x04\x04\x04\x04\x04\x04\xff\xff\xff\xcf\xf8\x10\x10\x10\x10\x00\x0c"
/// "\x2e\xff\x00\x00\x31\x53\x00\x02\x00\x00":"\x01\x62\x00\x00\x00\x0d\x90\x20\x80\x88\x08\x10\x80\xe9\x04\x80\xe7\x82\x36\x06\xff\xff\xff\xfc\xd0\xff\xff\xff\xff\x60\x50\x83\x0a\x00\x0d"
/// ...
/// "N$ dirtree/funcs":"\x31\x00\x00\xff"
pub(crate) fn parse_dirtree<'a, T, I>(
    entries_iter: I,
    mut builder: T,
    is_64: bool,
) -> Result<DirTreeRoot<T::Output>>
where
    T: FromDirTreeNumber,
    I: IntoIterator<Item = Result<(u64, u16, &'a [u8])>>,
{
    let mut entries_iter = entries_iter.into_iter();
    // parse all the raw entries
    let mut entries_raw = HashMap::new();
    // This is assuming the first entry is the root, because this is more general that assume it's always 0
    let mut root_idx = None;
    loop {
        let Some(entry) = entries_iter.next() else {
            break;
        };
        let (idx, sub_idx, entry_value) = entry?;
        ensure!(sub_idx == 0, "Non zero sub_idx for dirtree folder entry");
        let reader = DirtreeEntryRead {
            entry_value,
            idx,
            last_sub_idx: 0,
            iter: &mut entries_iter,
        };
        let entry = DirTreeEntryRaw::from_raw(reader, is_64)?;
        root_idx.get_or_insert(idx);
        if let Some(_old) = entries_raw.insert(idx, Some(entry)) {
            return Err(anyhow!("Duplicated dirtree index entry"));
        };
    }

    // assemble the raw_entries into a tree
    // first entry is always the root
    let root = entries_raw
        .get_mut(&root_idx.unwrap())
        .unwrap()
        .take()
        .unwrap();
    let name = root.name;
    ensure!(name.is_empty(), "DirTree With a named root");
    ensure!(root.parent == 0, "Dirtree Root with parent");
    let dirs = dirtree_directory_from_raw(&mut entries_raw, &mut builder, 0, root.entries)?;

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
    /// ## example for raw value in 32bits:
    /// Folder named `a` in the root dir containing just entries, no sub_folders
    /// `\x01\x61\x00\x00\x00\x0c\xc0\x00\x40\x20\x04\x04\x04\x04\x04\x04\xff\xff\xff\xcf\xf8\x10\x10\x10\x10\x00\x0c`
    ///
    /// ### Part 1: Header
    ///
    /// | data type         | value      | comment |
    /// |-------------------|------------|---------|
    /// | _unknown_always_1 | \x01       |         |
    /// | name              | \x61\x00   | "a"     |
    /// | parent            | \x00       | root    |
    /// | _unknown          | \x00       |         |
    /// | entries_len       | \x0c       | 12      |
    ///
    /// ### Part 2: Entries in the folder
    ///
    /// NOTE that values are relative to the prvious one, except the first that is absolute
    ///
    /// | entry number       | value                   | comment                      |
    /// |--------------------|-------------------------|------------------------------|
    /// | entry_0            | \xc0\x00\x40\x20        | 16416                        |
    /// | entry_1            | \x04                    | last_entry + 4 = 16420       |
    /// | entry_2            | \x04                    | last_entry + 4 = 16424       |
    /// | entry_3            | \x04                    | last_entry + 4 = 16428       |
    /// | entry_4            | \x04                    | last_entry + 4 = 16432       |
    /// | entry_5            | \x04                    | last_entry + 4 = 16436       |
    /// | entry_6            | \x04                    | last_entry + 4 = 16440       |
    /// | entry_7            | \xff\xff\xff\xcf\xf8    | last_entry + (-12296) = 4144 |
    /// | entry_8            | \x10                    | last_entry + 16 = 4160       |
    /// | entry_9            | \x10                    | last_entry + 16 = 4176       |
    /// | entry_10           | \x10                    | last_entry + 16 = 4192       |
    /// | entry_11           | \x10                    | last_entry + 16 = 4208       |
    ///
    /// ### Part 3: Classification for entries
    /// | entry range type   | value  | comment                         |
    /// | -------------------|--------|---------------------------------|
    /// | entries folder     | \x00   | 0..0 are folders                |
    /// | entries values     | \x0c   | from 0..12 are values           |
    ///
    fn from_raw<'a, I>(mut data: DirtreeEntryRead<'a, I>, is_64: bool) -> Result<Self>
    where
        I: Iterator<Item = Result<(u64, u16, &'a [u8])>>,
    {
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

        ensure!(
            data.entry_value.is_empty(),
            "Entra data after dirtree Entry"
        );
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

struct DirtreeEntryRead<'a, I> {
    entry_value: &'a [u8],
    idx: u64,
    last_sub_idx: u16,
    iter: I,
}
impl<'a, I> DirtreeEntryRead<'a, I>
where
    I: Iterator<Item = Result<(u64, u16, &'a [u8])>>,
{
    // get the next entry on the database
    fn next_entry(&mut self) -> std::io::Result<()> {
        loop {
            let Some(next_entry) = self.iter.next() else {
                return Ok(());
            };
            let (idx, sub_idx, entry) = next_entry.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Missing part of dirtree entry",
                )
            })?;
            if idx != self.idx {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid index for dirtree",
                ));
            }
            if self.last_sub_idx == u16::MAX {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Too many sub-entries for dirtree entry",
                ));
            }
            if self.last_sub_idx + 1 != sub_idx {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid sub-index for dirtree entry",
                ));
            }
            self.last_sub_idx = sub_idx;
            self.entry_value = entry;
            // that's probably never will happen, but I will allow the code to skip empty
            // sub-entries
            if !self.entry_value.is_empty() {
                break;
            }
        }
        Ok(())
    }
}

impl<'a, I> std::io::Read for DirtreeEntryRead<'a, I>
where
    I: Iterator<Item = Result<(u64, u16, &'a [u8])>>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.entry_value.is_empty() {
            self.next_entry()?;
        }
        let copy_len = buf.len().min(self.entry_value.len());
        buf[..copy_len].copy_from_slice(&self.entry_value[..copy_len]);
        self.entry_value = &self.entry_value[copy_len..];
        Ok(copy_len)
    }
}

impl<'a, I> std::io::BufRead for DirtreeEntryRead<'a, I>
where
    I: Iterator<Item = Result<(u64, u16, &'a [u8])>>,
{
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.entry_value.is_empty() {
            self.next_entry()?;
        }
        Ok(self.entry_value)
    }

    fn consume(&mut self, amt: usize) {
        self.entry_value = &self.entry_value[amt..];
    }
}

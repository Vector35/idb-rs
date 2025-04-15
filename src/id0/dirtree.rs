use std::collections::HashMap;

use anyhow::{anyhow, ensure, Result};
use num_traits::WrappingAdd;

use crate::ida_reader::{IdbBufRead, IdbReadKind};
use crate::{IDAKind, IDAUsize};

use super::Id0AddressKey;

#[derive(Clone, Debug)]
pub struct DirTreeRoot<T> {
    pub entries: Vec<DirTreeEntry<T>>,
}

impl<T> DirTreeRoot<T> {
    pub fn visit_leafs(&self, mut handle: impl FnMut(&T)) {
        Self::inner_visit_leafs(&mut handle, &self.entries);
    }

    fn inner_visit_leafs(
        handle: &mut impl FnMut(&T),
        entries: &[DirTreeEntry<T>],
    ) {
        for entry in entries {
            match entry {
                DirTreeEntry::Leaf(entry) => handle(entry),
                DirTreeEntry::Directory { name: _, entries } => {
                    Self::inner_visit_leafs(&mut *handle, entries)
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum DirTreeEntry<T> {
    Leaf(T),
    Directory {
        name: Vec<u8>,
        entries: Vec<DirTreeEntry<T>>,
    },
}

pub(crate) trait FromDirTreeNumber<K: IDAUsize> {
    fn new(value: K) -> Self;
}

impl<K: IDAUsize> FromDirTreeNumber<K> for K {
    fn new(value: K) -> K {
        value
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id0Address<K: IDAKind> {
    address: K::Usize,
}
impl<K: IDAKind> FromDirTreeNumber<K::Usize> for Id0Address<K> {
    fn new(address: K::Usize) -> Self {
        Self { address }
    }
}
impl<K: IDAKind> Id0AddressKey<K::Usize> for Id0Address<K> {
    fn as_u64(&self) -> K::Usize {
        self.address
    }
}

// TODO this can't be right
#[derive(Clone, Copy, Debug)]
pub struct Id0TilOrd {
    // TODO remove this pub
    pub ord: u64,
}
impl<K: IDAUsize> FromDirTreeNumber<K> for Id0TilOrd {
    fn new(ord: K) -> Self {
        Self { ord: ord.into() }
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
pub(crate) fn parse_dirtree<'a, T, I, K: IDAKind>(
    entries_iter: I,
) -> Result<DirTreeRoot<T>>
where
    T: FromDirTreeNumber<K::Usize>,
    I: IntoIterator<Item = Result<(K::Usize, u16, &'a [u8])>>,
{
    // parse all the raw entries
    let mut entries_raw = HashMap::new();
    // This is assuming the first entry is the root, because this is more general that assume it's always 0
    let mut reader = DirtreeEntryRead::<'_, _, K> {
        iter: entries_iter.into_iter(),
        // dummy value so next_entry() will get the first one
        state: DirtreeEntryState::Reading {
            idx: K::Usize::from(0u8),
            sub_idx: 0,
            entry: &[],
        },
    };
    let mut root_idx = None;
    loop {
        let Some(idx) = reader.next_entry()? else {
            break;
        };
        root_idx.get_or_insert(idx);
        let entry = DirTreeEntryRaw::<K>::from_raw(&mut reader)?;
        ensure!(!reader.have_data_left(), "Entry have data after dirtree");
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
    ensure!(
        root.parent == K::Usize::from(0u8),
        "Dirtree Root with parent"
    );
    let dirs = dirtree_directory_from_raw(
        &mut entries_raw,
        K::Usize::from(0u8),
        root.entries,
    )?;

    Ok(DirTreeRoot { entries: dirs })
}

fn dirtree_directory_from_raw<T: FromDirTreeNumber<K::Usize>, K: IDAKind>(
    raw: &mut HashMap<K::Usize, Option<DirTreeEntryRaw<K>>>,
    parent_idx: K::Usize,
    entries: Vec<DirTreeEntryChildRaw<K>>,
) -> Result<Vec<DirTreeEntry<T>>> {
    let sub_dirs = entries
        .into_iter()
        .map(|DirTreeEntryChildRaw { number, is_value }| {
            if is_value {
                // simple value, just make a leaf
                return Ok(DirTreeEntry::Leaf(T::new(number)));
            }
            // otherwise create the dirtree for the entry at "number"
            let raw_entry = raw
                .get_mut(&number)
                .ok_or_else(|| anyhow!("Invalid dirtree subfolder index"))?
                .take()
                .ok_or_else(|| {
                    anyhow!(
                        "Same entry in dirtree is owned by multiple parents"
                    )
                })?;
            let DirTreeEntryRaw {
                name,
                parent,
                entries,
            } = raw_entry;
            ensure!(
                parent == parent_idx,
                "Invalid parent idx for entry in dirtree"
            );
            let entries = dirtree_directory_from_raw(raw, number, entries)?;
            Ok(DirTreeEntry::Directory { name, entries })
        })
        .collect::<Result<_>>()?;
    Ok(sub_dirs)
}

#[derive(Clone, Debug)]
struct DirTreeEntryRaw<K: IDAKind> {
    name: Vec<u8>,
    parent: K::Usize,
    entries: Vec<DirTreeEntryChildRaw<K>>,
}

impl<K: IDAKind> DirTreeEntryRaw<K> {
    fn from_raw<I: IdbBufRead + IdbReadKind<K>>(data: &mut I) -> Result<Self> {
        // TODO It's unclear if this value is a version, it seems so
        match data.read_u8()? {
            0 => Self::from_raw_v0(data),
            1 => Self::from_raw_v1(data),
            v => Err(anyhow!("dirtree invalid version {v}")),
        }
    }

    fn from_raw_v0<I: IdbBufRead + IdbReadKind<K>>(
        data: &mut I,
    ) -> Result<Self> {
        // part 1: header
        let name = data.read_c_string_raw()?;
        // TODO maybe just a unpack_dd followed by \x00
        let parent = data.unpack_usize()?;
        let _unknown: u8 = bincode::deserialize_from(&mut *data)?;

        // part 2: populate the value part of the entries
        let mut entries = vec![];
        for is_value in core::iter::successors(Some(false), |x| Some(!(*x))) {
            // TODO unpack_dw/u8?
            let Some(entries_len) = data.unpack_dd_or_eof()? else {
                break;
            };
            parse_entries(&mut *data, &mut entries, entries_len, is_value)?;
        }

        Ok(Self {
            name,
            parent,
            entries,
        })
    }

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
    fn from_raw_v1<I: IdbBufRead + IdbReadKind<K>>(
        data: &mut I,
    ) -> Result<Self> {
        // part 1: header
        let name = data.read_c_string_raw()?;
        // TODO maybe just a unpack_dd followed by \x00
        let parent = data.unpack_usize()?;
        // this value had known values of 0 and 4, as long it's smaller then 0x80 there no
        // much of a problem, otherwise this could be a unpack_dw/unpack_dd
        let _unknown: u8 = bincode::deserialize_from(&mut *data)?;
        #[cfg(feature = "restrictive")]
        ensure!(_unknown < 0x80);
        // TODO unpack_dw/u8?
        let entries_len = data.unpack_dd()?;

        // part 2: populate the value part of the entries
        let mut entries = Vec::with_capacity(entries_len.try_into().unwrap());
        parse_entries(&mut *data, &mut entries, entries_len, false)?;

        // part 3: Classification for entries
        let mut current_entry = &mut entries[..];
        // classify the entries on this folder as `sub_folder` or `leaf` (value), the data is in the format:
        // [`number of folders` `number of leafs`..], that repeats until all the entries are classified as
        // one or the other.
        // NOTE in case the folder have 0 elements, there will be a 0 value, but don't take that for granted
        for is_value in core::iter::successors(Some(false), |x| Some(!(*x))) {
            // TODO unpack_dw/u8?
            let Some(num) = data.unpack_dd_or_eof()? else {
                if entries_len == 0 {
                    // this is an empty folder, so the last value is optional
                    break;
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Unexpected EoF while reading dirtree entries",
                    )
                    .into());
                }
            };
            let num = usize::try_from(num)
                .map_err(|_| anyhow!("Invalid number of entries"))?;
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

        Ok(Self {
            name,
            parent,
            entries,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct DirTreeEntryChildRaw<K: IDAKind> {
    number: K::Usize,
    is_value: bool,
}

struct DirtreeEntryRead<'a, I, K: IDAKind> {
    iter: I,
    state: DirtreeEntryState<'a, K>,
}

enum DirtreeEntryState<'a, K: IDAKind> {
    Reading {
        idx: K::Usize,
        sub_idx: u16,
        entry: &'a [u8],
    },
    Next {
        idx: K::Usize,
        entry: &'a [u8],
    },
}

impl<'a, I, K: IDAKind> DirtreeEntryRead<'a, I, K>
where
    I: Iterator<Item = Result<(K::Usize, u16, &'a [u8])>>,
{
    // get the next entry on the database
    fn next_entry(&mut self) -> Result<Option<K::Usize>> {
        let (idx, sub_idx, entry) = match self.state {
            DirtreeEntryState::Reading { entry: &[], .. } => {
                let Some(next_entry) = self.iter.next() else {
                    // no more entries
                    return Ok(None);
                };
                let (idx, sub_idx, entry) = next_entry
                    .map_err(|_| anyhow!("Missing expected dirtree entry"))?;
                if sub_idx != 0 {
                    return Err(anyhow!(
                        "Non zero sub_idx for dirtree folder entry"
                    ));
                }
                (idx, sub_idx, entry)
            }
            DirtreeEntryState::Reading { .. } => {
                panic!("Can't advance to next entry without consuming the current one")
            }
            DirtreeEntryState::Next { idx, entry } => (idx, 0, entry),
        };
        self.state = DirtreeEntryState::Reading {
            idx,
            sub_idx,
            entry,
        };
        Ok(Some(idx))
    }

    // get the continuation of the current entry
    fn next_sub_entry(&mut self) -> std::io::Result<bool> {
        match &mut self.state {
            DirtreeEntryState::Reading {
                idx,
                sub_idx,
                entry: entry @ &[],
            } => {
                loop {
                    let Some(next_entry) = self.iter.next() else {
                        return Ok(false);
                    };
                    let (next_idx, next_sub_idx, next_entry) = next_entry
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "Missing part of dirtree entry",
                            )
                        })?;
                    if next_idx != *idx {
                        // found a EoF for this entry
                        if next_sub_idx != 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Invalid sub_index for dirtree",
                            ));
                        }
                        self.state = DirtreeEntryState::Next {
                            idx: next_idx,
                            entry: next_entry,
                        };
                        return Ok(false);
                    }
                    if next_sub_idx != *sub_idx + 1 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid sub-index for dirtree entry",
                        ));
                    }
                    *sub_idx = next_sub_idx;
                    *entry = next_entry;
                    // that's probably never will happen, but I will allow the code to skip empty
                    // sub-entries
                    if !entry.is_empty() {
                        break;
                    }
                }
                Ok(true)
            }
            DirtreeEntryState::Reading { .. } => {
                panic!("Can't advance to next sub_entry without consuming the current one")
            }
            // this data is finished
            DirtreeEntryState::Next { .. } => Ok(false),
        }
    }

    fn have_data_left(&self) -> bool {
        match self.state {
            DirtreeEntryState::Reading { entry: &[], .. } => false,
            DirtreeEntryState::Reading { entry: &[..], .. } => true,
            DirtreeEntryState::Next { .. } => false,
        }
    }
}

impl<'a, I, K: IDAKind> std::io::Read for DirtreeEntryRead<'a, I, K>
where
    I: Iterator<Item = Result<(K::Usize, u16, &'a [u8])>>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let is_empty = match self.state {
            DirtreeEntryState::Next { .. } => return Ok(0),
            DirtreeEntryState::Reading { entry, .. } => entry.is_empty(),
        };
        if is_empty {
            // get the next sub_entry, if any
            if !self.next_sub_entry()? {
                return Ok(0);
            }
        }
        let DirtreeEntryState::Reading { entry, .. } = &mut self.state else {
            unreachable!()
        };
        let copy_len = buf.len().min(entry.len());
        buf[..copy_len].copy_from_slice(&entry[..copy_len]);
        *entry = &entry[copy_len..];
        Ok(copy_len)
    }
}

impl<'a, I, K: IDAKind> std::io::BufRead for DirtreeEntryRead<'a, I, K>
where
    I: Iterator<Item = Result<(K::Usize, u16, &'a [u8])>>,
{
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        match self.state {
            DirtreeEntryState::Next { .. } => Ok(&[]),
            DirtreeEntryState::Reading { entry, .. } if !entry.is_empty() => {
                Ok(entry)
            }
            DirtreeEntryState::Reading { .. } => {
                if !self.next_sub_entry()? {
                    return Ok(&[]);
                }
                self.fill_buf()
            }
        }
    }

    fn consume(&mut self, amt: usize) {
        match &mut self.state {
            DirtreeEntryState::Next { .. } => panic!(),
            DirtreeEntryState::Reading { entry, .. } => *entry = &entry[amt..],
        }
    }
}

fn parse_entries<K: IDAKind, I: IdbReadKind<K>>(
    data: &mut I,
    entries: &mut Vec<DirTreeEntryChildRaw<K>>,
    entries_len: u32,
    default_is_value: bool,
) -> Result<()> {
    let mut last_value: Option<K::Usize> = None;
    for _ in 0..entries_len {
        let rel_value = data.unpack_usize()?;
        let value = match last_value {
            // first value is absolute
            None => rel_value,
            // other are relative from the previous
            Some(last_value_old) => last_value_old.wrapping_add(&rel_value),
        };
        last_value = Some(value);
        entries.push(DirTreeEntryChildRaw {
            number: value,
            is_value: default_is_value,
        });
    }
    Ok(())
}

use anyhow::{anyhow, Result};
use num_traits::CheckedAdd;

use crate::ida_reader::IdbReadKind;
use crate::IdbKind;

use super::{ID0Entry, NodeIdx};

#[derive(Clone, Debug)]
pub struct FileRegions<K: IdbKind> {
    pub start: K::Int,
    pub end: K::Int,
    pub eva: K::Int,
}

impl<K: IdbKind> FileRegions<K> {
    fn read(_key: &[u8], data: &[u8], version: u16) -> Result<Self> {
        let mut cursor = data;
        let result = Self::innner_read(&mut cursor, version)?;
        match (version, cursor) {
            (..=699, &[]) => {}
            // TODO some may include an extra 0 byte at the end?
            (700.., &[] | &[0]) => {}
            _ => return Err(anyhow!("Unknown data after the ID0 FileRegions")),
        }
        Ok(result)
    }

    fn innner_read(
        cursor: &mut impl IdbReadKind<K>,
        version: u16,
    ) -> Result<Self> {
        // TODO detect versions with more accuracy
        let (start, end, eva) = match version {
            ..=699 => {
                let start = cursor.read_word()?;
                let end = cursor.read_word()?;
                let rva = cursor.read_u32()?;
                // TODO avoid this into and make it a enum?
                (start, end, rva.into())
            }
            700.. => {
                let start = cursor.unpack_usize()?;
                let len = cursor.unpack_usize()?;
                let end = start.checked_add(&len).ok_or_else(|| {
                    anyhow!("Overflow address in File Regions")
                })?;
                let rva = cursor.unpack_usize()?;
                (start, end, rva)
            }
        };
        Ok(Self { start, end, eva })
    }
}

pub struct FileRegionIdx<K: IdbKind>(pub(crate) NodeIdx<K>);

#[derive(Clone, Copy)]
pub struct FileRegionIter<'a, K: IdbKind> {
    pub(crate) _kind: std::marker::PhantomData<K>,
    pub(crate) segments: &'a [ID0Entry],
    pub(crate) key_len: usize,
    pub(crate) version: u16,
}

impl<'a, K: IdbKind> Iterator for FileRegionIter<'a, K> {
    type Item = Result<FileRegions<K>>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some((current, rest)) = self.segments.split_first() else {
            return None;
        };
        self.segments = rest;
        let key = &current.key[self.key_len..];
        Some(FileRegions::read(key, &current.value, self.version))
    }
}

use anyhow::{anyhow, Result};
use num_traits::CheckedAdd;

use crate::ida_reader::IdbReadKind;
use crate::IDAKind;

use super::{entry_iter::NetnodeSupRangeIter, NetnodeIdx};

#[derive(Clone, Debug)]
pub struct FileRegions<K: IDAKind> {
    pub start: K::Usize,
    pub end: K::Usize,
    pub eva: K::Usize,
}

impl<K: IDAKind> FileRegions<K> {
    fn read(data: &[u8], version: u16) -> Result<Self> {
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
                let start = cursor.read_usize()?;
                let end = cursor.read_usize()?;
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

pub struct FileRegionIdx<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> From<FileRegionIdx<K>> for NetnodeIdx<K> {
    fn from(value: FileRegionIdx<K>) -> Self {
        Self(value.0)
    }
}

#[derive(Clone, Copy)]
pub struct FileRegionIter<'a, K: IDAKind> {
    pub(crate) _kind: std::marker::PhantomData<K>,
    pub(crate) segments: NetnodeSupRangeIter<'a, K>,
    pub(crate) version: u16,
}

impl<K: IDAKind> Iterator for FileRegionIter<'_, K> {
    type Item = Result<FileRegions<K>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.segments.next()? {
            Ok((_addr, current)) => {
                Some(FileRegions::read(&current, self.version))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

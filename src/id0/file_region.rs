use anyhow::{anyhow, ensure, Result};

use crate::ida_reader::{IdaUnpack, IdaUnpacker};

use super::{ID0Entry, ID0Section};

#[derive(Clone, Debug)]
pub struct FileRegions {
    pub start: u64,
    pub end: u64,
    pub eva: u64,
}

impl FileRegions {
    fn read(
        _key: &[u8],
        data: &[u8],
        version: u16,
        is_64: bool,
    ) -> Result<Self> {
        let mut input = IdaUnpacker::new(data, is_64);
        // TODO detect versions with more accuracy
        let (start, end, eva) = match version {
            ..=699 => {
                let start = input.read_word()?;
                let end = input.read_word()?;
                let rva: u32 = bincode::deserialize_from(&mut input)?;
                (start, end, rva.into())
            }
            700.. => {
                let start = input.unpack_usize()?;
                let end = start.checked_add(input.unpack_usize()?).ok_or_else(
                    || anyhow!("Overflow address in File Regions"),
                )?;
                let rva = input.unpack_usize()?;
                // TODO some may include an extra 0 byte at the end?
                if let Ok(_unknown) = input.unpack_usize() {
                    ensure!(_unknown == 0);
                }
                (start, end, rva)
            }
        };
        ensure!(input.inner().is_empty());
        Ok(Self { start, end, eva })
    }
}

pub struct FileRegionIdx<'a>(pub(crate) &'a [u8]);

#[derive(Clone, Copy)]
pub struct FileRegionIter<'a> {
    pub(crate) id0: &'a ID0Section,
    pub(crate) segments: &'a [ID0Entry],
    pub(crate) key_len: usize,
    pub(crate) version: u16,
}

impl<'a> Iterator for FileRegionIter<'a> {
    type Item = Result<FileRegions>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some((current, rest)) = self.segments.split_first() else {
            return None;
        };
        self.segments = rest;
        let key = &current.key[self.key_len..];
        Some(FileRegions::read(
            key,
            &current.value,
            self.version,
            self.id0.is_64,
        ))
    }
}

use super::{ID0Entry, ID0Section};

use anyhow::{anyhow, Result};

#[derive(Clone, Copy, Debug)]
pub struct SegmentPatchIdx<'a>(pub(crate) &'a [u8]);

pub struct Patch {
    pub address: u64,
    pub original_byte: u8,
}

#[derive(Clone, Copy)]
pub struct SegmentPatchOridinalValueIter<'a> {
    pub(crate) id0: &'a ID0Section,
    pub(crate) entries: &'a [ID0Entry],
    pub(crate) key_len: usize,
    //pub(crate) segment_strings: SegmentStringsIter<'a>,
}
impl<'a> SegmentPatchOridinalValueIter<'a> {
    pub(crate) fn new(
        id0: &'a ID0Section,
        entries: &'a [ID0Entry],
        key_len: usize,
    ) -> Self {
        Self {
            id0,
            entries,
            key_len,
        }
    }

    fn patch_from_entry(&self, entry: &ID0Entry) -> Result<Patch> {
        // TODO find the InnerRef for this
        let addr_raw = &entry.key[self.key_len..];
        let address = if self.id0.is_64 {
            addr_raw.try_into().map(u64::from_be_bytes)
        } else {
            addr_raw.try_into().map(u32::from_be_bytes).map(u64::from)
        }
        .map_err(|_| anyhow!("Invalid id1 entry address"))?;

        let original_value_raw = &entry.value[..];
        let original_value = if self.id0.is_64 {
            original_value_raw.try_into().map(u64::from_le_bytes)
        } else {
            original_value_raw
                .try_into()
                .map(u32::from_le_bytes)
                .map(u64::from)
        }
        .map_err(|_| anyhow!("Invalid id1 entry original value"))?;

        Ok(Patch {
            address,
            // TODO the rest of the value is unknown, it's not the id1 flag...
            original_byte: (original_value & 0xFF) as u8,
        })
    }
}

impl Iterator for SegmentPatchOridinalValueIter<'_> {
    type Item = Result<Patch>;

    fn next(&mut self) -> Option<Self::Item> {
        let (first, rest) = self.entries.split_first()?;
        self.entries = rest;

        Some(self.patch_from_entry(first))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.entries.len(), Some(self.entries.len()))
    }
}

impl ExactSizeIterator for SegmentPatchOridinalValueIter<'_> {}

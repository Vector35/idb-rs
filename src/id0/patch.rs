use crate::{Address, IDAKind};

use super::{ID0Entry, NetnodeIdx};

use anyhow::{anyhow, Result};
use num_traits::AsPrimitive;

#[derive(Clone, Copy, Debug)]
pub struct SegmentPatchIdx<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> From<SegmentPatchIdx<K>> for NetnodeIdx<K> {
    fn from(value: SegmentPatchIdx<K>) -> Self {
        Self(value.0)
    }
}

pub struct Patch<K: IDAKind> {
    pub address: Address<K>,
    pub original_byte: u8,
}

#[derive(Clone, Copy)]
pub struct SegmentPatchOriginalValueIter<'a, K: IDAKind> {
    _kind: std::marker::PhantomData<K>,
    pub(crate) entries: &'a [ID0Entry],
    //pub(crate) segment_strings: SegmentStringsIter<'a>,
}
impl<'a, K: IDAKind> SegmentPatchOriginalValueIter<'a, K> {
    pub(crate) fn new(entries: &'a [ID0Entry]) -> Self {
        Self {
            _kind: std::marker::PhantomData,
            entries,
        }
    }

    fn patch_from_entry(&self, entry: &ID0Entry) -> Result<Patch<K>> {
        // TODO find the InnerRef for this
        let addr_raw = &entry.key[1 + usize::from(K::BYTES)..];

        let address = K::usize_try_from_be_bytes(addr_raw)
            .map(Address::from_raw)
            .ok_or_else(|| anyhow!("Invalid id1 entry address"))?;

        let original_value = K::usize_try_from_le_bytes(&entry.value[..])
            .ok_or_else(|| anyhow!("Invalid id1 entry original value"))?;
        let original_byte = AsPrimitive::<u8>::as_(original_value);

        // TODO the rest of the value is unknown, it's not the id1 flag...
        let _rest_byte = original_value >> 8;
        Ok(Patch {
            address,
            original_byte,
        })
    }
}

impl<K: IDAKind> Iterator for SegmentPatchOriginalValueIter<'_, K> {
    type Item = Result<Patch<K>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (first, rest) = self.entries.split_first()?;
        self.entries = rest;

        Some(self.patch_from_entry(first))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.entries.len(), Some(self.entries.len()))
    }
}

impl<K: IDAKind> ExactSizeIterator for SegmentPatchOriginalValueIter<'_, K> {}

use crate::{IDAKind, IDAUsize};

use super::ID0Entry;

use anyhow::{anyhow, Result};
use byteorder::{BE, LE};
use num_traits::AsPrimitive;

#[derive(Clone, Copy, Debug)]
pub struct SegmentPatchIdx<'a>(pub(crate) &'a [u8]);

pub struct Patch<K: IDAKind> {
    pub address: K::Usize,
    pub original_byte: u8,
}

#[derive(Clone, Copy)]
pub struct SegmentPatchOriginalValueIter<'a, K: IDAKind> {
    _kind: std::marker::PhantomData<K>,
    pub(crate) entries: &'a [ID0Entry],
    pub(crate) key_len: usize,
    //pub(crate) segment_strings: SegmentStringsIter<'a>,
}
impl<'a, K: IDAKind> SegmentPatchOriginalValueIter<'a, K> {
    pub(crate) fn new(entries: &'a [ID0Entry], key_len: usize) -> Self {
        Self {
            _kind: std::marker::PhantomData,
            entries,
            key_len,
        }
    }

    fn patch_from_entry(&self, entry: &ID0Entry) -> Result<Patch<K>> {
        // TODO find the InnerRef for this
        let addr_raw = &entry.key[self.key_len..];

        let address = K::Usize::from_bytes::<BE>(addr_raw)
            .ok_or_else(|| anyhow!("Invalid id1 entry address"))?;

        let original_value = K::Usize::from_bytes::<LE>(&entry.value[..])
            .ok_or_else(|| anyhow!("Invalid id1 entry original value"))?;
        let original_byte = AsPrimitive::<u8>::as_(original_value) & 0xFF;

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

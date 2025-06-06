use std::marker::PhantomData;

use anyhow::{anyhow, Result};

use crate::id0::{get_netnode_from_key, get_tag_from_key, is_key_netnode};
use crate::IDAKind;

use super::{get_sup_from_key, ID0Entry, ID0Section, NetnodeIdx};

pub struct EntryTagSubkeys<'a, K: IDAKind> {
    entries: &'a [ID0Entry],
    netnode: NetnodeIdx<K>,
    tag: u8,
}

impl<'a, K: IDAKind> EntryTagSubkeys<'a, K> {
    pub fn new(
        entries: &'a [ID0Entry],
        netnode: NetnodeIdx<K>,
        tag: u8,
    ) -> Self {
        Self {
            entries,
            netnode,
            tag,
        }
    }
}

impl<'a, K: IDAKind> Iterator for EntryTagSubkeys<'a, K> {
    type Item = &'a ID0Entry;

    fn next(&mut self) -> Option<Self::Item> {
        let (current, rest) = self.entries.split_first()?;
        if !is_key_netnode(&current.key)
            || get_netnode_from_key::<K>(&current.key) != Some(self.netnode.0)
            || get_tag_from_key::<K>(&current.key) != Some(self.tag)
        {
            return None;
        }
        self.entries = rest;
        Some(current)
    }
}

pub struct EntryTagContinuousSubkeys<'a, K: IDAKind> {
    iter: EntryTagSubkeys<'a, K>,
    expected_alt: K::Usize,
}

impl<'a, K: IDAKind> EntryTagContinuousSubkeys<'a, K> {
    pub fn new(
        id0: &'a ID0Section<K>,
        netnode: NetnodeIdx<K>,
        tag: u8,
        start: K::Usize,
    ) -> Self {
        let start_idx =
            id0.netnode_tag_alt_idx(netnode, start, tag).unwrap_or(0);
        let entries = &id0.entries[start_idx..];
        let expected_alt = entries
            .get(0)
            .and_then(|entry| get_sup_from_key::<K>(&entry.key))
            .unwrap_or(0u8.into());
        Self {
            iter: EntryTagSubkeys::new(entries, netnode, tag),
            expected_alt,
        }
    }
}

impl<'a, K: IDAKind> Iterator for EntryTagContinuousSubkeys<'a, K> {
    type Item = &'a ID0Entry;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.iter.next()?;
        if get_sup_from_key::<K>(&current.key) != Some(self.expected_alt) {
            return None;
        }
        self.expected_alt += 1u8.into();
        Some(current)
    }
}

#[derive(Clone, Copy)]
pub struct NetnodeRangeIter<'a, K> {
    pub(crate) entries: &'a [ID0Entry],
    _kind: PhantomData<K>,
}

impl<'a, K> NetnodeRangeIter<'a, K> {
    pub fn new(entries: &'a [ID0Entry]) -> Self {
        Self {
            entries,
            _kind: PhantomData,
        }
    }
}

impl<'a, K: IDAKind> Iterator for NetnodeRangeIter<'a, K> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let key_len = super::key_len_netnode::<K>();
        let (current, rest) = self.entries.split_first()?;
        self.entries = rest;
        Some((&current.key[key_len..], &current.value[..]))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NetnodeSupRangeIter<'a, K> {
    pub(crate) entries: &'a [ID0Entry],
    _kind: PhantomData<K>,
}

impl<'a, K> NetnodeSupRangeIter<'a, K> {
    pub fn new(entries: &'a [ID0Entry]) -> Self {
        Self {
            entries,
            _kind: PhantomData,
        }
    }
}

impl<'a, K: IDAKind> Iterator for NetnodeSupRangeIter<'a, K> {
    type Item = Result<(K::Usize, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        let key_len = super::key_len_netnode_tag::<K>();
        let (current, rest) = self.entries.split_first()?;
        self.entries = rest;
        let key_raw = &current.key[key_len..];
        let Some(key) = K::usize_try_from_be_bytes(key_raw) else {
            return Some(Err(anyhow!("Invalid sup netnode key")));
        };
        Some(Ok((key, &current.value[..])))
    }
}

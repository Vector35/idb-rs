use std::marker::PhantomData;

use anyhow::{anyhow, Result};

use num_traits::ToBytes;

use crate::IDAKind;

use super::{
    key_from_netnode_tag, key_len_netnode_tag, ID0Entry, ID0Section, NetnodeIdx,
};

pub fn iter_all_subkeys<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    start_idx: usize,
    netnode: NetnodeIdx<K>,
    tag: u8,
) -> impl Iterator<Item = &'a ID0Entry> + use<'a, K> {
    id0.entries[start_idx..].iter().scan((), move |(), entry| {
        let subkey: Vec<u8> =
            key_from_netnode_tag::<K>(netnode.0, tag).collect();
        entry.key.starts_with(&subkey).then_some(entry)
    })
}

pub fn iter_continous_subkeys<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    start_idx: usize,
    netnode: NetnodeIdx<K>,
    tag: u8,
    start: K::Usize,
) -> impl Iterator<Item = &'a ID0Entry> + use<'a, K> {
    iter_all_subkeys(id0, start_idx, netnode, tag).scan(
        start,
        move |current_subidx, entry| {
            let subkeylen = key_len_netnode_tag::<K>();
            if &entry.key[subkeylen..] != current_subidx.to_be_bytes().as_ref()
            {
                return None;
            }
            *current_subidx += 1u8.into();
            Some(entry)
        },
    )
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

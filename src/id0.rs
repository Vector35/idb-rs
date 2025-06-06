use std::collections::HashMap;
use std::num::NonZeroU32;

use crate::ida_reader::{IdbRead, IdbReadKind};
use crate::{IDAKind, IDAUsize};

use anyhow::{anyhow, ensure, Result};

mod address_info;
mod btree;
mod db;
mod dirtree;
pub(crate) mod entry_iter;
mod file_region;
pub mod flag;
mod patch;
mod root_info;
mod segment;

pub use address_info::*;
pub use btree::*;
pub use db::*;
pub use dirtree::*;
pub use file_region::*;
use num_traits::ToBytes;
pub use patch::*;
pub use root_info::*;
pub use segment::*;
pub mod function;

// TODO find this on the SDK, maybe migrate this to flags
const NETNODE_PREFIX: u8 = b'.';

pub(crate) const fn key_len_netnode<K: IDAKind>() -> usize {
    // one for the "." + Bytes
    1 + K::BYTES as usize
}

pub(crate) const fn key_len_netnode_tag<K: IDAKind>() -> usize {
    // one for tag
    key_len_netnode::<K>() + 1
}

pub(crate) fn is_key_netnode(key: &[u8]) -> bool {
    key.get(0).map(|i| *i == NETNODE_PREFIX).unwrap_or(false)
}

pub(crate) fn get_netnode_from_key<K: IDAKind>(key: &[u8]) -> Option<K::Usize> {
    let key_len = key_len_netnode::<K>();
    key.get(1..key_len)
        .and_then(|key| K::usize_try_from_be_bytes(key))
}

pub(crate) fn get_tag_from_key<K: IDAKind>(key: &[u8]) -> Option<u8> {
    let key_start = key_len_netnode::<K>();
    key.get(key_start).copied()
}

pub(crate) fn get_sup_from_key<K: IDAKind>(key: &[u8]) -> Option<K::Usize> {
    let key_start = key_len_netnode_tag::<K>();
    key.get(key_start..)
        .and_then(|key| K::usize_try_from_be_bytes(key))
}

pub(crate) fn get_hash_from_key<K: IDAKind>(key: &[u8]) -> Option<&[u8]> {
    let key_start = key_len_netnode_tag::<K>();
    key.get(key_start..)
}

// TODO improve this function, maybe make a one liner
pub(crate) fn key_from_netnode<K: IDAKind>(
    netnode: K::Usize,
) -> impl Iterator<Item = u8> {
    [NETNODE_PREFIX]
        .iter()
        .copied()
        .chain(netnode.to_be_bytes().as_ref().to_vec())
}

pub(crate) fn key_from_netnode_tag<K: IDAKind>(
    netnode: K::Usize,
    tag: u8,
) -> impl Iterator<Item = u8> {
    key_from_netnode::<K>(netnode).chain(Some(tag))
}

pub(crate) fn key_from_netnode_tag_alt<K: IDAKind>(
    netnode: K::Usize,
    tag: u8,
    alt: K::Usize,
) -> impl Iterator<Item = u8> {
    key_from_netnode_tag::<K>(netnode, tag)
        .chain(alt.to_be_bytes().as_ref().to_vec())
}

pub(crate) fn key_from_netnode_tag_hash<K: IDAKind>(
    netnode: K::Usize,
    tag: u8,
    alt: &[u8],
) -> impl Iterator<Item = u8> + use<'_, K> {
    key_from_netnode_tag::<K>(netnode, tag).chain(alt.iter().copied())
}

// parse a string that maybe is finalized with \x00
fn parse_maybe_cstr(data: &[u8]) -> Option<&[u8]> {
    // find the end of the string
    let end_pos = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    // Return the slice up to the first null byte
    Some(&data[..end_pos])
}

enum ID0CStr<'a, K: IDAKind> {
    CStr(&'a [u8]),
    Ref(K::Usize),
}

// parse a string that maybe is finalized with \x00
impl<'a, K: IDAKind> ID0CStr<'a, K> {
    pub(crate) fn parse_cstr_or_subkey(data: &'a [u8]) -> Option<Self> {
        // TODO find the InnerRef, so far I found only the
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x4e20c0
        match data {
            [b'\x00', rest @ ..] => {
                K::usize_try_from_be_bytes(rest).map(ID0CStr::Ref)
            }
            _ => parse_maybe_cstr(data).map(ID0CStr::CStr),
        }
    }
}

fn read_addr_from_key<K: IDAKind>(
    input: &mut impl IdbReadKind<K>,
) -> Result<K::Usize> {
    // skip the '.'
    ensure!(input.read_u8()? == NETNODE_PREFIX);
    // read the key
    input.read_usize_be()
}

fn read_addr_and_tag_from_key<K: IDAKind>(
    input: &mut impl IdbReadKind<K>,
) -> Result<(K::Usize, u8)> {
    let addr = read_addr_from_key::<K>(&mut *input)?;
    let tag = input.read_u8()?;
    Ok((addr, tag))
}

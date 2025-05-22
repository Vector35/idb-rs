use std::collections::HashMap;
use std::num::NonZeroU32;

use crate::ida_reader::{IdbBufRead, IdbRead, IdbReadKind};
use crate::{til, IDAKind, IDAUsize};

use anyhow::{anyhow, ensure, Result};

pub mod flag;

mod segment;
pub use segment::*;
mod root_info;
pub use root_info::*;
mod btree;
pub use btree::*;
mod address_info;
pub use address_info::*;
mod dirtree;
pub use dirtree::*;
mod file_region;
pub use file_region::*;
mod patch;
pub use patch::*;
mod db;
pub use db::*;
pub mod function;

// parse a string that maybe is finalized with \x00
fn parse_maybe_cstr(data: &[u8]) -> Option<&[u8]> {
    // find the end of the string
    let end_pos = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    // make sure there is no data after the \x00
    if data[end_pos..].iter().any(|b| *b != 0) {
        return None;
    }
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
                K::Usize::from_be_bytes(rest).map(ID0CStr::Ref)
            }
            _ => parse_maybe_cstr(data).map(ID0CStr::CStr),
        }
    }
}

fn read_addr_from_key<K: IDAKind>(
    input: &mut impl IdbReadKind<K>,
) -> Result<K::Usize> {
    // skip the '.'
    ensure!(input.read_u8()? == b'.');
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

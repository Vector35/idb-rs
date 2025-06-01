use std::collections::HashMap;
use std::num::NonZeroU32;
use std::ops::Range;

use crate::ida_reader::{IdbBufRead, IdbRead, IdbReadKind};
use crate::{til, IDAKind, IDAUsize};

use anyhow::{anyhow, ensure, Result};

pub mod flag;

mod segment;
use num_traits::CheckedAdd;
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

#[derive(Clone, Debug)]
pub struct IDBFunction<K: IDAKind> {
    pub address: Range<K::Usize>,
    pub flags: u16,
    pub extra: IDBFunctionExtra<K>,
}

#[derive(Clone, Debug)]
pub enum IDBFunctionExtra<K: IDAKind> {
    NonTail {
        frame: K::Usize,
    },
    Tail {
        /// function owner of the function start
        owner: K::Usize,
        refqty: K::Usize,
        _unknown1: u16,
        _unknown2: K::Usize,
    },
}

#[derive(Clone, Debug)]
pub enum FunctionsAndComments<'a, K: IDAKind> {
    // It's just the name "$ funcs"
    Name,
    Function(IDBFunction<K>),
    Comment {
        address: K::Usize,
        comment: Comments<'a>,
    },
    Unknown {
        key: &'a [u8],
        value: &'a [u8],
    },
}

impl<'a, K: IDAKind> FunctionsAndComments<'a, K> {
    fn read(key: &'a [u8], value: &'a [u8]) -> Result<Self> {
        let [key_type, sub_key @ ..] = key else {
            return Err(anyhow!("invalid Funcs subkey"));
        };
        match *key_type {
            flag::netnode::nn_res::NAME_TAG => {
                ensure!(parse_maybe_cstr(value) == Some(&b"$ funcs"[..]));
                Ok(Self::Name)
            }
            flag::netnode::nn_res::ARRAY_SUP_TAG => {
                IDBFunction::read(sub_key, value).map(Self::Function)
            }
            // some kind of style setting, maybe setting font and background color
            b'R' | b'C' if value.starts_with(&[4, 3, 2, 1]) => {
                Ok(Self::Unknown { key, value })
            }
            b'C' => {
                let address = K::Usize::from_be_bytes(sub_key)
                    .ok_or_else(|| anyhow!("Invalid Comment address"))?;
                parse_maybe_cstr(value)
                    .map(|value| Self::Comment {
                        address,
                        comment: Comments::Comment(value),
                    })
                    .ok_or_else(|| anyhow!("Invalid Comment string"))
            }
            b'R' => {
                let address =
                    K::Usize::from_be_bytes(sub_key).ok_or_else(|| {
                        anyhow!("Invalid Repetable Comment address")
                    })?;
                parse_maybe_cstr(value)
                    .map(|value| Self::Comment {
                        address,
                        comment: Comments::RepeatableComment(value),
                    })
                    .ok_or_else(|| anyhow!("Invalid Repetable Comment string"))
            }
            // TODO find the meaning of "$ funcs" b'V' entries
            _ => Ok(Self::Unknown { key, value }),
        }
    }
}

impl<K: IDAKind> IDBFunction<K> {
    // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x37dd30
    // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28f810
    fn read(_key: &[u8], value: &[u8]) -> Result<Self> {
        let mut input = value;
        let address = IdbReadKind::<K>::unpack_address_range(&mut input)?;
        let flags = input.unpack_dw()?;

        // CONST migrate this to mod flags
        const FUNC_TAIL: u16 = 0x8000;
        let extra = if flags & FUNC_TAIL == 0 {
            Self::read_extra_tail(&mut input, address.start)?
        } else {
            Self::read_extra_regular(&mut input)?
        };

        if !input.is_empty() {
            let _value = input.unpack_dq()?;
        }
        // TODO Undestand the InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28f9d8 data
        // TODO make sure all the data is parsed
        //ensure!(input.inner_ref().empty());
        Ok(Self {
            address,
            flags,
            extra,
        })
    }

    fn read_extra_regular(
        input: &mut impl IdbReadKind<K>,
    ) -> Result<IDBFunctionExtra<K>> {
        // TODO Undertand the sub operation at InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28f98f
        let frame = input.unpack_usize()?;
        let _unknown4 = input.unpack_dw()?;
        if _unknown4 == 0 {
            let _unknown5 = input.unpack_dd()?;
        }
        Ok(IDBFunctionExtra::NonTail { frame })
    }

    fn read_extra_tail<R>(
        input: &mut R,
        address_start: K::Usize,
    ) -> Result<IDBFunctionExtra<K>>
    where
        R: IdbBufRead + IdbReadKind<K>,
    {
        // offset of the function owner in relation to the function start
        let owner_offset = input.unpack_usize()?;
        let owner = address_start
            .checked_add(&owner_offset)
            .ok_or_else(|| anyhow!("Owner Function offset is invalid"))?;
        let refqty = input.unpack_usize()?;
        let _unknown1 = input.unpack_dw()?;
        let _unknown2 = input.unpack_usize()?;
        if input.peek_u8()?.is_some() {
            input.consume(1);
        }
        // TODO make data depending on variables that I don't understant
        // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28fa93
        Ok(IDBFunctionExtra::Tail {
            owner,
            refqty,
            _unknown1,
            _unknown2,
        })
    }
}

#[derive(Clone, Debug)]
pub enum EntryPointRaw<'a, K: IDAKind> {
    Name,
    Address { key: K::Usize, address: K::Usize },
    Ordinal { key: K::Usize, ordinal: K::Usize },
    ForwardedSymbol { key: K::Usize, symbol: &'a str },
    FunctionName { key: K::Usize, name: &'a str },
    Unknown { key: &'a [u8], value: &'a [u8] },
}

impl<'a, K: IDAKind> EntryPointRaw<'a, K> {
    fn read(key: &'a [u8], value: &'a [u8]) -> Result<Self> {
        let mut value = value;
        let [key_type, sub_key @ ..] = key else {
            return Err(anyhow!("invalid Funcs subkey"));
        };
        if *key_type == b'N' {
            ensure!(parse_maybe_cstr(value) == Some(&b"$ entry points"[..]));
            return Ok(Self::Name);
        }
        let Some(sub_key) = K::Usize::from_be_bytes(sub_key) else {
            return Ok(Self::Unknown { key, value });
        };
        match *key_type {
            // TODO for some reason the address is one byte extra
            flag::netnode::nn_res::ARRAY_ALT_TAG => {
                IdbReadKind::<K>::read_usize(&mut value)
                    .map(|address| Self::Address {
                        key: sub_key,
                        address: address - K::Usize::from(1u8),
                    })
                    .map_err(|_| anyhow!("Invalid Function address"))
            }
            b'I' => IdbReadKind::<K>::read_usize(&mut value)
                .map(|ordinal| Self::Ordinal {
                    key: sub_key,
                    ordinal,
                })
                .map_err(|_| anyhow!("Invalid Ordinal value")),
            b'F' => parse_maybe_cstr(value)
                .and_then(|symbol| {
                    Some(Self::ForwardedSymbol {
                        key: sub_key,
                        symbol: std::str::from_utf8(symbol).ok()?,
                    })
                })
                .ok_or_else(|| anyhow!("Invalid Forwarded symbol name")),
            flag::netnode::nn_res::ARRAY_SUP_TAG => parse_maybe_cstr(value)
                .and_then(|name| {
                    Some(Self::FunctionName {
                        key: sub_key,
                        name: std::str::from_utf8(name).ok()?,
                    })
                })
                .ok_or_else(|| anyhow!("Invalid Function name")),
            // TODO find the meaning of "$ funcs" b'V' entry
            _ => Ok(Self::Unknown { key, value }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EntryPoint<K: IDAKind> {
    pub name: String,
    pub address: K::Usize,
    pub forwarded: Option<String>,
    pub entry_type: Option<til::Type>,
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

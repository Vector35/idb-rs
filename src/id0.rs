use std::collections::HashMap;
use std::num::NonZeroU32;
use std::ops::Range;

use crate::ida_reader::{IdbBufRead, IdbRead, IdbReadKind};
use crate::{til, IDBSectionCompression, IdbInt, IdbKind};

use anyhow::{anyhow, ensure, Result};
use byteorder::BE;

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
pub struct IDBFunction<K: IdbKind> {
    pub address: Range<K::Int>,
    pub flags: u16,
    pub extra: IDBFunctionExtra<K>,
}

#[derive(Clone, Debug)]
pub enum IDBFunctionExtra<K: IdbKind> {
    NonTail {
        frame: K::Int,
    },
    Tail {
        /// function owner of the function start
        owner: K::Int,
        refqty: K::Int,
        _unknown1: u16,
        _unknown2: K::Int,
    },
}

#[derive(Clone, Debug)]
pub enum FunctionsAndComments<'a, K: IdbKind> {
    // It's just the name "$ funcs"
    Name,
    Function(IDBFunction<K>),
    Comment {
        address: K::Int,
        comment: Comments<'a>,
    },
    Unknown {
        key: &'a [u8],
        value: &'a [u8],
    },
}

impl<'a, K: IdbKind> FunctionsAndComments<'a, K> {
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
                let address = K::Int::from_bytes::<BE>(sub_key)
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
                    K::Int::from_bytes::<BE>(sub_key).ok_or_else(|| {
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

impl<K: IdbKind> IDBFunction<K> {
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
        address_start: K::Int,
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
pub enum EntryPointRaw<'a, K: IdbKind> {
    Name,
    Address { key: K::Int, address: K::Int },
    Ordinal { key: K::Int, ordinal: K::Int },
    ForwardedSymbol { key: K::Int, symbol: &'a str },
    FunctionName { key: K::Int, name: &'a str },
    Unknown { key: &'a [u8], value: &'a [u8] },
}

impl<'a, K: IdbKind> EntryPointRaw<'a, K> {
    fn read(key: &'a [u8], value: &'a [u8]) -> Result<Self> {
        let mut value = value;
        let [key_type, sub_key @ ..] = key else {
            return Err(anyhow!("invalid Funcs subkey"));
        };
        if *key_type == b'N' {
            ensure!(parse_maybe_cstr(value) == Some(&b"$ entry points"[..]));
            return Ok(Self::Name);
        }
        let Some(sub_key) = K::Int::from_bytes::<BE>(sub_key) else {
            return Ok(Self::Unknown { key, value });
        };
        match *key_type {
            // TODO for some reason the address is one byte extra
            flag::netnode::nn_res::ARRAY_ALT_TAG => {
                IdbReadKind::<K>::read_word(&mut value)
                    .map(|address| Self::Address {
                        key: sub_key,
                        address: address - K::Int::from(1u8),
                    })
                    .map_err(|_| anyhow!("Invalid Function address"))
            }
            b'I' => IdbReadKind::<K>::read_word(&mut value)
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
pub struct EntryPoint<K: IdbKind> {
    pub name: String,
    pub address: K::Int,
    pub forwarded: Option<String>,
    pub entry_type: Option<til::Type>,
}

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

enum ID0CStr<'a, K: IdbKind> {
    CStr(&'a [u8]),
    Ref(K::Int),
}

// parse a string that maybe is finalized with \x00
impl<'a, K: IdbKind> ID0CStr<'a, K> {
    pub(crate) fn parse_cstr_or_subkey(data: &'a [u8]) -> Option<Self> {
        // TODO find the InnerRef, so far I found only the
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x4e20c0
        match data {
            [b'\x00', rest @ ..] => {
                K::Int::from_bytes::<BE>(rest).map(ID0CStr::Ref)
            }
            _ => parse_maybe_cstr(data).map(ID0CStr::CStr),
        }
    }
}

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::ops::Range;

use crate::ida_reader::{IdaGenericUnpack, IdaUnpack, IdaUnpacker};
use crate::{til, IDBHeader, IDBSectionCompression};

use anyhow::{anyhow, ensure, Result};

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

#[derive(Clone, Debug)]
pub struct IDBFileRegions {
    pub start: u64,
    pub end: u64,
    pub eva: u64,
}

impl IDBFileRegions {
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

#[derive(Clone, Debug)]
pub enum FunctionsAndComments<'a> {
    // It's just the name "$ funcs"
    Name,
    Function(IDBFunction),
    Comment { address: u64, comment: Comments<'a> },
    Unknown { key: &'a [u8], value: &'a [u8] },
}

impl<'a> FunctionsAndComments<'a> {
    fn read(key: &'a [u8], value: &'a [u8], is_64: bool) -> Result<Self> {
        let [key_type, sub_key @ ..] = key else {
            return Err(anyhow!("invalid Funcs subkey"));
        };
        match *key_type {
            b'N' => {
                ensure!(parse_maybe_cstr(value) == Some(&b"$ funcs"[..]));
                Ok(Self::Name)
            }
            b'S' => {
                IDBFunction::read(sub_key, value, is_64).map(Self::Function)
            }
            // some kind of style setting, maybe setting font and background color
            b'R' | b'C' if value.starts_with(&[4, 3, 2, 1]) => {
                Ok(Self::Unknown { key, value })
            }
            b'C' => {
                let address = parse_number(sub_key, true, is_64)
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
                    parse_number(sub_key, true, is_64).ok_or_else(|| {
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

#[derive(Clone, Debug)]
pub struct IDBFunction {
    pub address: Range<u64>,
    pub flags: u16,
    pub extra: Option<IDBFunctionExtra>,
}

#[derive(Clone, Debug)]
pub enum IDBFunctionExtra {
    NonTail {
        frame: u64,
    },
    Tail {
        /// function owner of the function start
        owner: u64,
        refqty: u64,
    },
}

impl IDBFunction {
    // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28f810
    fn read(_key: &[u8], value: &[u8], is_64: bool) -> Result<Self> {
        let mut input = IdaUnpacker::new(value, is_64);
        let address = input.unpack_address_range()?;
        let flags = input.unpack_dw()?;

        // CONST migrate this to mod flags
        const FUNC_TAIL: u16 = 0x8000;
        let extra = if flags & FUNC_TAIL != 0 {
            Self::read_extra_tail(input, address.start).ok()
        } else {
            Self::read_extra_regular(input).ok()
        };
        // TODO Undertand the InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28f9d8 data
        // TODO make sure all the data is parsed
        //ensure!(input.position() == u64::try_from(data.len()).unwrap());
        Ok(Self {
            address,
            flags,
            extra,
        })
    }

    fn read_extra_regular(
        mut input: impl IdaUnpack,
    ) -> Result<IDBFunctionExtra> {
        // TODO Undertand the sub operation at InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28f98f
        let frame = input.unpack_usize_ext_max()?;
        let _unknown4 = input.unpack_dw()?;
        if _unknown4 == 0 {
            let _unknown5 = input.unpack_dd()?;
        }
        Ok(IDBFunctionExtra::NonTail { frame })
    }

    fn read_extra_tail(
        mut input: impl IdaUnpack,
        address_start: u64,
    ) -> Result<IDBFunctionExtra> {
        // offset of the function owner in relation to the function start
        let owner_offset = input.unpack_usize()? as i64;
        let owner = match address_start.checked_add_signed(owner_offset) {
            Some(0xFFFF_FFFF) => u64::MAX,
            Some(value) => value,
            None => return Err(anyhow!("Owner Function offset is invalid")),
        };
        let refqty = input.unpack_usize_ext_max()?;
        let _unknown1 = input.unpack_dw()?;
        let _unknown2 = input.unpack_usize_ext_max()?;
        // TODO make data depending on variables that I don't understant
        // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28fa93
        Ok(IDBFunctionExtra::Tail { owner, refqty })
    }
}

#[derive(Clone, Debug)]
pub enum EntryPointRaw<'a> {
    Name,
    Address { key: u64, address: u64 },
    Ordinal { key: u64, ordinal: u64 },
    ForwardedSymbol { key: u64, symbol: &'a str },
    FunctionName { key: u64, name: &'a str },
    Unknown { key: &'a [u8], value: &'a [u8] },
}

impl<'a> EntryPointRaw<'a> {
    fn read(key: &'a [u8], value: &'a [u8], is_64: bool) -> Result<Self> {
        let [key_type, sub_key @ ..] = key else {
            return Err(anyhow!("invalid Funcs subkey"));
        };
        if *key_type == b'N' {
            ensure!(parse_maybe_cstr(value) == Some(&b"$ entry points"[..]));
            return Ok(Self::Name);
        }
        let Some(sub_key) = parse_number(sub_key, true, is_64) else {
            return Ok(Self::Unknown { key, value });
        };
        match *key_type {
            // TODO for some reason the address is one byte extra
            b'A' => IdaUnpacker::new(value, is_64)
                .read_word()
                .map(|address| Self::Address {
                    key: sub_key,
                    address: address - 1,
                })
                .map_err(|_| anyhow!("Invalid Function address")),
            b'I' => IdaUnpacker::new(value, is_64)
                .read_word()
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
            b'S' => parse_maybe_cstr(value)
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
pub struct EntryPoint {
    pub name: String,
    pub address: u64,
    pub forwarded: Option<String>,
    pub entry_type: Option<til::Type>,
}

pub(crate) fn parse_number(
    data: &[u8],
    big_endian: bool,
    is_64: bool,
) -> Option<u64> {
    Some(match (data.len(), is_64, big_endian) {
        (8, true, true) => u64::from_be_bytes(data.try_into().unwrap()),
        (8, true, false) => u64::from_le_bytes(data.try_into().unwrap()),
        (4, false, true) => u32::from_be_bytes(data.try_into().unwrap()).into(),
        (4, false, false) => {
            u32::from_le_bytes(data.try_into().unwrap()).into()
        }
        _ => return None,
    })
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

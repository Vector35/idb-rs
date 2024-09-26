use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{BufRead, Cursor, ErrorKind, Read, Seek, SeekFrom};
use std::num::NonZeroU32;
use std::ops::Range;

use crate::{read_bytes_len_u16, read_c_string_raw, til, IDBHeader, IDBSectionCompression};

use anyhow::{anyhow, ensure, Result};

mod segment;
pub use segment::*;
mod root_info;
pub use root_info::*;
mod btree;
pub use btree::*;
mod address_info;
pub use address_info::*;

#[derive(Clone, Debug)]
pub struct IDBFileRegions {
    pub start: u64,
    pub end: u64,
    pub eva: u64,
}

impl IDBFileRegions {
    fn read(key: &[u8], data: &[u8], version: u16, is_64: bool) -> Result<Self> {
        let mut input = Cursor::new(data);
        // TODO detect versions with more accuracy
        let (start, end, eva) = match version {
            ..=699 => {
                let start = read_word(&mut input, is_64)?;
                let end = read_word(&mut input, is_64)?;
                let rva: u32 = bincode::deserialize_from(&mut input)?;
                (start, end, rva.into())
            }
            700.. => {
                let start = unpack_usize(&mut input, is_64)?;
                let end = start
                    .checked_add(unpack_usize(&mut input, is_64)?)
                    .ok_or_else(|| anyhow!("Overflow address in File Regions"))?;
                let rva = unpack_usize(&mut input, is_64)?;
                // TODO some may include an extra 0 byte at the end?
                if let Ok(_unknown) = unpack_usize(&mut input, is_64) {
                    ensure!(_unknown == 0);
                }
                (start, end, rva)
            }
        };
        let key_offset =
            parse_number(key, true, is_64).ok_or_else(|| anyhow!("Invalid IDB File Key Offset"))?;
        ensure!(key_offset == start);
        ensure!(input.position() == u64::try_from(data.len()).unwrap());
        Ok(Self { start, end, eva })
    }
}

#[derive(Clone, Debug)]
pub enum FunctionsAndComments<'a> {
    // It's just the name "$ funcs"
    Name,
    Function(IDBFunction),
    Comment { address: u64, value: &'a str },
    RepeatableComment { address: u64, value: &'a str },
    Unknown { key: &'a [u8], value: &'a [u8] },
}

impl<'a> FunctionsAndComments<'a> {
    fn read(key: &'a [u8], value: &'a [u8], is_64: bool) -> Result<Self> {
        let [key_type, sub_key @ ..] = key else {
            return Err(anyhow!("invalid Funcs subkey"));
        };
        match *key_type {
            b'N' => {
                ensure!(parse_maybe_cstr(value) == Some("$ funcs"));
                Ok(Self::Name)
            }
            b'S' => IDBFunction::read(sub_key, value, is_64).map(Self::Function),
            b'C' => {
                let address = parse_number(sub_key, true, is_64)
                    .ok_or_else(|| anyhow!("Invalid Comment address"))?;
                parse_maybe_cstr(value)
                    .map(|value| Self::Comment { address, value })
                    .ok_or_else(|| anyhow!("Invalid Comment string"))
            }
            b'R' => {
                let address = parse_number(sub_key, true, is_64)
                    .ok_or_else(|| anyhow!("Invalid Repetable Comment address"))?;
                parse_maybe_cstr(value)
                    .map(|value| Self::RepeatableComment { address, value })
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
    // InnerRef: 0x38f810
    fn read(key: &[u8], value: &[u8], is_64: bool) -> Result<Self> {
        let key_address = parse_number(key, true, is_64)
            .ok_or_else(|| anyhow!("Invalid IDB FileRefion Key Offset"))?;
        let mut input = Cursor::new(value);
        let address = unpack_address_range(&mut input, is_64)?;
        ensure!(key_address == address.start);
        let flags = unpack_dw(&mut input)?;

        // CONST migrate this to mod flags
        const FUNC_TAIL: u16 = 0x8000;
        let extra = if flags & FUNC_TAIL != 0 {
            Self::read_extra_tail(&mut input, is_64, address.start).ok()
        } else {
            Self::read_extra_regular(&mut input, is_64).ok()
        };
        // TODO Undertand the InnerRef 0x38f9d8 data
        // TODO make sure all the data is parsed
        //ensure!(input.position() == u64::try_from(data.len()).unwrap());
        Ok(Self {
            address,
            flags,
            extra,
        })
    }

    fn read_extra_regular(input: &mut impl Read, is_64: bool) -> Result<IDBFunctionExtra> {
        // TODO Undertand the sub operation at InnerRef 0x38f98f
        let frame = unpack_usize_ext_max(&mut *input, is_64)?;
        let _unknown4 = unpack_dw(&mut *input)?;
        if _unknown4 == 0 {
            let _unknown5 = unpack_dd(&mut *input)?;
        }
        Ok(IDBFunctionExtra::NonTail { frame })
    }

    fn read_extra_tail(
        input: &mut impl Read,
        is_64: bool,
        address_start: u64,
    ) -> Result<IDBFunctionExtra> {
        // offset of the function owner in relation to the function start
        let owner_offset = unpack_usize(&mut *input, is_64)? as i64;
        let owner = match address_start.checked_add_signed(owner_offset) {
            Some(0xFFFF_FFFF) => u64::MAX,
            Some(value) => value,
            None => return Err(anyhow!("Owner Function offset is invalid")),
        };
        let refqty = unpack_usize_ext_max(&mut *input, is_64)?;
        let _unknown1 = unpack_dw(&mut *input)?;
        let _unknown2 = unpack_usize_ext_max(&mut *input, is_64)?;
        // TODO make data depending on variables that I don't understant
        // InnerRef: 0x38fa93
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
            ensure!(parse_maybe_cstr(value) == Some("$ entry points"));
            return Ok(Self::Name);
        }
        let Some(sub_key) = parse_number(sub_key, true, is_64) else {
            return Ok(Self::Unknown { key, value });
        };
        match *key_type {
            // TODO for some reason the address is one byte extra
            b'A' => read_word(value, is_64)
                .map(|address| Self::Address {
                    key: sub_key,
                    address: address - 1,
                })
                .map_err(|_| anyhow!("Invalid Function address")),
            b'I' => read_word(value, is_64)
                .map(|ordinal| Self::Ordinal {
                    key: sub_key,
                    ordinal,
                })
                .map_err(|_| anyhow!("Invalid Ordinal value")),
            b'F' => parse_maybe_cstr(value)
                .map(|symbol| Self::ForwardedSymbol {
                    key: sub_key,
                    symbol,
                })
                .ok_or_else(|| anyhow!("Invalid Forwarded symbol name")),
            b'S' => parse_maybe_cstr(value)
                .map(|name| Self::FunctionName { key: sub_key, name })
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

fn read_exact_or_nothing<R: std::io::Read + ?Sized>(
    this: &mut R,
    mut buf: &mut [u8],
) -> std::io::Result<usize> {
    let len = buf.len();
    while !buf.is_empty() {
        match this.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(len - buf.len())
}

fn read_word<I: Read>(input: I, is_64: bool) -> Result<u64> {
    if is_64 {
        Ok(bincode::deserialize_from(input)?)
    } else {
        Ok(bincode::deserialize_from::<_, u32>(input).map(u64::from)?)
    }
}

fn unpack_usize<I: Read>(input: &mut I, is_64: bool) -> Result<u64> {
    if is_64 {
        unpack_dq(input)
    } else {
        unpack_dd(input).map(u64::from)
    }
}

fn unpack_usize_ext_max<I: Read>(input: &mut I, is_64: bool) -> Result<u64> {
    if is_64 {
        unpack_dq(input)
    } else {
        unpack_dd_ext_max(input).map(u64::from)
    }
}

// InnerRef: 0x38f8cc
fn unpack_address_range<I: Read>(input: &mut I, is_64: bool) -> Result<Range<u64>> {
    if is_64 {
        let start = unpack_dq(&mut *input)?;
        let len = unpack_dq(&mut *input)?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| anyhow!("Function range overflows"))?;
        Ok(start..end)
    } else {
        let start = unpack_dd_ext_max(&mut *input)?;
        let len = unpack_dd(&mut *input)?;
        // NOTE may not look right, but that's how ida does it
        let end = match start.checked_add(len.into()) {
            Some(0xFFFF_FFFF) => u64::MAX,
            Some(value) => value,
            None => return Err(anyhow!("Function range overflows")),
        };
        Ok(start..end)
    }
}

fn parse_u8<I: Read>(input: &mut I) -> Result<u8> {
    Ok(bincode::deserialize_from(&mut *input)?)
}

// InnerRef: unpack_dw
// NOTE: the original implementation never fails, if input hit EoF it a partial result or 0
/// Reads 1 to 3 bytes.
fn unpack_dw<I: Read>(input: &mut I) -> Result<u16> {
    let b1: u8 = bincode::deserialize_from(&mut *input)?;
    match b1 {
        // 7 bit value
        // [0xxx xxxx]
        0x00..=0x7F => Ok(b1.into()),
        // 14 bits value
        // [10xx xxxx] xxxx xxxx
        0x80..=0xBF => {
            let lo: u8 = bincode::deserialize_from(&mut *input)?;
            Ok(u16::from_be_bytes([b1 & 0x3F, lo]))
        }
        // 16 bits value
        // [11XX XXXX] xxxx xxxx xxxx xxxx
        0xC0..=0xFF => {
            // NOTE first byte 6 bits seems to be ignored
            //ensure!(header != 0xC0 && header != 0xFF);
            Ok(u16::from_be_bytes(bincode::deserialize_from(&mut *input)?))
        }
    }
}

// InnerRef: unpack_dd
// NOTE the orignal implementation never fails, if input hit EoF it a partial result or 0
/// Reads 1 to 5 bytes.
fn unpack_dd<I: Read>(input: &mut I) -> Result<u32> {
    let b1: u8 = bincode::deserialize_from(&mut *input)?;
    match b1 {
        // 7 bit value
        // [0xxx xxxx]
        0x00..=0x7F => Ok(b1.into()),
        // 14 bits value
        // [10xx xxxx] xxxx xxxx
        0x80..=0xBF => {
            let lo: u8 = bincode::deserialize_from(&mut *input)?;
            Ok(u32::from_be_bytes([0, 0, b1 & 0x3F, lo]))
        }
        // 29 bit value:
        // [110x xxxx] xxxx xxxx xxxx xxxx xxxx xxxx
        0xC0..=0xDF => {
            let bytes: [u8; 3] = bincode::deserialize_from(&mut *input)?;
            Ok(u32::from_be_bytes([
                b1 & 0x1F,
                bytes[0],
                bytes[1],
                bytes[2],
            ]))
        }
        // 32 bits value
        // [111X XXXX] xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx
        0xE0..=0xFF => {
            // NOTE first byte 5 bits seems to be ignored
            //ensure!(header != 0xE0 && header != 0xFF);
            Ok(u32::from_be_bytes(bincode::deserialize_from(&mut *input)?))
        }
    }
}

fn unpack_dd_ext_max<I: Read>(input: &mut I) -> Result<u64> {
    match unpack_dd(input)? {
        u32::MAX => Ok(u64::MAX),
        value => Ok(u64::from(value)),
    }
}

// InnerRef: unpack_dq
// NOTE the orignal implementation never fails, if input hit EoF it a partial result or 0
/// Reads 2 to 10 bytes.
fn unpack_dq<I: Read>(input: &mut I) -> Result<u64> {
    let lo = unpack_dd(&mut *input)?;
    let hi = unpack_dd(&mut *input)?;
    Ok((u64::from(hi) << 32) | u64::from(lo))
}

// InnerRef: unpack_ds
// NOTE: the original implementation never fails, if input hit EoF it a partial result or 0
#[allow(unused)]
fn unpack_ds<I: Read>(input: &mut I) -> Result<Vec<u8>> {
    let len = unpack_dd(&mut *input)?;
    let mut result = vec![0; len.try_into()?];
    input.read_exact(&mut result)?;
    Ok(result)
}

fn parse_number(data: &[u8], big_endian: bool, is_64: bool) -> Option<u64> {
    Some(match (data.len(), is_64, big_endian) {
        (8, true, true) => u64::from_be_bytes(data.try_into().unwrap()),
        (8, true, false) => u64::from_le_bytes(data.try_into().unwrap()),
        (4, false, true) => u32::from_be_bytes(data.try_into().unwrap()).into(),
        (4, false, false) => u32::from_le_bytes(data.try_into().unwrap()).into(),
        _ => return None,
    })
}

// parse a string that maybe is finalized with \x00
fn parse_maybe_cstr(data: &[u8]) -> Option<&str> {
    // find the end of the string
    let end_pos = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    // make sure there is no data after the \x00
    if data[end_pos..].iter().any(|b| *b != 0) {
        return None;
    }
    core::str::from_utf8(&data[..end_pos]).ok()
}

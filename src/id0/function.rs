use std::ops::Range;

use crate::id0::parse_maybe_cstr;
use crate::ida_reader::{IdbBufRead, IdbRead, IdbReadKind};
use crate::{flags_to_struct, til, IDAKind};

use super::flag::func::*;
use super::flag::netnode::nn_res::ARRAY_SUP_TAG;
use super::{flag, Comments, ID0Section, NetnodeIdx};

use anyhow::{anyhow, ensure, Result};
use num_traits::WrappingSub;

#[derive(Copy, Clone, Debug)]
pub struct FuncIdx<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> From<FuncIdx<K>> for NetnodeIdx<K> {
    fn from(value: FuncIdx<K>) -> Self {
        Self(value.0)
    }
}

pub(crate) fn funcs_idx<K: IDAKind>(
    id0: &ID0Section<K>,
) -> Result<Option<FuncIdx<K>>> {
    Ok(id0.netnode_idx_by_name("$ funcs")?.map(|x| FuncIdx(x.0)))
}

pub(crate) fn functions_and_comments<K: IDAKind>(
    id0: &ID0Section<K>,
    idx: FuncIdx<K>,
) -> impl Iterator<Item = Result<FunctionsAndComments<'_, K>>> {
    id0.netnode_range(idx.into())
        .map(move |(key, value)| FunctionsAndComments::read(key, value))
}

pub(crate) fn fchunks<K: IDAKind>(
    id0: &ID0Section<K>,
    idx: FuncIdx<K>,
) -> impl Iterator<Item = Result<IDBFunction<K>>> + use<'_, K> {
    let entries = id0.sup_range(idx.into(), ARRAY_SUP_TAG).entries;
    entries
        .iter()
        .map(move |value| IDBFunction::read(&value.value[..]))
}

#[derive(Clone, Debug)]
pub struct IDBFunction<K: IDAKind> {
    pub address: Range<K::Usize>,
    pub flags: IDBFunctionFlag,
    pub extra: IDBFunctionType<K>,
}

#[derive(Clone, Debug)]
pub enum IDBFunctionType<K: IDAKind> {
    Tail(IDBFunctionTail<K>),
    NonTail(IDBFunctionNonTail<K>),
}

#[derive(Clone, Debug)]
pub struct IDBFunctionTail<K: IDAKind> {
    /// function owner of the function start
    pub owner: K::Usize,
    pub _unknown4: u16,
    pub _unknown5: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct IDBFunctionNonTail<K: IDAKind> {
    pub frame: K::Usize,
    /// Local variables area
    pub frsize: K::Usize,
    /// Saved registers
    pub frregs: u16,
    /// Purged bytes
    pub argsize: K::Usize,
    pub pntqty: u16,
    pub llabelqty: u16,
    pub(crate) _unknown1: u16,
    pub regargqty: u16,
    pub color: Option<u32>,
    pub tailqty: u16,
    pub fpd: K::Usize,
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
    pub(crate) fn read(key: &'a [u8], value: &'a [u8]) -> Result<Self> {
        let [key_type, sub_key @ ..] = key else {
            return Err(anyhow!("invalid Funcs subkey"));
        };
        match *key_type {
            flag::netnode::nn_res::NAME_TAG => {
                ensure!(parse_maybe_cstr(value) == Some(&b"$ funcs"[..]));
                Ok(Self::Name)
            }
            flag::netnode::nn_res::ARRAY_SUP_TAG => {
                IDBFunction::read(value).map(Self::Function)
            }
            // some kind of style setting, maybe setting font and background color
            b'R' | b'C' if value.starts_with(&[4, 3, 2, 1]) => {
                Ok(Self::Unknown { key, value })
            }
            b'C' => {
                let address = K::usize_try_from_be_bytes(sub_key)
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
                    K::usize_try_from_be_bytes(sub_key).ok_or_else(|| {
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
    // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28f810
    // InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x68bbc0
    pub(crate) fn read(value: &[u8]) -> Result<Self> {
        let mut input = value;
        let address = IdbReadKind::<K>::unpack_address_range(&mut input)?;
        // Partial flag, the rest is set below
        let flags_part1 = input.unpack_dw()?;
        let mut flags = IDBFunctionFlag::from_raw(flags_part1.into())?;

        let extra = if flags.is_tail() {
            Self::read_extra_tail(&mut input, address.start)?
        } else {
            Self::read_extra_non_tail(&mut input, address.start)?
        };

        // TODO Undestand the InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28f9d8 data
        if !input.is_empty() {
            let flags_full = input.unpack_dq()?;
            ensure!(
                flags_full as u16 == flags_part1,
                "Full flag conflict with partial flag"
            );
            flags = IDBFunctionFlag::from_raw(flags_full)?;
        }
        // TODO make sure all the data is parsed
        ensure!(
            input.is_empty(),
            "unable to parse {}bytes: {input:02X?}",
            input.len()
        );
        Ok(Self {
            address,
            flags,
            extra,
        })
    }

    fn read_extra_tail(
        input: &mut impl IdbReadKind<K>,
        address_start: K::Usize,
    ) -> Result<IDBFunctionType<K>> {
        let owner = address_start.wrapping_sub(&input.unpack_usize()?);
        let _unknown4 = input.unpack_dw()?;
        let _unknown5 =
            (_unknown4 == 0).then(|| input.unpack_dd()).transpose()?;
        Ok(IDBFunctionType::Tail(IDBFunctionTail {
            owner,
            _unknown4,
            _unknown5,
        }))
    }

    fn read_extra_non_tail<R>(
        input: &mut R,
        address_start: K::Usize,
    ) -> Result<IDBFunctionType<K>>
    where
        R: IdbBufRead + IdbReadKind<K>,
    {
        // offset of the function owner in relation to the function start
        let owner_offset = input.unpack_usize()?;
        // TODO maybe this is some kind of flag
        let high_bit: K::Usize =
            K::Usize::from(1u8) << (usize::from(K::BYTES - 1) * 8);
        // TODO this is not correct
        let frame = match owner_offset {
            _ if owner_offset == address_start | high_bit => address_start,
            value => value,
        };
        let frsize = input.unpack_usize()?;
        let frregs = input.unpack_dw()?;
        let argsize = input.unpack_usize()?;
        let pntqty = input.unpack_dw()?;
        let _unknown1 = input.unpack_dw()?;
        let llabelqty = input.unpack_dw()?;
        let regargqty = input.unpack_dw()?;
        let color_raw = input.unpack_dd()?;
        let color = (color_raw != 0).then(|| color_raw - 1);
        let tailqty = input.unpack_dw()?;
        let fpd = input.unpack_usize()?;

        // TODO make data depending on variables that I don't understant
        // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x28fa93
        Ok(IDBFunctionType::NonTail(IDBFunctionNonTail {
            frame,
            frsize,
            frregs,
            argsize,
            pntqty,
            llabelqty,
            _unknown1,
            regargqty,
            color,
            tailqty,
            fpd,
        }))
    }
}

flags_to_struct!(
    IDBFunctionFlag, u64,
    FUNC_NORET is_no_return "Function doesn't return",
    FUNC_FAR is_far "Far function",
    FUNC_LIB is_lib "Library function",
    FUNC_STATICDEF is_static "Static function",
    FUNC_FRAME use_frame_pointer "Function uses frame pointer (BP)",
    FUNC_USERFAR is_user_far "User has specified far-ness of the function",
    FUNC_HIDDEN is_hidden "A hidden function chunk",
    FUNC_THUNK is_thunk "Thunk (jump) function",
    FUNC_BOTTOMBP is_bot_tombp "BP points to the bottom of the stack frame",
    FUNC_NORET_PENDING is_noret_pending "Function 'non-return' analysis must be performed. This flag is verified upon func_does_return()",
    FUNC_SP_READY is_sp_ready "SP-analysis has been performed",
    FUNC_FUZZY_SP is_fuzzy_sp "Function changes SP in untraceable way, eg: `and esp, 0FFFFFFF0h`",
    FUNC_PROLOG_OK is_prolog_ok "Prolog analysis has been performed by last SP-analysis",
    FUNC_PURGED_OK is_purged_ok "'argsize' field has been validated. If this bit is clear and 'argsize' is 0, then we do not known the real number of bytes removed from the stack. This bit is handled by the processor module",
    FUNC_TAIL is_tail "This is a function tail. Other bits must be clear (except #FUNC_HIDDEN)",
    FUNC_LUMINA is_lumina "Function info is provided by Lumina",
    FUNC_OUTLINE is_outline "Outlined code, not a real function",
    FUNC_REANALYZE is_reanalyze "Function frame changed, request to reanalyze the function after the last insn is analyzed",
    FUNC_UNWIND is_unwind_handler "function is an exception unwind handler",
    FUNC_CATCH is_catch_handler "function is an exception catch handler",
);

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
    pub(crate) fn read(key: &'a [u8], value: &'a [u8]) -> Result<Self> {
        let mut value = value;
        let [key_type, sub_key @ ..] = key else {
            return Err(anyhow!("invalid Funcs subkey"));
        };
        if *key_type == b'N' {
            ensure!(parse_maybe_cstr(value) == Some(&b"$ entry points"[..]));
            return Ok(Self::Name);
        }
        let Some(sub_key) = K::usize_try_from_be_bytes(sub_key) else {
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

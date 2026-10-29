use std::num::NonZeroU8;

use crate::ida_reader::{IdbBufRead, IdbRead};
use crate::til::{Basic, Type, TypeVariant};
use crate::IDBString;
use anyhow::{anyhow, ensure, Context, Result};
use serde::Serialize;

use super::section::TILSectionHeader;
use super::CommentType;

#[derive(Debug, Clone, Serialize)]
pub struct Function {
    pub calling_convention: Option<CallingConvention>,
    pub ret: Box<Type>,
    pub args: Vec<FunctionArg>,
    pub retloc: Option<ArgLoc>,

    pub method: Option<CallMethod>,
    pub is_noret: bool,
    pub is_pure: bool,
    pub is_high: bool,
    pub is_static: bool,
    pub is_virtual: bool,
    pub is_const: bool,
    pub is_constructor: bool,
    pub is_destructor: bool,
}

impl Function {
    pub(crate) fn read(
        input: &mut impl IdbBufRead,
        header: &TILSectionHeader,
        metadata: u8,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
    ) -> Result<Self> {
        use super::flag::tf_func::*;
        let method = match metadata {
            BTMT_DEFCALL => None,
            BTMT_NEARCALL => Some(CallMethod::Near),
            BTMT_FARCALL => Some(CallMethod::Far),
            BTMT_INTCALL => Some(CallMethod::Int),
            _ => unreachable!(),
        };

        // TODO InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473bf1 print_til_type
        let FunctionCC {
            cc,
            flags,
            _spoiled,
        } = read_cc(&mut *input)?;
        let cc = CallingConvention::from_cm_raw(cc)?;

        // TODO investigate why this don't hold true
        // function returns by iret (BTMT_INTCALL) in this case cc MUST be 'unknown'
        //if method == Some(CallMethod::Int) {
        //    ensure!(
        //        cc == CallingConvention::Unknown,
        //        "Invalid CC in function with CallMethod Int"
        //    );
        //}

        // consume the flags and verify if a unknown value is present
        // TODO find those in flags
        let have_spoiled = flags & 0x0001 != 0;
        if !have_spoiled {
            ensure!(_spoiled.is_empty());
        }
        let flags_lower = ((flags & 0xFF) >> 1) as u8;

        let is_noret = flags_lower & BFA_NORET != 0;
        let is_pure = flags_lower & BFA_PURE != 0;
        let is_high = flags_lower & BFA_HIGH != 0;
        let is_static = flags_lower & BFA_STATIC != 0;
        let is_virtual = flags_lower & BFA_VIRTUAL != 0;
        #[cfg(feature = "restrictive")]
        ensure!(
            flags_lower
                & !(BFA_NORET | BFA_PURE | BFA_HIGH | BFA_STATIC | BFA_VIRTUAL)
                == 0
        );

        // TODO find those flags
        const BFA_CONST: u8 = 0x4;
        const BFA_CONSTRUCTOR: u8 = 0x8;
        const BFA_DESTRUCTOR: u8 = 0x10;
        let flags_upper = ((flags & 0xFF00) >> 8) as u8;
        let is_const = flags_upper & BFA_CONST != 0;
        let is_constructor = flags_upper & BFA_CONSTRUCTOR != 0;
        let is_destructor = flags_upper & BFA_DESTRUCTOR != 0;
        #[cfg(feature = "restrictive")]
        ensure!(
            flags_upper & !(BFA_CONST | BFA_CONSTRUCTOR | BFA_DESTRUCTOR) == 0
        );

        let ret = Type::read(&mut *input, header, None, fields, comments)
            .context("Return Argument")?;
        // TODO double check documentation for [flag::tf_func::BT_FUN]
        let is_special_pe =
            cc.map(CallingConvention::is_special_pe).unwrap_or(false);
        let have_retloc = is_special_pe
            && !matches!(&ret.type_variant, TypeVariant::Basic(Basic::Void));
        let retloc = have_retloc
            .then(|| ArgLoc::read(&mut *input))
            .transpose()
            .context("Retloc")?;

        let mut result = Self {
            calling_convention: cc,
            ret: Box::new(ret),
            args: vec![],
            retloc,

            method,
            is_noret,
            is_pure,
            is_high,
            is_static,
            is_virtual,
            is_const,
            is_constructor,
            is_destructor,
        };
        if cc == Some(CallingConvention::Voidarg) {
            return Ok(result);
        }

        let n = input.read_dt()?;
        result.args = (0..n)
            .map(|i| {
                let name = fields.next().flatten();
                let comment = comments.next().flatten();
                let tmp = input.peek_u8()?;
                let flags = (tmp == Some(0xFF))
                    .then(|| {
                        input.consume(1);
                        // TODO what is this?
                        FunctionArgFlags::from_raw(input.read_de()?)
                    })
                    .transpose()?;
                let ty =
                    Type::read(&mut *input, header, None, fields, comments)
                        .with_context(|| format!("Argument Type {i}"))?;
                let loc = is_special_pe
                    .then(|| ArgLoc::read(&mut *input))
                    .transpose()
                    .with_context(|| format!("Argument Argloc {i}"))?;

                Ok(FunctionArg {
                    name,
                    comment,
                    ty,
                    loc,
                    flags,
                })
            })
            .collect::<Result<_>>()?;

        Ok(result)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionArg {
    pub name: Option<IDBString>,
    pub comment: Option<CommentType>,
    pub ty: Type,
    pub loc: Option<ArgLoc>,
    pub flags: Option<FunctionArgFlags>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct FunctionArgFlags {
    pub is_hidden: bool,
    pub is_return_ptr: bool,
    pub is_struct_ptr: bool,
    pub is_array_ptr: bool,
    pub is_unused: bool,
}

impl FunctionArgFlags {
    pub(crate) fn from_raw(flags: u32) -> Result<Self> {
        #[cfg(feature = "restrictive")]
        if flags > 0x10 {
            return Err(anyhow!("Invalid value for FunctionArgFlags "));
        }
        // TODO find the value for this in `crate::til::flag::*`
        let is_hidden = flags & 0x1 != 0;
        let is_return_ptr = flags & 0x2 != 0;
        let is_struct_ptr = flags & 0x4 != 0;
        let is_array_ptr = flags & 0x8 != 0;
        let is_unused = flags & 0x10 != 0;
        Ok(Self {
            is_hidden,
            is_return_ptr,
            is_struct_ptr,
            is_array_ptr,
            is_unused,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum ArgLoc {
    /// 0 - None
    None,
    /// 1 - stack offset
    Stack(i64),
    /// 2 - distributed (scattered)
    Dist(Vec<ArgLocDist>),
    /// 3 - one register and the byte offset within it
    Reg1 { reg: u16, off: u16 },
    /// 4 - register pair, first register in bits 0..16, second in 16..32
    Reg2(u32),
    /// 5 - register relative
    RRel { reg: u16, off: i64 },
    /// 6 - global address
    Static(u64),
}

/// One part of a scattered argument.
#[derive(Debug, Clone, Serialize)]
pub struct ArgLocDist {
    pub loc: ArgLoc,
    /// offset of the part within the argument
    pub off: u16,
    pub size: u32,
}

impl ArgLoc {
    fn read(input: &mut impl IdbRead) -> Result<Self> {
        Self::read_inner(input, true)
    }

    /// A part of a scattered argument can't be scattered itself.
    fn read_inner(input: &mut impl IdbRead, allow_dist: bool) -> Result<Self> {
        let t: u8 = input.read_u8()?;
        if t != 0xFF {
            let b = t & 0x7F;
            return match (t, b) {
                (0..=0x80, 1..) => Ok(Self::Reg1 {
                    reg: (b - 1).into(),
                    off: 0,
                }),
                (0..=0x80, 0) => Ok(Self::Stack(0)),
                _ => {
                    let c: u8 = bincode::deserialize_from(&mut *input)?;
                    if c == 0 {
                        Ok(Self::None)
                    } else {
                        Ok(Self::Reg2(u32::from(b) | u32::from(c - 1) << 16))
                    }
                }
            };
        }
        // Layout checked against IDA 9.1-9.5 `tinfo_t::serialize`: a dt of
        // `0x80 | n` starts `n` scattered parts; otherwise the byte is
        // `0x20 | ALOC_*` (dt values below 0x80 are stored as value + 1).
        use super::flag::tf_func::argloc::*;
        let kind = input.read_dt()?;
        if let Some(parts) = kind.checked_sub(0x80) {
            ensure!(allow_dist, "Nested scattered ArgLoc");
            let parts = (0..parts)
                .map(|_| {
                    let loc = Self::read_inner(&mut *input, false)?;
                    let off = input.read_dt()?;
                    let size = input.read_de()?;
                    Ok(ArgLocDist { loc, off, size })
                })
                .collect::<Result<_>>()?;
            return Ok(Self::Dist(parts));
        }
        let kind = kind + 1;
        ensure!(kind & 0xF0 == 0x20, "Unknown ArgLoc kind {kind:#x}");
        match (kind & 0xF) as u8 {
            ALOC_STACK => Ok(Self::Stack(read_de64(input)? as i64)),
            ALOC_REG1 => Ok(Self::Reg1 {
                reg: input.read_dt()?,
                off: input.read_dt()?,
            }),
            ALOC_REG2 => {
                let reg1 = input.read_dt()?;
                let reg2 = input.read_dt()?;
                Ok(Self::Reg2(u32::from(reg1) | u32::from(reg2) << 16))
            }
            ALOC_RREL => Ok(Self::RRel {
                reg: input.read_dt()?,
                off: read_de64(input)? as i64,
            }),
            ALOC_STATIC => Ok(Self::Static(read_de64(input)?)),
            other => Err(anyhow!("Unsupported ArgLoc type {other}")),
        }
    }
}

/// A 64-bit value stored as two `de`, low half first.
fn read_de64(input: &mut impl IdbRead) -> Result<u64> {
    let lo = input.read_de()?;
    let hi = input.read_de()?;
    Ok(u64::from(lo) | u64::from(hi) << 32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CallingConvention {
    /// function without arguments
    Voidarg = 0x2,
    /// stack
    Cdecl = 0x3,
    /// cdecl + ellipsis
    Ellipsis = 0x4,
    /// stack, purged
    Stdcall = 0x5,
    /// stack, purged, reverse order of args
    Pascal = 0x6,
    /// stack, purged (x86), first args are in regs (compiler-dependent)
    Fastcall = 0x7,
    /// stack, purged (x86), first arg is in reg (compiler-dependent)
    Thiscall = 0x8,
    /// (Swift) arguments and return values in registers (compiler-dependent)
    Swift = 0x9,
    /// (Go) arguments and return value in stack
    Golang = 0xb,
    Reserved3 = 0xc,
    /// ::CM_CC_SPECIAL with ellipsis
    Uservars = 0xd,
    /// Equal to ::CM_CC_SPECIAL, but with purged stack
    Userpurge = 0xe,
    /// usercall: locations of all arguments
    /// and the return value are explicitly specified
    Usercall = 0xf,
}

impl CallingConvention {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b860
    pub(crate) fn from_cm_raw(cm: u8) -> Result<Option<Self>> {
        use super::flag::cm::cc::*;

        Ok(Some(match cm & CM_CC_MASK {
            // !ERR(spoil)!
            CM_CC_SPOILED => {
                return Err(anyhow!(
                    "Unexpected Spoiled Function Calling Convention"
                ))
            }
            // this is an invalid value
            CM_CC_INVALID => {
                return Err(anyhow!("Invalid Function Calling Convention"))
            }
            CM_CC_UNKNOWN => return Ok(None),
            CM_CC_VOIDARG => Self::Voidarg,
            CM_CC_CDECL => Self::Cdecl,
            CM_CC_ELLIPSIS => Self::Ellipsis,
            CM_CC_STDCALL => Self::Stdcall,
            CM_CC_PASCAL => Self::Pascal,
            CM_CC_FASTCALL => Self::Fastcall,
            CM_CC_THISCALL => Self::Thiscall,
            CM_CC_SWIFT => Self::Swift,
            CM_CC_GOLANG => Self::Golang,
            CM_CC_RESERVE3 => Self::Reserved3,
            CM_CC_SPECIALE => Self::Uservars,
            CM_CC_SPECIALP => Self::Userpurge,
            CM_CC_SPECIAL => Self::Usercall,
            _ => unreachable!(),
        }))
    }

    pub const fn is_special_pe(self) -> bool {
        matches!(self, Self::Uservars | Self::Userpurge | Self::Usercall)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CCPtrSize {
    /// near 1 byte, far 2 bytes
    N8F16,
    /// near 2 bytes, far 4 bytes
    N16F32,
    /// near 4 bytes, far 6 bytes
    N32F48,
    /// near 8 bytes, far 8 bytes
    N64,
}

impl CCPtrSize {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40b7ed
    pub(crate) fn from_cm_raw(cm: u8, size_int: NonZeroU8) -> Option<Self> {
        use super::flag::cm::cm_ptr::*;

        Some(match cm & CM_MASK {
            CM_UNKNOWN => return None,
            CM_N8_F16 if size_int.get() <= 2 => Self::N8F16,
            CM_N64 /* if size_int.get() > 2 */ => Self::N64,
            CM_N16_F32 => Self::N16F32,
            CM_N32_F48 => Self::N32F48,
            _ => unreachable!(),
        })
    }

    pub const fn near_bytes(self) -> NonZeroU8 {
        match self {
            CCPtrSize::N8F16 => NonZeroU8::new(1).unwrap(),
            CCPtrSize::N16F32 => NonZeroU8::new(2).unwrap(),
            CCPtrSize::N32F48 => NonZeroU8::new(4).unwrap(),
            CCPtrSize::N64 => NonZeroU8::new(8).unwrap(),
        }
    }

    pub const fn far_bytes(self) -> NonZeroU8 {
        match self {
            CCPtrSize::N8F16 => NonZeroU8::new(2).unwrap(),
            CCPtrSize::N16F32 => NonZeroU8::new(4).unwrap(),
            CCPtrSize::N32F48 => NonZeroU8::new(6).unwrap(),
            CCPtrSize::N64 => NonZeroU8::new(8).unwrap(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CCModel {
    /// small:   code=near, data=near
    NN,
    /// large:   code=far, data=far
    FF,
    /// compact: code=near, data=far
    NF,
    /// medium:  code=far, data=near
    FN,
}

impl CCModel {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x40ba3b
    pub(crate) fn from_cm_raw(cm: u8) -> Option<Self> {
        use super::flag::cm::cm_ptr::*;
        use super::flag::cm::m::*;
        Some(match (cm & CM_M_MASK, cm & CM_MASK) {
            // small:   code=near, data=near (or unknown if CM_UNKNOWN)
            (CM_M_NN, CM_UNKNOWN) => return None,
            (CM_M_NN, _) => Self::NN,
            (CM_M_FF, _) => Self::FF,
            (CM_M_NF, _) => Self::NF,
            (CM_M_FN, _) => Self::FN,
            _ => unreachable!(),
        })
    }

    pub const fn is_code_near(self) -> bool {
        match self {
            CCModel::NN => true,
            CCModel::FF => false,
            CCModel::NF => true,
            CCModel::FN => false,
        }
    }
    pub const fn is_code_far(self) -> bool {
        !self.is_code_near()
    }

    pub const fn is_data_near(self) -> bool {
        match self {
            CCModel::NN => true,
            CCModel::FF => false,
            CCModel::NF => false,
            CCModel::FN => true,
        }
    }
    pub const fn is_data_far(self) -> bool {
        !self.is_data_near()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CallMethod {
    Near,
    Far,
    Int,
}

struct FunctionCC {
    cc: u8,
    flags: u16,
    _spoiled: Vec<(u16, u8)>,
}

// InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x476e60
/// [BT_FUNC](https://hex-rays.com/products/ida/support/sdkdoc/group__tf__func.html#ga7b7fee21f21237beb6d91e854410e0fa)
fn read_cc(input: &mut impl IdbBufRead) -> Result<FunctionCC> {
    let mut cc = input.read_u8()?;
    // TODO find the flag for that
    if cc & 0xF0 != 0xA0 {
        return Ok(FunctionCC {
            cc,
            flags: 0,
            _spoiled: vec![],
        });
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46de7c
    let pbyte2 = input.peek_u8()?;
    if cc & 0xF != 0xF || matches!(pbyte2, Some(x) if x & 0x80 == 0) {
        let mut spoiled = vec![];
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46df47
        let mut flags = 0;
        loop {
            if cc & 0xF == 0xF {
                let byte2 = input.read_u8()?;
                // TODO check that flags are not duplicated?
                flags |= (byte2 & 0x1F) << 1;
            } else {
                let nspoiled = cc as u16 & 0xF;
                flags |= 1;
                // TODO make sure spoiled is always None?
                read_cc_spoiled(input, nspoiled, &mut spoiled)?;
            }

            cc = input.read_u8()?;
            if cc & 0xF0 != 0xA0 {
                return Ok(FunctionCC {
                    cc,
                    flags: flags.into(),
                    _spoiled: spoiled,
                });
            }
        }
    } else {
        let byte2 = input.read_u8()?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46def4
        let mut spoiled = vec![];
        let flag = input.read_de()?;
        if byte2 & 1 != 0 {
            let nspoiled = input.read_dt()?;
            read_cc_spoiled(input, nspoiled, &mut spoiled)?;
        }
        let cc = input.read_u8()?;
        // TODO is this `&` realy necessary? Should we allow invalid flags?
        Ok(FunctionCC {
            cc,
            flags: (flag & 0x1E3F) as u16,
            _spoiled: spoiled,
        })
    }
}

fn read_cc_spoiled(
    input: &mut impl IdbBufRead,
    nspoiled: u16,
    spoiled: &mut Vec<(u16, u8)>,
) -> Result<()> {
    spoiled.reserve(nspoiled.into());
    for _i in 0..nspoiled {
        let b: u8 = input.read_u8()?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46c23d
        if b & 0x80 != 0 {
            let reg = if b == 0xFF {
                input.read_dt()?
            } else {
                (b & 0x7F).into()
            };
            let size = input.read_u8()?;
            spoiled.push((reg, size))
        } else {
            let size = (b >> 4) + 1;
            // TODO what if (b & 0xF) == 0?
            #[cfg(feature = "restrictive")]
            let reg = (b & 0xF)
                .checked_sub(1)
                .ok_or_else(|| anyhow!("invalid spoiled reg value"))?;
            #[cfg(not(feature = "restrictive"))]
            let reg = (b & 0xF).saturating_sub(1);
            spoiled.push((reg.into(), size))
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ArgLoc;

    #[test]
    fn nested_scattered_arg_loc_is_an_error() {
        // 0xFF, dt(0x81): one scattered part, whose location is again
        // 0xFF, dt(0x81)
        let data = [0xFF, 0x82, 0x01, 0xFF, 0x82, 0x01, 0x01, 0x01];
        assert!(ArgLoc::read(&mut &data[..]).is_err());
    }
}

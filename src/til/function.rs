use std::collections::HashMap;
use std::num::NonZeroU8;

use crate::ida_reader::{IdaGenericBufUnpack, IdaGenericUnpack};
use crate::til::{Basic, Type, TypeRaw};
use crate::IDBString;
use anyhow::{anyhow, ensure, Context, Result};

use super::section::TILSectionHeader;
use super::TypeVariantRaw;

#[derive(Debug, Clone)]
pub struct Function {
    pub calling_convention: Option<CallingConvention>,
    pub ret: Box<Type>,
    pub args: Vec<(Option<IDBString>, Type, Option<ArgLoc>)>,
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
    pub(crate) fn new(
        til: &TILSectionHeader,
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        value: FunctionRaw,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
    ) -> Result<Self> {
        let ret = Type::new(
            til,
            type_by_name,
            type_by_ord,
            *value.ret,
            &mut *fields,
        )?;
        let mut args = Vec::with_capacity(value.args.len());
        for (arg_type, arg_loc) in value.args {
            let field_name = fields.next().flatten();
            let new_member = Type::new(
                til,
                type_by_name,
                type_by_ord,
                arg_type,
                &mut *fields,
            )?;
            args.push((field_name, new_member, arg_loc));
        }
        Ok(Self {
            calling_convention: value.calling_convention,
            ret: Box::new(ret),
            args,
            method: value.method,
            retloc: value.retloc,
            is_noret: value.is_noret,
            is_pure: value.is_pure,
            is_high: value.is_high,
            is_static: value.is_static,
            is_virtual: value.is_virtual,
            is_const: value.is_const,
            is_constructor: value.is_constructor,
            is_destructor: value.is_destructor,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FunctionRaw {
    pub ret: Box<TypeRaw>,
    pub args: Vec<(TypeRaw, Option<ArgLoc>)>,
    pub retloc: Option<ArgLoc>,
    pub calling_convention: Option<CallingConvention>,

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

#[derive(Debug, Clone)]
pub enum ArgLoc {
    // TODO add those to flags
    // ::ALOC_STACK
    // ::ALOC_STATIC
    // ::ALOC_REG1
    // ::ALOC_REG2
    // ::ALOC_RREL
    // ::ALOC_DIST
    // ::ALOC_CUSTOM
    /// 0 - None
    None,
    /// 1 - stack offset
    Stack(u32),
    /// 2 - distributed (scattered)
    Dist(Vec<ArgLocDist>),
    /// 3 - one register (and offset within it)
    Reg1(u32),
    /// 4 - register pair
    Reg2(u32),
    /// 5 - register relative
    RRel { reg: u16, off: u32 },
    /// 6 - global address
    Static(u32),
    // 7..=0xf custom
    // TODO is possible to know the custom impl len?
}

#[derive(Debug, Clone)]
pub struct ArgLocDist {
    pub info: u16,
    pub off: u16,
    pub size: u16,
}

impl FunctionRaw {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473190 print_til_type
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47c8f0
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        metadata: u8,
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
        let (cc, flags, _spoiled) = read_cc(&mut *input)?;
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

        let ret =
            TypeRaw::read(&mut *input, header).context("Return Argument")?;
        // TODO double check documentation for [flag::tf_func::BT_FUN]
        let is_special_pe =
            cc.map(CallingConvention::is_special_pe).unwrap_or(false);
        let have_retloc = is_special_pe
            && !matches!(&ret.variant, TypeVariantRaw::Basic(Basic::Void));
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
            .map(|i| -> Result<_> {
                let tmp = input.peek_u8()?;
                if tmp == Some(0xFF) {
                    input.consume(1);
                    // TODO what is this?
                    let _flags = input.read_de()?;
                }
                let tinfo = TypeRaw::read(&mut *input, header)
                    .with_context(|| format!("Argument Type {i}"))?;
                let argloc = is_special_pe
                    .then(|| ArgLoc::read(&mut *input))
                    .transpose()
                    .with_context(|| format!("Argument Argloc {i}"))?;

                Ok((tinfo, argloc))
            })
            .collect::<Result<_, _>>()?;

        Ok(result)
    }
}

impl ArgLoc {
    fn read(input: &mut impl IdaGenericUnpack) -> Result<Self> {
        let t: u8 = input.read_u8()?;
        if t != 0xFF {
            let b = t & 0x7F;
            match (t, b) {
                (0..=0x80, 1..) => Ok(Self::Reg1((b - 1).into())),
                (0..=0x80, 0) => Ok(Self::Stack(0)),
                _ => {
                    let c: u8 = bincode::deserialize_from(&mut *input)?;
                    if c == 0 {
                        Ok(Self::None)
                    } else {
                        Ok(Self::Reg2(u32::from(b) | u32::from(c - 1) << 16))
                    }
                }
            }
        } else {
            use super::flag::tf_func::argloc::*;
            let typ = input.read_dt()?;
            match (typ & 0xF) as u8 {
                ALOC_NONE => Ok(Self::None),
                ALOC_STACK => {
                    let sval = input.read_de()?;
                    Ok(Self::Stack(sval))
                }
                ALOC_DIST => {
                    let n = (typ >> 5) & 0x7;
                    let dist: Vec<_> = (0..n)
                        .map(|_| {
                            let info = input.read_dt()?;
                            let off = input.read_dt()?;
                            let size = input.read_dt()?;
                            Ok(ArgLocDist { info, off, size })
                        })
                        .collect::<Result<_>>()?;
                    Ok(Self::Dist(dist))
                }
                ALOC_REG1 => {
                    let reg_info = input.read_dt()?;
                    // TODO read other dt?
                    Ok(Self::Reg1(reg_info.into()))
                }
                ALOC_REG2 => {
                    let reg_info = input.read_dt()?;
                    // TODO read other dt?
                    Ok(Self::Reg2(reg_info.into()))
                }
                ALOC_RREL => {
                    let reg = input.read_dt()?;
                    let off = input.read_de()?;
                    Ok(Self::RRel { reg, off })
                }
                ALOC_STATIC => {
                    let sval = input.read_de()?;
                    Ok(Self::Static(sval))
                }
                #[cfg(feature = "restrictive")]
                ALOC_CUSTOM.. => {
                    Err(anyhow!("Custom implementation for ArgLoc"))
                }
                #[cfg(not(feature = "restrictive"))]
                ALOC_CUSTOM.. => Ok(Self::None),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMethod {
    Near,
    Far,
    Int,
}

// InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x476e60
/// [BT_FUNC](https://hex-rays.com/products/ida/support/sdkdoc/group__tf__func.html#ga7b7fee21f21237beb6d91e854410e0fa)
fn read_cc(
    input: &mut impl IdaGenericBufUnpack,
) -> Result<(u8, u16, Vec<(u16, u8)>)> {
    let mut cc = input.read_u8()?;
    // TODO find the flag for that
    if cc & 0xF0 != 0xA0 {
        return Ok((cc, 0, vec![]));
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
                return Ok((cc, flags.into(), spoiled));
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
        Ok((cc, (flag & 0x1E3F) as u16, spoiled))
    }
}

fn read_cc_spoiled(
    input: &mut impl IdaGenericBufUnpack,
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

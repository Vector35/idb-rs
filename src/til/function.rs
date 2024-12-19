use crate::ida_reader::{IdaGenericBufUnpack, IdaGenericUnpack};
use crate::til::section::TILSectionHeader;
use crate::til::{Basic, Type, TypeRaw, TAH};
use anyhow::anyhow;

use super::TypeVariantRaw;

#[derive(Debug, Clone)]
pub struct Function {
    pub calling_convention: CallingConvention,
    pub ret: Box<Type>,
    pub args: Vec<(Option<Vec<u8>>, Type, Option<ArgLoc>)>,
    pub retloc: Option<ArgLoc>,
}
impl Function {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: FunctionRaw,
        fields: &mut impl Iterator<Item = Vec<u8>>,
    ) -> anyhow::Result<Self> {
        let ret = Type::new(til, *value.ret, &mut *fields)?;
        let mut args = Vec::with_capacity(value.args.len());
        for (arg_type, arg_loc) in value.args {
            let field_name = fields.next();
            let new_member = Type::new(til, arg_type, &mut *fields)?;
            args.push((field_name, new_member, arg_loc));
        }
        Ok(Self {
            calling_convention: value.calling_convention,
            ret: Box::new(ret),
            args,
            retloc: value.retloc,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FunctionRaw {
    pub ret: Box<TypeRaw>,
    pub args: Vec<(TypeRaw, Option<ArgLoc>)>,
    pub retloc: Option<ArgLoc>,
    pub calling_convention: CallingConvention,
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
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        _metadata: u8,
    ) -> anyhow::Result<Self> {
        //match metadata {
        //    super::flag::tf_func::BTMT_DEFCALL => todo!(),
        //    super::flag::tf_func::BTMT_NEARCALL => todo!(),
        //    super::flag::tf_func::BTMT_FARCALL => todo!(),
        //    super::flag::tf_func::BTMT_INTCALL => todo!(),
        //    _ => unreachable!(),
        //}

        // TODO InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473bf1 print_til_type
        let (cc, _flags, _spoiled) = read_cc(&mut *input)?;
        let cc = CallingConvention::from_cm_raw(cc)
            .ok_or_else(|| anyhow!("Invalid Function Calling Convention"))?;

        let _tah = TAH::read(&mut *input)?;

        let ret = TypeRaw::read(&mut *input, header)?;
        // TODO double check documentation for [flag::tf_func::BT_FUN]
        let is_special_pe = cc.is_special_pe();
        let have_retloc =
            is_special_pe && !matches!(&ret.variant, TypeVariantRaw::Basic(Basic::Void));
        let retloc = have_retloc.then(|| ArgLoc::read(&mut *input)).transpose()?;
        if matches!(cc, CallingConvention::Voidarg) {
            return Ok(Self {
                calling_convention: cc,
                ret: Box::new(ret),
                args: vec![],
                retloc,
            });
        }

        let n = input.read_dt()?;
        let args = (0..n)
            .map(|_| -> anyhow::Result<_> {
                let tmp = input.peek_u8()?;
                if tmp == Some(0xFF) {
                    input.consume(1);
                    // TODO what is this?
                    let _flags = input.read_de()?;
                }
                let tinfo = TypeRaw::read(&mut *input, header)?;
                let argloc = is_special_pe
                    .then(|| ArgLoc::read(&mut *input))
                    .transpose()?;

                Ok((tinfo, argloc))
            })
            .collect::<anyhow::Result<_, _>>()?;

        Ok(Self {
            calling_convention: cc,
            ret: Box::new(ret),
            args,
            retloc,
        })
    }
}

impl ArgLoc {
    fn read(input: &mut impl IdaGenericUnpack) -> anyhow::Result<Self> {
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
                        .collect::<anyhow::Result<_>>()?;
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
                ALOC_CUSTOM.. => Err(anyhow!("Custom implementation for ArgLoc")),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// unknown calling convention
    Unknown = 0x1,
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
    pub(crate) fn from_cm_raw(cm: u8) -> Option<Self> {
        use super::flag::cm::cc::*;

        Some(match cm & CM_CC_MASK {
            // !ERR(spoil)!
            CM_CC_SPOILED => return None,
            // this is an invalid value
            CM_CC_INVALID => return None,
            CM_CC_UNKNOWN => Self::Unknown,
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
        })
    }

    pub fn is_special_pe(&self) -> bool {
        matches!(self, Self::Uservars | Self::Userpurge | Self::Usercall)
    }
}

/// [BT_FUNC](https://hex-rays.com/products/ida/support/sdkdoc/group__tf__func.html#ga7b7fee21f21237beb6d91e854410e0fa)
fn read_cc(
    input: &mut impl IdaGenericBufUnpack,
) -> anyhow::Result<(u8, u16, Option<Vec<(u16, u8)>>)> {
    let mut cc = input.read_u8()?;
    // TODO find the flag for that
    if cc & 0xF0 != 0xA0 {
        return Ok((cc, 0, None));
    }
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46de7c
    let pbyte2 = input.peek_u8()?;
    if cc & 0xF != 0xF || matches!(pbyte2, Some(x) if x & 0x80 == 0) {
        let mut spoiled = None;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46df47
        let mut flags = 0;
        loop {
            if cc & 0xF == 0xF {
                let byte2 = input.read_u8()?;
                // TODO check that flags are not duplicated?
                flags |= (byte2 & 0x1F) << 1;
            } else {
                let nspoiled = cc as u16 & 0xF;
                // TODO make sure spoiled is always None?
                read_cc_spoiled(input, nspoiled, spoiled.get_or_insert_default())?;
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
        Ok((cc, (flag & 0x1E3F) as u16, Some(spoiled)))
    }
}

fn read_cc_spoiled(
    input: &mut impl IdaGenericBufUnpack,
    nspoiled: u16,
    spoiled: &mut Vec<(u16, u8)>,
) -> anyhow::Result<()> {
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
            let reg = (b & 0xF)
                .checked_sub(1)
                .ok_or_else(|| anyhow!("invalid spoiled reg value"))?;
            spoiled.push((reg.into(), size))
        }
    }
    Ok(())
}

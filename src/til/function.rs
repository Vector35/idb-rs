use crate::ida_reader::{IdaGenericBufUnpack, IdaGenericUnpack};
use crate::til::section::TILSectionHeader;
use crate::til::{associate_field_name_and_member, Basic, Type, TypeMetadata, TypeRaw, TAH};
use anyhow::{ensure, Context};

#[derive(Debug, Clone)]
pub struct Function {
    pub ret: Box<Type>,
    pub args: Vec<(Option<Vec<u8>>, Type, Option<ArgLoc>)>,
    pub retloc: Option<ArgLoc>,
}
impl Function {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: FunctionRaw,
        fields: Option<Vec<Vec<u8>>>,
    ) -> anyhow::Result<Self> {
        let args = associate_field_name_and_member(fields, value.args)
            .context("Function")?
            .map(|(n, (t, a))| Type::new(til, t, None).map(|t| (n, t, a)))
            .collect::<anyhow::Result<_, _>>()?;
        Ok(Self {
            ret: Type::new(til, *value.ret, None).map(Box::new)?,
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
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        metadata: u8,
    ) -> anyhow::Result<Self> {
        // TODO what is that?
        let mut flags = metadata << 2;

        let cc = Self::read_cc(&mut *input, &mut flags)?;

        let _tah = TAH::read(&mut *input)?;
        let ret = TypeRaw::read(&mut *input, header)?;
        // TODO double check documentation for [flag::tf_func::BT_FUN]
        let have_retloc = cc.get_calling_convention().is_special_pe()
            && !matches!(&ret, TypeRaw::Basic(Basic::Void));
        let retloc = have_retloc.then(|| ArgLoc::read(&mut *input)).transpose()?;
        if cc.get_calling_convention().is_void_arg() {
            return Ok(Self {
                ret: Box::new(ret),
                args: vec![],
                retloc,
            });
        }

        let n = input.read_dt()?;
        let is_special_pe = cc.get_calling_convention().is_special_pe();
        let args = (0..n)
            .map(|_| -> anyhow::Result<_> {
                let tmp = input.fill_buf()?.first().copied();
                if tmp == Some(0xFF) {
                    // TODO what is this?
                    let _tmp: u8 = bincode::deserialize_from(&mut *input)?;
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
            ret: Box::new(ret),
            args,
            retloc,
        })
    }

    /// [BT_FUNC](https://hex-rays.com/products/ida/support/sdkdoc/group__tf__func.html#ga7b7fee21f21237beb6d91e854410e0fa)
    fn read_cc(
        input: &mut impl IdaGenericBufUnpack,
        flags: &mut u8,
    ) -> anyhow::Result<TypeMetadata> {
        let mut cm = TypeMetadata::read(&mut *input)?;
        if !cm.get_calling_convention().is_spoiled() {
            return Ok(cm);
        }
        // TODO find what to do with this spoiled and flags stuff
        let mut _spoiled = vec![];
        loop {
            // TODO create flags::CM_CC_MASK
            let nspoiled = cm.0 & 0xf;
            if nspoiled == 0xF {
                let bfa_byte: u8 = bincode::deserialize_from(&mut *input)?;
                if bfa_byte & 0x80 != 0 {
                    // TODO what is this? Do this repeat `bfa_byte & 0xF` number of times?
                    let _fti_bits: u16 = bincode::deserialize_from(&mut *input)?;
                } else {
                    *flags |= (bfa_byte & 0x1F) << 1;
                }
            } else {
                for _ in 0..nspoiled {
                    let b: u8 = bincode::deserialize_from(&mut *input)?;
                    let (size, reg) = if b & 0x80 != 0 {
                        let size: u8 = bincode::deserialize_from(&mut *input)?;
                        let reg = b & 0x7F;
                        (size, reg)
                    } else {
                        ensure!(b > 0, "Unable to solve register from a spoiled function");
                        let size = (b >> 4) + 1;
                        let reg = (b & 0xF) - 1;
                        (size, reg)
                    };
                    _spoiled.push((size, reg));
                }
                *flags |= 1;
            }

            cm = TypeMetadata::read(&mut *input)?;
            if !cm.get_calling_convention().is_spoiled() {
                return Ok(cm);
            }
        }
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
            let typ = input.read_dt()?;
            match typ & 0xF {
                0 => Ok(Self::None),
                1 => {
                    let sval = input.read_de()?;
                    Ok(Self::Stack(sval))
                }
                2 => {
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
                3 => {
                    let reg_info = input.read_dt()?;
                    // TODO read other dt?
                    Ok(Self::Reg1(reg_info.into()))
                }
                4 => {
                    let reg_info = input.read_dt()?;
                    // TODO read other dt?
                    Ok(Self::Reg2(reg_info.into()))
                }
                5 => {
                    let reg = input.read_dt()?;
                    let off = input.read_de()?;
                    Ok(Self::RRel { reg, off })
                }
                6 => {
                    let sval = input.read_de()?;
                    Ok(Self::Static(sval))
                }
                0x7..=0xF => todo!("Custom implementation for ArgLoc"),
                _ => unreachable!(),
            }
        }
    }
}

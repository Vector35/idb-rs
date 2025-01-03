use std::num::{NonZeroU16, NonZeroU8};

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw, SDACL};
use anyhow::{anyhow, Result};
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

use super::{StructModifierRaw, TypeVariantRaw};

#[derive(Clone, Debug)]
pub struct Struct {
    pub effective_alignment: Option<NonZeroU8>,
    pub members: Vec<StructMember>,
    /// Unaligned struct
    pub is_unaligned: bool,
    /// Gcc msstruct attribute
    pub is_msstruct: bool,
    /// C++ object, not simple pod type
    pub is_cpp_obj: bool,
    /// Virtual function table
    pub is_vftable: bool,
    /// Unknown meaning, use at your own risk
    pub is_uknown_8: bool,
    /// Alignment in bytes
    pub alignment: Option<NonZeroU8>,
    // TODO delete others, parse all values or return an error
    /// other unparsed values from the type attribute
    pub others: Option<NonZeroU16>,
}
impl Struct {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: StructRaw,
        fields: &mut impl Iterator<Item = Option<Vec<u8>>>,
    ) -> Result<Self> {
        let members = value
            .members
            .into_iter()
            .map(|member| StructMember::new(til, fields.next().flatten(), member, &mut *fields))
            .collect::<Result<_>>()?;
        Ok(Struct {
            effective_alignment: value.effective_alignment,
            members,
            is_unaligned: value.modifier.is_unaligned,
            is_msstruct: value.modifier.is_msstruct,
            is_cpp_obj: value.modifier.is_cpp_obj,
            is_vftable: value.modifier.is_vftable,
            is_uknown_8: value.modifier.is_unknown_8,
            alignment: value.modifier.alignment,
            others: value.modifier.others,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StructRaw {
    effective_alignment: Option<NonZeroU8>,
    modifier: StructModifierRaw,
    members: Vec<StructMemberRaw>,
}

impl StructRaw {
    pub fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> Result<TypeVariantRaw> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459883
        let Some(n) = input.read_dt_de()? else {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // simple reference
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let _taudt_bits = SDACL::read(&mut *input)?;
            let TypeVariantRaw::Typedef(ref_type) = ref_type.variant else {
                return Err(anyhow!("StructRef Non Typedef"));
            };
            return Ok(TypeVariantRaw::StructRef(ref_type));
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
        let mem_cnt = n >> 3;
        // TODO what is effective_alignment and how it's diferent from Modifier alignment?
        let alpow = n & 7;
        let effective_alignment = (alpow != 0).then(|| NonZeroU8::new(1 << (alpow - 1)).unwrap());
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459c97
        let mut taudt_bits = SDACL::read(&mut *input)?;

        // consume the is_bit used by the StructMemberRaw
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478203
        let is_bitset = taudt_bits.0 .0 & 0x200 != 0;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47822d
        let is_bitset2 = taudt_bits.0 .0 & 0x4 != 0;
        taudt_bits.0 .0 &= !0x204;

        let members = (0..mem_cnt)
            .map(|_| StructMemberRaw::read(&mut *input, header, is_bitset, is_bitset2))
            .collect::<Result<_, _>>()?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46c4fc print_til_types_att
        let modifier = StructModifierRaw::from_value(taudt_bits.0 .0);
        Ok(TypeVariantRaw::Struct(Self {
            effective_alignment,
            modifier,
            members,
        }))
    }
}

#[derive(Clone, Debug)]
pub struct StructMember {
    pub name: Option<Vec<u8>>,
    pub member_type: Type,
    pub sdacl: SDACL,
    pub att: Option<StructMemberAtt>,
}

impl StructMember {
    fn new(
        til: &TILSectionHeader,
        name: Option<Vec<u8>>,
        m: StructMemberRaw,
        fields: &mut impl Iterator<Item = Option<Vec<u8>>>,
    ) -> Result<Self> {
        Ok(Self {
            name,
            member_type: Type::new(til, m.ty, fields)?,
            sdacl: m.sdacl,
            att: m.att,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct StructMemberRaw {
    pub ty: TypeRaw,
    pub sdacl: SDACL,
    pub att: Option<StructMemberAtt>,
}

impl StructMemberRaw {
    fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        is_bit_set: bool,
        is_bit_set2: bool,
    ) -> Result<Self> {
        let ty = TypeRaw::read(&mut *input, header)?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478256
        let att = is_bit_set
            .then(|| Self::read_member_att_1(input, header))
            .transpose()?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47825d
        let mut sdacl = SDACL(crate::til::TypeAttribute(0));
        if !is_bit_set || matches!(att, Some(_att1)) {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47825d
            sdacl = SDACL::read(&mut *input)?;
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47822d
            if is_bit_set2 && sdacl.0 .0 & 0x200 == 0 {
                // TODO there is more to this impl?
                // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478411
                // todo!();
            }
        }

        Ok(Self { ty, sdacl, att })
    }

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486cd0
    fn read_member_att_1(
        input: &mut impl IdaGenericBufUnpack,
        _header: &TILSectionHeader,
    ) -> Result<StructMemberAtt> {
        let att = input.read_ext_att()?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486d0d
        match att & 0xf {
            0xd..=0xf => Err(anyhow!("Invalid value for member attribute {att:#x}")),
            0..=7 => Ok(StructMemberAtt::Var0to7(Self::basic_att(input, att)?)),
            8 | 0xb => todo!(),
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486d3f
            9 => {
                let val1 = input.read_de()?;
                // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486f8d
                let att0 = (val1 & 0x1010 == 0)
                    .then(|| input.read_ext_att())
                    .transpose()?;

                let att1 = input.read_ext_att()?;
                let att2 = input.read_ext_att()?;
                // TODO find this value
                Ok(StructMemberAtt::Var9 {
                    val1,
                    att0,
                    att1,
                    att2,
                })
            }
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486e50
            0xa | 0xc => {
                let val1 = input.read_de()?;
                let att0 = Self::basic_att(input, att)?;
                Ok(StructMemberAtt::VarAorC { val1, att0 })
            }
            0x10.. => unreachable!(),
        }
    }

    fn basic_att(input: &mut impl IdaGenericBufUnpack, att: u64) -> Result<StructMemberAttBasic> {
        if (att >> 8) & 0x10 != 0 {
            // TODO this is diferent from the implementation, double check the read_de and this code
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486df0
            let val1 = input.read_de()?;
            let val2 = input.read_de()?;
            let val3 = input.read_de()?;
            Ok(StructMemberAttBasic::Var2 {
                att,
                val1,
                val2,
                val3,
            })
        } else {
            Ok(StructMemberAttBasic::Var1(att))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StructMemberAtt {
    Var0to7(StructMemberAttBasic),
    Var9 {
        val1: u32,
        att0: Option<u64>,
        att1: u64,
        att2: u64,
    },
    VarAorC {
        val1: u32,
        att0: StructMemberAttBasic,
    },
}

// InnerRef InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x720880
#[derive(Clone, Copy, Debug)]
pub enum StructMemberAttBasic {
    Var1(u64),
    Var2 {
        att: u64,
        val1: u32,
        val2: u32,
        val3: u32,
    },
}

impl StructMemberAtt {
    pub fn str_type(self) -> Option<StringType> {
        match self {
            // 0x8 0xa   "__strlit"
            StructMemberAtt::VarAorC {
                val1,
                att0: StructMemberAttBasic::Var1(0xa),
            } => Some(val1.into()),
            _ => None,
        }
    }
    pub fn offset_type(self) -> Option<ExtAttOffset> {
        match self {
            // 0x8 0x9   "__offset"
            StructMemberAtt::Var9 {
                val1,
                att0: None,
                att1: 0,
                att2: u64::MAX,
            } => Some(ExtAttOffset {
                offset: (val1 & 0xf) as u8,
                flag: val1 & !0xf,
            }),
            _ => None,
        }
    }

    pub fn basic(self) -> Option<ExtAttBasic> {
        match self {
            StructMemberAtt::Var0to7(StructMemberAttBasic::Var1(raw)) => {
                ExtAttBasic::from_raw(raw, None)
            }
            // 0x9 0x1000 "__tabform"
            StructMemberAtt::Var0to7(StructMemberAttBasic::Var2 {
                att,
                val1,
                val2,
                val3: u32::MAX,
            }) if att & 0x1000 != 0 => ExtAttBasic::from_raw(att & !0x1000, Some((val1, val2))),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExtAttOffset {
    pub offset: u8,
    // InnerRef InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x720aa0
    flag: u32,
}

impl ExtAttOffset {
    pub fn is_rvaoff(&self) -> bool {
        self.flag & 0x10 != 0
    }
    pub fn is_pastend(&self) -> bool {
        self.flag & 0x20 != 0
    }
    pub fn is_nobase(&self) -> bool {
        self.flag & 0x80 != 0
    }
    pub fn is_subtract(&self) -> bool {
        self.flag & 0x100 != 0
    }
    pub fn is_signedop(&self) -> bool {
        self.flag & 0x200 != 0
    }
    pub fn is_nozeroes(&self) -> bool {
        self.flag & 0x400 != 0
    }
    pub fn is_noones(&self) -> bool {
        self.flag & 0x800 != 0
    }
    pub fn is_selfref(&self) -> bool {
        self.flag & 0x1000 != 0
    }
}

#[derive(Clone, Copy, Debug, FromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum StringType {
    Utf8,
    Utf16Le,
    Utf32Le,
    Utf16Be,
    Utf32Be,
    #[num_enum(catch_all)]
    Other(u32),
}

impl StringType {
    pub fn as_strlib(self) -> u32 {
        self.into()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExtAttBasic {
    pub fmt: ExtAttBasicFmt,
    pub tabform: Option<ExtAttBasicTabform>,
    pub is_signed: bool,
    pub is_inv_sign: bool,
    pub is_inv_bits: bool,
    pub is_lzero: bool,
}
impl ExtAttBasic {
    fn from_raw(value: u64, val1: Option<(u32, u32)>) -> Option<Self> {
        use ExtAttBasicFmt::*;
        let fmt = match value & 0xf {
            0x1 => Bin,
            0x2 => Oct,
            0x3 => Hex,
            0x4 => Dec,
            0x5 => Float,
            0x6 => Char,
            0x7 => Segm,
            0x9 => Off,
            _ => return None,
        };
        let is_inv_sign = value & 0x100 != 0;
        let is_inv_bits = value & 0x200 != 0;
        let is_signed = value & 0x400 != 0;
        let is_lzero = value & 0x800 != 0;

        let tabform = val1.map(|(val1, val2)| {
            let val1 = ExtAttBasicTabformVal1::try_from_primitive(val1.try_into().ok()?).ok()?;
            Some(ExtAttBasicTabform { val1, val2 })
        });
        let tabform = match tabform {
            // convert correctly
            Some(Some(val)) => Some(val),
            // coud not convert, return nothing
            Some(None) => return None,
            // there is no tabform
            None => None,
        };

        // TODO panic on unknown values?
        Some(Self {
            fmt,
            tabform,
            is_signed,
            is_inv_sign,
            is_inv_bits,
            is_lzero,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ExtAttBasicFmt {
    Bin,
    Oct,
    Hex,
    Dec,
    Float,
    Char,
    Segm,
    Off,
}

#[derive(Clone, Copy, Debug)]
pub struct ExtAttBasicTabform {
    pub val1: ExtAttBasicTabformVal1,
    pub val2: u32,
}

#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum ExtAttBasicTabformVal1 {
    NODUPS = 0,
    HEX = 1,
    DEC = 2,
    OCT = 3,
    BIN = 4,
}

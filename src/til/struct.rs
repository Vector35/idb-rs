use std::collections::HashMap;
use std::num::NonZeroU8;

use crate::ida_reader::IdbBufRead;
use crate::til::{Type, TypeRaw};
use crate::IDBString;
use anyhow::{anyhow, ensure, Context, Result};
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use serde::Serialize;

use super::section::TILSectionHeader;
use super::{CommentType, TypeAttribute, TypeVariantRaw};

#[derive(Clone, Debug, Serialize)]
pub struct Struct {
    pub effective_alignment: Option<NonZeroU8>,
    pub members: Vec<StructMember>,
    pub extra_padding: Option<u64>,

    /// Unaligned struct
    pub is_unaligned: bool,
    /// Gcc msstruct attribute
    pub is_msstruct: bool,
    /// C++ object, not simple pod type
    is_cppobj: bool,
    /// Virtual function table
    pub is_vft: bool,
    /// struct have a fixed len
    pub is_fixed: bool,
    /// Unknown meaning, use at your own risk
    pub is_uknown_8: bool,
    /// Alignment in bytes
    pub alignment: Option<NonZeroU8>,
}
impl Struct {
    pub(crate) fn new(
        til: &TILSectionHeader,
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        value: StructRaw,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
    ) -> Result<Self> {
        let members = value
            .members
            .into_iter()
            .map(|member| {
                StructMember::new(
                    til,
                    type_by_name,
                    type_by_ord,
                    member,
                    fields,
                    comments,
                )
            })
            .collect::<Result<_>>()?;
        Ok(Struct {
            effective_alignment: value.effective_alignment,
            members,
            extra_padding: value.extra_padding,
            is_unaligned: value.is_unaligned,
            is_msstruct: value.is_msstruct,
            is_cppobj: value.is_cppobj,
            is_vft: value.is_vft,
            is_fixed: value.is_fixed,
            is_uknown_8: value.is_unknown_8,
            alignment: value.alignment,
        })
    }

    pub fn is_cppobj(&self) -> bool {
        // TODO check innerref, maybe baseclass don't need to be the first, nor
        // need to only one
        self.is_cppobj
            || matches!(self.members.first(), Some(first) if first.is_baseclass)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StructRaw {
    effective_alignment: Option<NonZeroU8>,
    members: Vec<StructMemberRaw>,
    extra_padding: Option<u64>,

    /// Unaligned struct
    is_unaligned: bool,
    /// Gcc msstruct attribute
    is_msstruct: bool,
    /// C++ object, not simple pod type
    is_cppobj: bool,
    /// Virtual function table
    is_vft: bool,
    /// struct have a fixed len
    is_fixed: bool,
    // TODO unknown meaning
    is_unknown_8: bool,
    /// Alignment in bytes
    alignment: Option<NonZeroU8>,
}

impl StructRaw {
    pub fn read(
        input: &mut impl IdbBufRead,
        header: &TILSectionHeader,
    ) -> Result<TypeVariantRaw> {
        // TODO n == 0 && n_cond == false?
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x325f87
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x303393
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459883
        let Some((n, _)) = input.read_dt_de()? else {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // simple reference
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let _taudt_bits = input.read_sdacl()?;
            let TypeVariantRaw::Typedef(ref_type) = ref_type.variant else {
                return Err(anyhow!("StructRef Non Typedef"));
            };
            return Ok(TypeVariantRaw::StructRef(ref_type));
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
        let mem_cnt = n >> 3;
        // TODO what is effective_alignment and how it's diferent from Modifier alignment?
        let packalig = n & 7;
        let effective_alignment = (packalig != 0)
            .then(|| NonZeroU8::new(1 << (packalig - 1)).unwrap());
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459c97
        let mut alignment = None;
        let mut is_unknown_8 = false;
        let mut is_msstruct = false;
        let mut is_unaligned = false;
        let mut is_cppobj = false;
        let mut is_vft = false;
        let mut is_fixed = false;
        let mut is_method = false;
        let mut is_bitset2 = false;
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x30379a
        if let Some(TypeAttribute {
            tattr,
            extended: _extended,
        }) = input.read_sdacl()?
        {
            use crate::til::flag::tattr::*;
            use crate::til::flag::tattr_field::*;
            use crate::til::flag::tattr_udt::*;

            let align_raw = (tattr & MAX_DECL_ALIGN) as u8;

            // TODO WHY?
            is_unknown_8 = align_raw & 0x8 != 0;
            alignment = (align_raw & 0x7 != 0)
                .then(|| NonZeroU8::new(1 << ((align_raw & 0x7) - 1)).unwrap());

            is_msstruct = tattr & TAUDT_MSSTRUCT != 0;
            is_unaligned = tattr & TAUDT_UNALIGNED != 0;
            is_cppobj = tattr & TAUDT_CPPOBJ != 0;
            is_vft = tattr & TAUDT_VFTABLE != 0;
            is_fixed = tattr & TAUDT_FIXED != 0;
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478203
            // TODO using a field flag on the struct seems out-of-place
            is_method = tattr & TAFLD_METHOD != 0;
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47822d
            // TODO this value can't be right, it defines the alignment!
            is_bitset2 = align_raw & 0x4 != 0;

            const _ALL_FLAGS: u16 = MAX_DECL_ALIGN
                | TAUDT_MSSTRUCT
                | TAUDT_UNALIGNED
                | TAUDT_CPPOBJ
                | TAUDT_VFTABLE
                | TAUDT_FIXED
                | TAFLD_METHOD;
            #[cfg(feature = "restrictive")]
            ensure!(
                tattr & !_ALL_FLAGS == 0,
                "Invalid Struct taenum_bits {tattr:x}"
            );
            #[cfg(feature = "restrictive")]
            ensure!(
                _extended.is_none(),
                "Unable to parse extended attributes for struct"
            );
        }

        let members = (0..mem_cnt)
            .map(|i| {
                StructMemberRaw::read(
                    &mut *input,
                    header,
                    is_method,
                    is_fixed,
                    is_bitset2,
                )
                .with_context(|| format!("Member {i}"))
            })
            .collect::<Result<_, _>>()?;

        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x3269ca
        let extra_padding =
            is_fixed.then(|| input.read_ext_att()).transpose()?;

        Ok(TypeVariantRaw::Struct(Self {
            effective_alignment,
            members,
            extra_padding,
            is_unaligned,
            is_msstruct,
            is_cppobj,
            is_vft,
            is_fixed,
            is_unknown_8,
            alignment,
        }))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StructMember {
    pub name: Option<IDBString>,
    pub comment: Option<CommentType>,
    pub member_type: Type,
    pub att: Option<StructMemberAtt>,

    pub alignment: Option<NonZeroU8>,
    pub is_baseclass: bool,
    pub is_unaligned: bool,
    pub is_vft: bool,
    pub is_method: bool,
    pub is_unknown_8: bool,
}

impl StructMember {
    fn new(
        til: &TILSectionHeader,
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        m: StructMemberRaw,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
    ) -> Result<Self> {
        let name = fields.next().flatten();
        let comment = comments.next().flatten();
        Ok(Self {
            name,
            comment,
            member_type: Type::new(
                til,
                type_by_name,
                type_by_ord,
                m.ty,
                fields,
                None,
                comments,
            )?,
            att: m.att,
            alignment: m.alignment,
            is_baseclass: m.is_baseclass,
            is_unaligned: m.is_unaligned,
            is_vft: m.is_vft,
            is_method: m.is_method,
            is_unknown_8: m.is_unknown_8,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct StructMemberRaw {
    pub ty: TypeRaw,
    pub att: Option<StructMemberAtt>,
    pub alignment: Option<NonZeroU8>,
    pub is_baseclass: bool,
    pub is_unaligned: bool,
    pub is_vft: bool,
    pub is_method: bool,
    pub is_unknown_8: bool,
}

impl StructMemberRaw {
    fn read(
        input: &mut impl IdbBufRead,
        header: &TILSectionHeader,
        is_method: bool,
        is_fixed: bool,
        is_bit_set2: bool,
    ) -> Result<Self> {
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x326610
        let ty = TypeRaw::read(&mut *input, header)?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478256
        let att = is_method
            .then(|| Self::read_member_att_1(input, header))
            .transpose()?;

        let mut alignment = None;
        let mut is_baseclass = false;
        let mut is_unaligned = false;
        let mut is_vft = false;
        let mut is_method = false;
        let mut is_unknown_8 = false;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47825d
        if !is_method || att.is_some() {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47825d
            if let Some(TypeAttribute {
                tattr,
                extended: _extended,
            }) = input.read_sdacl()?
            {
                use crate::til::flag::tattr::*;
                use crate::til::flag::tattr_field::*;

                let alignment_raw = (tattr & MAX_DECL_ALIGN) as u8;
                is_unknown_8 = alignment_raw & 0x8 != 0;
                alignment = ((alignment_raw & 0x7) != 0).then(|| {
                    NonZeroU8::new(1 << ((alignment_raw & 0x7) - 1)).unwrap()
                });
                is_baseclass = tattr & TAFLD_BASECLASS != 0;
                is_unaligned = tattr & TAFLD_UNALIGNED != 0;
                let is_virtbase = tattr & TAFLD_VIRTBASE != 0;
                ensure!(
                    !is_virtbase,
                    "UDT Member virtual base is not supported yet"
                );
                is_vft = tattr & TAFLD_VFTABLE != 0;
                // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478203
                is_method = tattr & TAFLD_METHOD != 0;
                // TODO handle those flags
                let _is_gap = tattr & TAFLD_GAP != 0;
                let _is_regcmt = tattr & TAFLD_REGCMT != 0;
                let _is_frame_r = tattr & TAFLD_FRAME_R != 0;
                let _is_frame_s = tattr & TAFLD_FRAME_S != 0;
                let _is_bytil = tattr & TAFLD_BYTIL != 0;
                const _ALL_FLAGS: u16 = MAX_DECL_ALIGN
                    | TAFLD_BASECLASS
                    | TAFLD_UNALIGNED
                    | TAFLD_VFTABLE
                    | TAFLD_METHOD
                    | TAFLD_GAP
                    | TAFLD_REGCMT
                    | TAFLD_FRAME_R
                    | TAFLD_FRAME_S
                    | TAFLD_BYTIL;
                #[cfg(feature = "restrictive")]
                ensure!(
                    tattr & !_ALL_FLAGS == 0,
                    "Invalid Struct taenum_bits {tattr:x}"
                );
                #[cfg(feature = "restrictive")]
                ensure!(
                    _extended.is_none(),
                    "Unable to parse extended attributes for struct member"
                );
            }

            if is_fixed && !is_method {
                // TODO unknown meaning
                // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x326820
                let _value = input.read_ext_att()?;
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47822d
            if is_bit_set2 && !is_method {
                // TODO there is more to this impl?
                // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478411
                // todo!();
            }
        }

        Ok(Self {
            ty,
            att,
            alignment,
            is_baseclass,
            is_unaligned,
            is_vft,
            is_method,
            is_unknown_8,
        })
    }

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486cd0
    fn read_member_att_1(
        input: &mut impl IdbBufRead,
        _header: &TILSectionHeader,
    ) -> Result<StructMemberAtt> {
        let att = input.read_ext_att()?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486d0d
        match att & 0xf {
            0xd..=0xf => {
                Err(anyhow!("Invalid value for member attribute {att:#x}"))
            }
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

    fn basic_att(
        input: &mut impl IdbBufRead,
        att: u64,
    ) -> Result<StructMemberAttBasic> {
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

#[derive(Clone, Copy, Debug, Serialize)]
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
#[derive(Clone, Copy, Debug, Serialize)]
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
            }) if att & 0x1000 != 0 => {
                ExtAttBasic::from_raw(att & !0x1000, Some((val1, val2)))
            }
            _ => None,
        }
    }

    pub fn basic_offset_type(self) -> Option<(u32, bool)> {
        // TODO find the InnerRef
        match self {
            StructMemberAtt::Var9 {
                val1,
                att0: Some(att0 @ (0 | 0x4e8 | 0x3f58)),
                att1: 0,
                att2: u64::MAX,
            } => Some((val1, att0 != 0)),
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
            let val1 = ExtAttBasicTabformVal1::try_from_primitive(
                val1.try_into().ok()?,
            )
            .ok()?;
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

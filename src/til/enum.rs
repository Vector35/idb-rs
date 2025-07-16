use std::num::NonZeroU8;

use crate::ida_reader::IdbBufRead;
use crate::til::{flag, TypeAttribute, TypeRaw, TypeVariantRaw};
use crate::IDBString;
use anyhow::{anyhow, ensure, Result};
use serde::Serialize;

use super::section::TILSectionHeader;
use super::CommentType;

#[derive(Clone, Debug, Serialize)]
pub struct Enum {
    pub is_signed: bool,
    pub is_unsigned: bool,
    pub is_64: bool,
    pub output_format: EnumFormat,
    pub members: EnumMembers,
    pub storage_size: Option<NonZeroU8>,
    // TODO parse type attributes
    //others: StructMemberRaw,
}

impl Enum {
    pub(crate) fn new(
        _til: &TILSectionHeader,
        value: EnumRaw,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
    ) -> Result<Self> {
        let members = match value.members {
            EnumMembersRaw::Regular(members) => EnumMembers::Regular(
                members
                    .into_iter()
                    .map(|member| {
                        Self::new_enum_member(member, fields, comments)
                    })
                    .collect(),
            ),
            EnumMembersRaw::BitMask(members) => EnumMembers::Groups(
                members
                    .into_iter()
                    .map(|(mask, members)| {
                        let field =
                            Self::new_enum_member(mask, fields, comments);
                        let sub_fields = members
                            .into_iter()
                            .map(|member| {
                                Self::new_enum_member(member, fields, comments)
                            })
                            .collect();
                        EnumGroup { field, sub_fields }
                    })
                    .collect(),
            ),
        };
        Ok(Self {
            is_signed: value.is_signed,
            is_unsigned: value.is_unsigned,
            is_64: value.is_64,
            output_format: value.output_format,
            members,
            storage_size: value.storage_size,
        })
    }

    pub(crate) fn new_enum_member(
        value: u64,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
    ) -> EnumMember {
        EnumMember {
            name: fields.next().flatten(),
            comment: comments.next().flatten(),
            value,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub enum EnumMembers {
    Regular(Vec<EnumMember>),
    Groups(Vec<EnumGroup>),
}

#[derive(Clone, Debug, Serialize)]
pub struct EnumGroup {
    pub field: EnumMember,
    pub sub_fields: Vec<EnumMember>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnumMember {
    pub name: Option<IDBString>,
    pub comment: Option<CommentType>,
    pub value: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct EnumRaw {
    pub(crate) is_signed: bool,
    pub(crate) is_unsigned: bool,
    pub(crate) is_64: bool,
    pub(crate) output_format: EnumFormat,
    pub(crate) members: EnumMembersRaw,
    pub(crate) storage_size: Option<NonZeroU8>,
}

#[derive(Clone, Debug)]
pub(crate) enum EnumMembersRaw {
    Regular(Vec<u64>),
    BitMask(Vec<(u64, Vec<u64>)>),
}

impl EnumRaw {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473a08
    pub(crate) fn read(
        input: &mut impl IdbBufRead,
        header: &TILSectionHeader,
    ) -> Result<TypeVariantRaw> {
        use flag::tattr_enum::*;
        use flag::tf_enum::*;

        // TODO n == 0 && n_cond == false?
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x325f87
        let Some((member_num, _)) = input.read_dt_de()? else {
            // is ref
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            // TODO ensure all bits from sdacl are parsed
            let _taenum_bits = input.read_sdacl()?;
            let TypeVariantRaw::Typedef(ref_type) = ref_type.variant else {
                return Err(anyhow!("EnumRef Non Typedef"));
            };
            return Ok(TypeVariantRaw::EnumRef(ref_type));
        };

        let mut is_64 = false;
        let mut is_signed = false;
        let mut is_unsigned = false;
        if let Some(TypeAttribute {
            tattr,
            extended: _extended,
        }) = input.read_tah()?
        {
            // TODO enum have an align field (MAX_DECL_ALIGN) in tattr?
            is_64 = tattr & TAENUM_64BIT != 0;
            is_signed = tattr & TAENUM_SIGNED != 0;
            is_unsigned = tattr & TAENUM_UNSIGNED != 0;
            // TODO handle those flags
            let _is_oct = tattr & TAENUM_OCT != 0;
            let _is_bin = tattr & TAENUM_BIN != 0;
            let _is_numsign = tattr & TAENUM_NUMSIGN != 0;
            let _is_lzero = tattr & TAENUM_LZERO != 0;

            #[cfg(feature = "restrictive")]
            {
                const ALL_FLAGS: crate::til::flag::TattrT = TAENUM_64BIT
                    | TAENUM_SIGNED
                    | TAENUM_UNSIGNED
                    | TAENUM_OCT
                    | TAENUM_BIN
                    | TAENUM_NUMSIGN
                    | TAENUM_LZERO;
                ensure!(
                    tattr & !ALL_FLAGS == 0,
                    "Invalid Enum taenum_bits {tattr:x}"
                );
            }
            #[cfg(feature = "restrictive")]
            ensure!(
                !(is_signed && is_unsigned),
                "Enum can't be signed and unsigned at the same time"
            );
            #[cfg(feature = "restrictive")]
            ensure!(
                _extended.is_none(),
                "Unable to parse extended attributes for Enum"
            );
        }

        // all BTE bits are consumed
        let bte = input.read_u8()?;
        let storage_size_raw = bte & BTE_SIZE_MASK;
        #[cfg(feature = "restrictive")]
        ensure!(
            bte & BTE_RESERVED == 0,
            "Enum BTE including the Always off sub-field"
        );
        let output_format_raw = bte & BTE_OUT_MASK;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452312 deserialize_enum
        ensure!(
            bte & BTE_ALWAYS != 0,
            "Enum BTE missing the Always on sub-field"
        );

        let storage_size: Option<NonZeroU8> = match storage_size_raw {
            0 => None,
            emsize @ 1..=4 => Some((1 << (emsize - 1)).try_into().unwrap()),
            // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4523c8 deserialize_enum
            5..=7 => return Err(anyhow!("BTE emsize with reserved values")),
            _ => unreachable!(),
        };
        // TODO enum size defaults to 4?
        let storage_size_final = storage_size.map(NonZeroU8::get).unwrap_or(4);
        let mask: u64 = if storage_size_final >= 16 {
            #[cfg(feature = "restrictive")]
            return Err(anyhow!("Bytes size is too big"));
            #[cfg(not(feature = "restrictive"))]
            u64::MAX
        } else {
            u64::MAX >> (u64::BITS - (storage_size_final as u32 * 8))
        };

        let output_format = match output_format_raw {
            BTE_HEX => EnumFormat::Hex,
            BTE_CHAR => EnumFormat::Char,
            BTE_SDEC => EnumFormat::SignedDecimal,
            BTE_UDEC => EnumFormat::UnsignedDecimal,
            _ => unreachable!(),
        };

        let members = if bte & BTE_BITFIELD != 0 {
            EnumMembersRaw::BitMask(Self::read_members_bitmask(
                input, member_num, mask, is_64,
            )?)
        } else {
            EnumMembersRaw::Regular(Self::read_member_regular(
                input, member_num, mask, is_64,
            )?)
        };

        Ok(TypeVariantRaw::Enum(EnumRaw {
            is_signed,
            is_unsigned,
            is_64,
            output_format,
            members,
            storage_size,
        }))
    }

    fn read_member_regular(
        input: &mut impl IdbBufRead,
        member_num: u32,
        mask: u64,
        is_64: bool,
    ) -> Result<Vec<u64>> {
        let mut low_acc: u32 = 0;
        let mut high_acc: u32 = 0;
        (0..member_num)
            .map(|_member_idx| {
                // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x45242f deserialize_enum
                // NOTE this is originaly i32, but wrapping_add a u32/i32 have the same result
                low_acc = low_acc.wrapping_add(input.read_de()?);
                if is_64 {
                    high_acc = high_acc.wrapping_add(input.read_de()?);
                }

                // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452472 deserialize_enum
                Ok((((high_acc as u64) << 32) | low_acc as u64) & mask)
            })
            .collect()
    }

    fn read_members_bitmask(
        input: &mut impl IdbBufRead,
        member_num: u32,
        mask: u64,
        is_64: bool,
    ) -> Result<Vec<(u64, Vec<u64>)>> {
        (0..member_num)
            .map(|_i| {
                // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452527 deserialize_enum
                let group_num = input.read_dt()?;
                ensure!(group_num != 0);

                let mask_low = input.read_de()?;
                let mask_high = if is_64 { input.read_de()? } else { 0 };
                let mask =
                    (((mask_high as u64) << 32) | mask_low as u64) & mask;
                let mut acc_low: u32 = 0;
                let mut acc_high: u32 = 0;
                let sub_members = (0..group_num - 1)
                    .map(|_i| {
                        // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x45242f deserialize_enum
                        // NOTE this is originaly i32, but wrapping_add a u32/i32 have the same result
                        acc_low = acc_low.wrapping_add(input.read_de()?);
                        if is_64 {
                            acc_high = acc_high.wrapping_add(input.read_de()?);
                        }

                        // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452472 deserialize_enum
                        Ok((((acc_high as u64) << 32) | acc_low as u64) & mask)
                    })
                    .collect::<Result<_>>()?;
                Ok((mask, sub_members))
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum EnumFormat {
    Char,
    Hex,
    SignedDecimal,
    UnsignedDecimal,
}

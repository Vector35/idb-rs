use std::num::NonZeroU8;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::{flag, TypeAttribute, TypeRaw, TypeVariantRaw};
use crate::IDBString;
use anyhow::{anyhow, ensure};

use super::section::TILSectionHeader;
use super::CommentType;

#[derive(Clone, Debug)]
pub struct Enum {
    pub is_signed: bool,
    pub is_unsigned: bool,
    pub is_64: bool,
    pub output_format: EnumFormat,
    pub members: Vec<EnumMember>,
    pub groups: Option<Vec<u16>>,
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
    ) -> anyhow::Result<Self> {
        let members = value
            .members
            .into_iter()
            .map(|member| EnumMember {
                name: fields.next().flatten(),
                comment: comments.next().flatten(),
                value: member,
            })
            .collect();
        Ok(Self {
            is_signed: value.is_signed,
            is_unsigned: value.is_unsigned,
            is_64: value.is_64,
            output_format: value.output_format,
            members,
            groups: value.groups,
            storage_size: value.storage_size,
        })
    }
}

#[derive(Clone, Debug)]
pub struct EnumMember {
    pub name: Option<IDBString>,
    pub comment: Option<CommentType>,
    pub value: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct EnumRaw {
    is_signed: bool,
    is_unsigned: bool,
    is_64: bool,
    output_format: EnumFormat,
    groups: Option<Vec<u16>>,
    members: Vec<u64>,
    storage_size: Option<NonZeroU8>,
}

impl EnumRaw {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473a08
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<TypeVariantRaw> {
        use flag::tattr_enum::*;
        use flag::tf_enum::*;

        let Some(member_num) = input.read_dt_de()? else {
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
            #[cfg(feature = "restrictive")]
            ensure!(
                tattr & !(TAENUM_64BIT | TAENUM_SIGNED | TAENUM_UNSIGNED) == 0,
                "Invalid Enum taenum_bits {tattr:x}"
            );
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
        let have_subarrays = bte & BTE_BITFIELD != 0;
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

        let mut low_acc: u32 = 0;
        let mut high_acc: u32 = 0;
        let mut group_acc = 0;
        let mut groups = have_subarrays.then_some(vec![]);
        let members = (0..member_num)
            .map(|_member_idx| {
                if let Some(groups) = &mut groups {
                    // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452527 deserialize_enum
                    if group_acc == 0 {
                        group_acc = input.read_dt()?;
                        groups.push(group_acc);
                    }
                    group_acc -= 1;
                }
                // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x45242f deserialize_enum
                // NOTE this is originaly i32, but wrapping_add a u32/i32 have the same result
                low_acc = low_acc.wrapping_add(input.read_de()?);
                if is_64 {
                    high_acc = high_acc.wrapping_add(input.read_de()?);
                }
                // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452472 deserialize_enum
                Ok((((high_acc as u64) << 32) | low_acc as u64) & mask)
            })
            .collect::<anyhow::Result<_>>()?;

        Ok(TypeVariantRaw::Enum(EnumRaw {
            is_signed,
            is_unsigned,
            is_64,
            output_format,
            members,
            groups,
            storage_size,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EnumFormat {
    Char,
    Hex,
    SignedDecimal,
    UnsignedDecimal,
}

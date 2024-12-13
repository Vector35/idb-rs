use std::num::NonZeroU8;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{associate_field_name_and_member, flag, Type, TypeAttribute, TypeRaw, SDACL, TAH};
use anyhow::{anyhow, ensure, Context};

#[derive(Clone, Debug)]
pub enum Enum {
    Ref {
        ref_type: Box<Type>,
        taenum_bits: TypeAttribute,
    },
    NonRef {
        output_format: EnumFormat,
        members: Vec<(Option<Vec<u8>>, u64)>,
        groups: Vec<u16>,
        storage_size: Option<NonZeroU8>,
    },
}
impl Enum {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: EnumRaw,
        fields: Option<Vec<Vec<u8>>>,
    ) -> anyhow::Result<Self> {
        match value {
            EnumRaw::Ref {
                ref_type,
                taenum_bits,
            } => {
                if matches!(&fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Ref Enum"));
                }
                Ok(Enum::Ref {
                    ref_type: Type::new(til, *ref_type, None).map(Box::new)?,
                    taenum_bits,
                })
            }
            EnumRaw::NonRef {
                output_format,
                members,
                groups,
                storage_size,
            } => {
                let members = associate_field_name_and_member(fields, members)
                    .context("Enum")?
                    .collect();
                Ok(Enum::NonRef {
                    output_format,
                    members,
                    groups,
                    storage_size,
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum EnumRaw {
    Ref {
        ref_type: Box<TypeRaw>,
        taenum_bits: TypeAttribute,
    },
    NonRef {
        output_format: EnumFormat,
        groups: Vec<u16>,
        members: Vec<u64>,
        storage_size: Option<NonZeroU8>,
    },
}

impl EnumRaw {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473a08
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Self> {
        use flag::tf_enum::*;
        let Some(member_num) = input.read_dt_de()? else {
            // is ref
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let taenum_bits = SDACL::read(&mut *input)?.0;
            return Ok(EnumRaw::Ref {
                ref_type: Box::new(ref_type),
                taenum_bits,
            });
        };

        let _taenum_bits = TAH::read(&mut *input)?.0;
        // TODO parse ext attr
        let bte = input.read_u8()?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452312 deserialize_enum
        ensure!(
            bte & BTE_ALWAYS != 0,
            "Enum BTE missing the Always sub-field"
        );
        let storage_size: Option<NonZeroU8> = match bte & BTE_SIZE_MASK {
            0 => header.size_enum,
            emsize @ 1..=4 => Some((1 << (emsize - 1)).try_into().unwrap()),
            // Allowed at InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4523c8 deserialize_enum
            5..=7 => return Err(anyhow!("BTE emsize with reserved values")),
            _ => unreachable!(),
        };
        // TODO enum size defaults to 4?
        let storage_size_final = storage_size.map(NonZeroU8::get).unwrap_or(4);
        let mask: u64 = if storage_size_final >= 16 {
            // is saturating valid?
            //u64::MAX
            return Err(anyhow!("Bytes size is too big"));
        } else {
            u64::MAX >> (u64::BITS - (storage_size_final as u32 * 8))
        };

        let output_format = match bte & BTE_OUT_MASK {
            BTE_HEX => EnumFormat::Hex,
            BTE_CHAR => EnumFormat::Char,
            BTE_SDEC => EnumFormat::SignedDecimal,
            BTE_UDEC => EnumFormat::UnsignedDecimal,
            _ => unreachable!(),
        };

        let is_64 = (_taenum_bits.0 & 0x20) != 0;
        let mut cur: u64 = 0;
        let mut groups = vec![];
        let members = (0..member_num)
            .map(|_member_idx| {
                let mut step: u64 = input.read_de()?.into();
                if is_64 {
                    let hi: u64 = input.read_de()?.into();
                    step |= hi << 32;
                }
                if bte & BTE_BITFIELD != 0 {
                    let group_size = input.read_dt()?;
                    groups.push(group_size);
                }
                // TODO check is this is wrapping by default
                cur = cur.wrapping_add(step & mask);
                Ok(cur)
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(EnumRaw::NonRef {
            output_format,
            members,
            groups,
            storage_size,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EnumFormat {
    Char,
    Hex,
    SignedDecimal,
    UnsignedDecimal,
}

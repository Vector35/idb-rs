use std::num::NonZeroU8;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{associate_field_name_and_member, flag, Type, TypeAttribute, TypeRaw, SDACL, TAH};
use anyhow::{anyhow, Context};

#[derive(Clone, Debug)]
pub enum Enum {
    Ref {
        ref_type: Box<Type>,
        taenum_bits: TypeAttribute,
    },
    NonRef {
        group_sizes: Vec<u16>,
        taenum_bits: TypeAttribute,
        bte: u8,
        members: Vec<(Option<Vec<u8>>, u64)>,
        bytesize: Option<NonZeroU8>,
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
                group_sizes,
                taenum_bits,
                bte,
                members,
                bytesize,
            } => {
                let members = associate_field_name_and_member(fields, members)
                    .context("Enum")?
                    .collect();
                Ok(Enum::NonRef {
                    group_sizes,
                    taenum_bits,
                    bte,
                    members,
                    bytesize,
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
        group_sizes: Vec<u16>,
        taenum_bits: TypeAttribute,
        bte: u8,
        members: Vec<u64>,
        bytesize: Option<NonZeroU8>,
    },
}

impl EnumRaw {
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Self> {
        let Some(n) = input.read_dt_de()? else {
            // is ref
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let taenum_bits = SDACL::read(&mut *input)?.0;
            return Ok(EnumRaw::Ref {
                ref_type: Box::new(ref_type),
                taenum_bits,
            });
        };

        let taenum_bits = TAH::read(&mut *input)?.0;
        let bte = bincode::deserialize_from(&mut *input)?;
        let mut cur: u64 = 0;
        let emsize = bte & flag::tf_enum::BTE_SIZE_MASK;
        let bytesize: Option<NonZeroU8> = match emsize {
            0 => None,
            1..=4 => Some((1 << (emsize - 1)).try_into().unwrap()),
            5..=7 => return Err(anyhow!("BTE emsize with reserved values")),
            _ => unreachable!(),
        };

        // TODO enum size defaults to 4?
        let bytesize_final = bytesize
            .map(|x| x.get())
            .or(header.size_enum.map(|x| x.get().into()))
            .unwrap_or(4);
        let mask: u64 = if bytesize_final >= 16 {
            // is saturating valid?
            //u64::MAX
            return Err(anyhow!("Bytes size is too big"));
        } else {
            u64::MAX >> (u64::BITS - (bytesize_final as u32 * 8))
        };

        let mut group_sizes = vec![];
        let mut members = vec![];
        for _ in 0..n {
            let lo: u64 = input.read_de()?.into();
            let is_64 = (taenum_bits.0 & 0x0020) != 0;
            let step = if is_64 {
                let hi: u64 = input.read_de()?.into();
                (lo | (hi << 32)) & mask
            } else {
                lo & mask
            };
            // TODO: subarrays
            // https://www.hex-rays.com/products/ida/support/sdkdoc/group__tf__enum.html#ga9ae7aa54dbc597ec17cbb17555306a02
            if (bte & flag::tf_enum::BTE_BITFIELD) != 0 {
                let group_size = input.read_dt()?;
                group_sizes.push(group_size);
            }
            // TODO check is this is wrapping by default
            let next_step = cur.wrapping_add(step);
            cur = next_step;
            members.push(cur);
        }
        Ok(EnumRaw::NonRef {
            group_sizes,
            taenum_bits,
            bte,
            members,
            bytesize,
        })
    }
}

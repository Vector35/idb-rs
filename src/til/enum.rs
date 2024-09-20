use crate::til::section::TILSectionHeader;
use crate::til::{
    associate_field_name_and_member, flag, read_de, read_dt, read_dt_de, Type, TypeAttribute,
    TypeRaw, SDACL, TAH,
};
use anyhow::{anyhow, Context};
use std::io::BufRead;

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
        members: Vec<(Option<String>, u64)>,
        bytesize: u64,
    },
}
impl Enum {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: EnumRaw,
        fields: Option<Vec<String>>,
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
        bytesize: u64,
    },
}

impl EnumRaw {
    pub(crate) fn read<I: BufRead>(
        input: &mut I,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Self> {
        let Some(n) = read_dt_de(&mut *input)? else {
            // is ref
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
        let bytesize: u32 = match emsize {
            0 if header.size_enum != 0 => header.size_enum.into(),
            0 => return Err(anyhow!("BTE emsize is 0 without header")),
            1..5 => 1u32 << (emsize - 1),
            5..=7 => return Err(anyhow!("BTE emsize with reserved values")),
            _ => unreachable!(),
        };

        let mask: u64 = if bytesize >= 16 {
            // is saturating valid?
            //u64::MAX
            return Err(anyhow!("Bytes size is too big"));
        } else {
            u64::MAX >> (u64::BITS - (bytesize * 8))
        };

        let mut group_sizes = vec![];
        let mut members = vec![];
        for _ in 0..n {
            let lo: u64 = read_de(&mut *input)?.into();
            let is_64 = (taenum_bits.0 & 0x0020) != 0;
            let step = if is_64 {
                let hi: u64 = read_de(&mut *input)?.into();
                (lo | (hi << 32)) & mask
            } else {
                lo & mask
            };
            // TODO: subarrays
            // https://www.hex-rays.com/products/ida/support/sdkdoc/group__tf__enum.html#ga9ae7aa54dbc597ec17cbb17555306a02
            if (bte & flag::tf_enum::BTE_BITFIELD) != 0 {
                let group_size = read_dt(&mut *input)?;
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
            bytesize: bytesize.into(),
        })
    }
}

use anyhow::{anyhow, Context, Result};

use std::collections::HashMap;
use std::num::{NonZeroU16, NonZeroU8};

use crate::ida_reader::IdbBufRead;
use crate::til::{Type, TypeRaw};
use crate::IDBString;

use super::section::TILSectionHeader;
use super::{CommentType, TypeAttribute, TypeVariantRaw};

#[derive(Clone, Debug)]
pub struct Union {
    pub effective_alignment: Option<NonZeroU16>,
    pub alignment: Option<NonZeroU8>,
    pub members: Vec<UnionMember>,

    pub is_unaligned: bool,
    pub is_unknown_8: bool,
}
impl Union {
    pub(crate) fn new(
        til: &TILSectionHeader,
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        value: UnionRaw,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
    ) -> Result<Self> {
        let members = value
            .members
            .into_iter()
            .map(|member| {
                let comment = comments.next().flatten();
                let name = fields.next().flatten();
                let ty = Type::new(
                    til,
                    type_by_name,
                    type_by_ord,
                    member,
                    fields,
                    None,
                    &mut *comments,
                )?;
                Ok(UnionMember { name, comment, ty })
            })
            .collect::<Result<_>>()?;
        Ok(Union {
            effective_alignment: value.effective_alignment,
            alignment: value.alignment,
            members,
            is_unaligned: value.is_unaligned,
            is_unknown_8: value.is_unknown_8,
        })
    }
}

#[derive(Clone, Debug)]
pub struct UnionMember {
    pub name: Option<IDBString>,
    pub comment: Option<CommentType>,
    pub ty: Type,
}

// TODO struct and union are basically identical, the diff is that member in union don't have SDACL,
// merge both
#[derive(Clone, Debug)]
pub(crate) struct UnionRaw {
    effective_alignment: Option<NonZeroU16>,
    alignment: Option<NonZeroU8>,
    members: Vec<TypeRaw>,
    is_unaligned: bool,
    is_unknown_8: bool,
}

impl UnionRaw {
    pub fn read(
        input: &mut impl IdbBufRead,
        header: &TILSectionHeader,
    ) -> Result<TypeVariantRaw> {
        // TODO n == 0 && n_cond == false?
        // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x325f87
        let Some((n, _)) = input.read_dt_de()? else {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // is ref
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let _taudt_bits = input.read_sdacl()?;
            let TypeVariantRaw::Typedef(ref_type) = ref_type.variant else {
                return Err(anyhow!("UnionRef Non Typedef"));
            };
            return Ok(TypeVariantRaw::UnionRef(ref_type));
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
        let alpow = n & 7;
        let mem_cnt = n >> 3;
        let effective_alignment =
            NonZeroU16::new(if alpow == 0 { 0 } else { 1 << (alpow - 1) });

        let mut alignment = None;
        let mut is_unaligned = false;
        let mut is_unknown_8 = false;
        if let Some(TypeAttribute {
            tattr,
            extended: _extended,
        }) = input.read_sdacl()?
        {
            use crate::til::flag::tattr::*;
            use crate::til::flag::tattr_udt::*;

            let alignment_raw = (tattr & MAX_DECL_ALIGN) as u8;
            is_unknown_8 = alignment_raw & 0x8 != 0;
            alignment = ((alignment_raw & 0x7) != 0).then(|| {
                NonZeroU8::new(1 << ((alignment_raw & 0x7) - 1)).unwrap()
            });
            is_unaligned = tattr & TAUDT_UNALIGNED != 0;

            const _ALL_FLAGS: u16 = MAX_DECL_ALIGN | TAUDT_UNALIGNED;
            #[cfg(feature = "restrictive")]
            anyhow::ensure!(
                tattr & !_ALL_FLAGS == 0,
                "Invalid Union taenum_bits {tattr:x}"
            );
            #[cfg(feature = "restrictive")]
            anyhow::ensure!(
                _extended.is_none(),
                "Unable to parse extended attributes for union"
            );
        }

        let members = (0..mem_cnt)
            .map(|i| {
                TypeRaw::read(&mut *input, header)
                    .with_context(|| format!("Member {i}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(TypeVariantRaw::Union(Self {
            effective_alignment,
            alignment,
            members,
            is_unaligned,
            is_unknown_8,
        }))
    }
}

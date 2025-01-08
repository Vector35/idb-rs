use anyhow::{anyhow, ensure, Context};

use std::num::NonZeroU8;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw};

use super::{TypeAttribute, TypeVariantRaw};

#[derive(Clone, Debug)]
pub struct Union {
    pub effective_alignment: u16,
    pub alignment: Option<NonZeroU8>,
    pub members: Vec<(Option<Vec<u8>>, Type)>,

    pub is_unaligned: bool,
}
impl Union {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: UnionRaw,
        fields: &mut impl Iterator<Item = Option<Vec<u8>>>,
    ) -> anyhow::Result<Self> {
        let members = value
            .members
            .into_iter()
            .map(|member| {
                let field_name = fields.next().flatten();
                let new_member = Type::new(til, member, &mut *fields)?;
                Ok((field_name, new_member))
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Union {
            effective_alignment: value.effective_alignment,
            alignment: value.alignment,
            members,
            is_unaligned: value.is_unaligned,
        })
    }
}

// TODO struct and union are basically identical, the diff is that member in union don't have SDACL,
// merge both
#[derive(Clone, Debug)]
pub(crate) struct UnionRaw {
    effective_alignment: u16,
    alignment: Option<NonZeroU8>,
    members: Vec<TypeRaw>,
    is_unaligned: bool,
}

impl UnionRaw {
    pub fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<TypeVariantRaw> {
        let Some(n) = input.read_dt_de()? else {
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
        let effective_alignment = if alpow == 0 { 0 } else { 1 << (alpow - 1) };

        let mut alignment = None;
        let mut is_unaligned = false;
        if let Some(TypeAttribute { tattr, extended }) = input.read_sdacl()? {
            use crate::til::flag::tattr::*;
            use crate::til::flag::tattr_udt::*;

            alignment = NonZeroU8::new((tattr & MAX_DECL_ALIGN) as u8);
            is_unaligned = tattr & TAUDT_UNALIGNED != 0;

            const ALL_FLAGS: u16 = MAX_DECL_ALIGN | TAUDT_UNALIGNED;
            ensure!(
                tattr & !ALL_FLAGS == 0,
                "Invalid Union taenum_bits {tattr:x}"
            );
            ensure!(
                extended.is_none(),
                "Unable to parse extended attributes for union"
            );
        }

        let members = (0..mem_cnt)
            .map(|i| TypeRaw::read(&mut *input, header).with_context(|| format!("Member {i}")))
            .collect::<anyhow::Result<_, _>>()?;
        Ok(TypeVariantRaw::Union(Self {
            effective_alignment,
            alignment,
            members,
            is_unaligned,
        }))
    }
}

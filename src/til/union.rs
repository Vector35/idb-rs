use anyhow::{anyhow, Context};

use std::num::NonZeroU8;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw};

use super::{StructModifierRaw, TypeVariantRaw};

#[derive(Clone, Debug)]
pub struct Union {
    pub effective_alignment: u16,
    pub alignment: Option<NonZeroU8>,
    pub members: Vec<(Option<Vec<u8>>, Type)>,
    // TODO parse type attributes
    //others: StructMemberRaw,
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
        let taudt_bits = input.read_sdacl()?;
        // TODO handle ext atts
        let taudt_bits = taudt_bits.as_ref().map(|x| x.tattr).unwrap_or(0);
        let modifiers = StructModifierRaw::from_value(taudt_bits);
        // TODO check InnerRef to how to handle modifiers
        let alignment = modifiers.alignment;
        let members = (0..mem_cnt)
            .map(|i| TypeRaw::read(&mut *input, header).with_context(|| format!("Member {i}")))
            .collect::<anyhow::Result<_, _>>()?;
        Ok(TypeVariantRaw::Union(Self {
            effective_alignment,
            alignment,
            members,
        }))
    }
}

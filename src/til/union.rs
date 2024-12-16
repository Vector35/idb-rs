use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{associate_field_name_and_member, Type, TypeRaw, SDACL};
use anyhow::{anyhow, Context};

use super::r#struct::StructModifier;

#[derive(Clone, Debug)]
pub enum Union {
    Ref {
        ref_type: Box<Type>,
        taudt_bits: SDACL,
    },
    NonRef {
        effective_alignment: u16,
        modifiers: Vec<StructModifier>,
        members: Vec<(Option<Vec<u8>>, Type)>,
    },
}
impl Union {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: UnionRaw,
        fields: Option<Vec<Vec<u8>>>,
    ) -> anyhow::Result<Self> {
        match value {
            UnionRaw::Ref {
                ref_type,
                taudt_bits,
            } => {
                if matches!(fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Ref Union"));
                }
                Ok(Union::Ref {
                    ref_type: Type::new(til, *ref_type, None).map(Box::new)?,
                    taudt_bits,
                })
            }
            UnionRaw::NonRef {
                effective_alignment,
                modifiers,
                members,
            } => {
                let members = associate_field_name_and_member(fields, members)
                    .context("Union")?
                    .map(|(n, m)| Type::new(til, m, None).map(|m| (n, m)))
                    .collect::<anyhow::Result<_, _>>()?;
                Ok(Union::NonRef {
                    effective_alignment,
                    modifiers,
                    members,
                })
            }
        }
    }
}

// TODO struct and union are basically identical, the diff is that member in union don't have SDACL,
// merge both
#[derive(Clone, Debug)]
pub(crate) enum UnionRaw {
    Ref {
        ref_type: Box<TypeRaw>,
        taudt_bits: SDACL,
    },
    NonRef {
        effective_alignment: u16,
        modifiers: Vec<StructModifier>,
        members: Vec<TypeRaw>,
    },
}

impl UnionRaw {
    pub fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Self> {
        let Some(n) = input.read_dt_de()? else {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // is ref
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let taudt_bits = SDACL::read(&mut *input)?;
            return Ok(Self::Ref {
                ref_type: Box::new(ref_type),
                taudt_bits,
            });
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
        let alpow = n & 7;
        let mem_cnt = n >> 3;
        let effective_alignment = if alpow == 0 { 0 } else { 1 << (alpow - 1) };
        let taudt_bits = SDACL::read(&mut *input)?;
        let modifiers = StructModifier::from_value(taudt_bits.0 .0);
        let members = (0..mem_cnt)
            .map(|_| TypeRaw::read(&mut *input, header))
            .collect::<anyhow::Result<_, _>>()?;
        Ok(Self::NonRef {
            effective_alignment,
            modifiers,
            members,
        })
    }
}

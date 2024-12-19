use std::num::NonZeroU8;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw, SDACL};

use super::StructModifierRaw;

#[derive(Clone, Debug)]
pub enum Union {
    Ref {
        ref_type: Box<Type>,
        taudt_bits: SDACL,
    },
    NonRef {
        effective_alignment: u16,
        alignment: Option<NonZeroU8>,
        members: Vec<(Option<Vec<u8>>, Type)>,
        // TODO parse type attributes
        //others: StructMemberRaw,
    },
}
impl Union {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: UnionRaw,
        fields: &mut impl Iterator<Item = Vec<u8>>,
    ) -> anyhow::Result<Self> {
        match value {
            UnionRaw::Ref {
                ref_type,
                taudt_bits,
            } => Ok(Union::Ref {
                ref_type: Type::new(til, *ref_type, fields).map(Box::new)?,
                taudt_bits,
            }),
            UnionRaw::NonRef {
                effective_alignment,
                alignment,
                members,
            } => {
                let mut new_members = Vec::with_capacity(members.len());
                for member in members {
                    let field = fields.next();
                    let new_member = Type::new(til, member, &mut *fields)?;
                    new_members.push((field, new_member));
                }
                Ok(Union::NonRef {
                    effective_alignment,
                    alignment,
                    members: new_members,
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
        alignment: Option<NonZeroU8>,
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
        let modifiers = StructModifierRaw::from_value(taudt_bits.0 .0);
        // TODO check InnerRef to how to handle modifiers
        let alignment = modifiers.alignment;
        let members = (0..mem_cnt)
            .map(|_| TypeRaw::read(&mut *input, header))
            .collect::<anyhow::Result<_, _>>()?;
        Ok(Self::NonRef {
            effective_alignment,
            alignment,
            members,
        })
    }
}

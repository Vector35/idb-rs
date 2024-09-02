use crate::til::section::TILSectionHeader;
use crate::til::{associate_field_name_and_member, read_dt_de, Type, TypeRaw, SDACL};
use anyhow::{anyhow, Context};
use std::io::BufRead;

#[derive(Clone, Debug)]
pub enum Union {
    Ref {
        ref_type: Box<Type>,
        taudt_bits: SDACL,
    },
    NonRef {
        taudt_bits: SDACL,
        effective_alignment: u16,
        members: Vec<(Option<String>, Type)>,
    },
}
impl Union {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: UnionRaw,
        fields: Option<Vec<String>>,
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
                taudt_bits,
                effective_alignment,
                members,
            } => {
                let members = associate_field_name_and_member(fields, members)
                    .context("Union")?
                    .map(|(n, m)| Type::new(til, m, None).map(|m| (n, m)))
                    .collect::<anyhow::Result<_, _>>()?;
                Ok(Union::NonRef {
                    taudt_bits,
                    effective_alignment,
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
        taudt_bits: SDACL,
        effective_alignment: u16,
        members: Vec<TypeRaw>,
    },
}

impl UnionRaw {
    pub fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> anyhow::Result<Self> {
        let Some(n) = read_dt_de(&mut *input)? else {
            // is ref
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let taudt_bits = SDACL::read(&mut *input)?;
            return Ok(Self::Ref {
                ref_type: Box::new(ref_type),
                taudt_bits,
            });
        };
        let alpow = n & 7;
        let mem_cnt = n >> 3;
        let effective_alignment = if alpow == 0 { 0 } else { 1 << (alpow - 1) };
        let taudt_bits = SDACL::read(&mut *input)?;
        let members = (0..mem_cnt)
            .map(|_| TypeRaw::read(&mut *input, header))
            .collect::<anyhow::Result<_, _>>()?;
        Ok(Self::NonRef {
            effective_alignment,
            taudt_bits,
            members,
        })
    }
}

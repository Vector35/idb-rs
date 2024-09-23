use crate::til::section::TILSectionHeader;
use crate::til::{associate_field_name_and_member, read_dt_de, Type, TypeRaw, SDACL};
use anyhow::{anyhow, Context};
use std::io::BufRead;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub enum Struct {
    Ref {
        ref_type: Box<Type>,
        taudt_bits: SDACL,
    },
    NonRef {
        effective_alignment: u16,
        taudt_bits: SDACL,
        members: Vec<StructMember>,
    },
}
impl Struct {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: StructRaw,
        fields: Option<Vec<String>>,
    ) -> anyhow::Result<Self> {
        match value {
            StructRaw::Ref {
                ref_type,
                taudt_bits,
            } => {
                if matches!(&fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Ref Struct"));
                }
                Ok(Struct::Ref {
                    ref_type: Type::new(til, *ref_type, None).map(Box::new)?,
                    taudt_bits,
                })
            }
            StructRaw::NonRef {
                effective_alignment,
                taudt_bits,
                members,
            } => {
                let members = associate_field_name_and_member(fields, members)
                    .context("Struct")?
                    .map(|(n, m)| StructMember::new(til, n, m))
                    .collect::<anyhow::Result<_, _>>()?;
                Ok(Struct::NonRef {
                    effective_alignment,
                    taudt_bits,
                    members,
                })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum StructRaw {
    Ref {
        ref_type: Box<TypeRaw>,
        taudt_bits: SDACL,
    },
    NonRef {
        effective_alignment: u16,
        taudt_bits: SDACL,
        members: Vec<StructMemberRaw>,
    },
}

impl StructRaw {
    pub fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> anyhow::Result<Self> {
        let Some(n) = read_dt_de(&mut *input)? else {
            // simple reference
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
            .map(|_| StructMemberRaw::read(&mut *input, header))
            .collect::<anyhow::Result<_, _>>()?;
        Ok(Self::NonRef {
            effective_alignment,
            taudt_bits,
            members,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StructMember {
    pub name: Option<String>,
    pub member_type: Type,
    pub sdacl: SDACL,
}

impl StructMember {
    fn new(
        til: &TILSectionHeader,
        name: Option<String>,
        m: StructMemberRaw,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            name,
            member_type: Type::new(til, m.0, None)?,
            sdacl: m.1,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct StructMemberRaw(pub TypeRaw, pub SDACL);

impl StructMemberRaw {
    fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> anyhow::Result<Self> {
        let member_type = TypeRaw::read(&mut *input, header)?;
        let sdacl = SDACL::read(&mut *input)?;
        Ok(Self(member_type, sdacl))
    }
}

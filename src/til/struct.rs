use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{associate_field_name_and_member, Type, TypeRaw, SDACL};
use anyhow::{anyhow, Context, Result};

#[derive(Clone, Debug)]
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
        fields: Option<Vec<Vec<u8>>>,
    ) -> Result<Self> {
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
    pub fn read(input: &mut impl IdaGenericBufUnpack, header: &TILSectionHeader) -> Result<Self> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459883
        let Some(n) = input.read_dt_de()? else {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // simple reference
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
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459c97
        let taudt_bits = SDACL::read(&mut *input)?;
        let members = (0..mem_cnt)
            .map(|_| StructMemberRaw::read(&mut *input, header, taudt_bits.0 .0))
            .collect::<Result<_, _>>()?;
        Ok(Self::NonRef {
            effective_alignment,
            taudt_bits,
            members,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StructMember {
    pub name: Option<Vec<u8>>,
    pub member_type: Type,
    pub sdacl: SDACL,
}

impl StructMember {
    fn new(til: &TILSectionHeader, name: Option<Vec<u8>>, m: StructMemberRaw) -> Result<Self> {
        Ok(Self {
            name,
            member_type: Type::new(til, m.ty, None)?,
            sdacl: m.sdacl,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct StructMemberRaw {
    pub ty: TypeRaw,
    pub sdacl: SDACL,
}

impl StructMemberRaw {
    fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        taudt_bits: u16,
    ) -> Result<Self> {
        let ty = TypeRaw::read(&mut *input, header)?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478203
        let is_bit_set = taudt_bits & 0x200 != 0;

        let mut att1 = None;
        if is_bit_set {
            att1 = Self::read_member_att_1(input, header)?;
        }

        //// InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47825d
        let mut sdacl = SDACL(crate::til::TypeAttribute(0));
        if !is_bit_set || matches!(att1, Some(_att1)) {
            sdacl = SDACL::read(&mut *input)?;
            // TODO there is more to this impl
            //todo!();
        }

        Ok(Self { ty, sdacl })
    }

    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486cd0
    fn read_member_att_1(
        input: &mut impl IdaGenericBufUnpack,
        _header: &TILSectionHeader,
    ) -> Result<Option<u64>> {
        let Some(att) = input.read_ext_att()? else {
            return Ok(None);
        };
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486d0d
        match att & 0xf {
            0xd..=0xf => return Err(anyhow!("Invalid value for member attribute {att:#x}")),
            0..=7 => Self::basic_att(input, att),
            8 | 0xb => todo!(),
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486d3f
            9 => {
                let val1 = input.read_de()?;
                if val1 & 0x1010 == 0 {
                    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486f8d
                    let _att = input
                        .read_ext_att()?
                        .ok_or_else(|| anyhow!("Unable to read att of type 9"))?;
                }

                let _att1 = input
                    .read_ext_att()?
                    .ok_or_else(|| anyhow!("Unable to read att of type 9"))?;
                let _att2 = input
                    .read_ext_att()?
                    .ok_or_else(|| anyhow!("Unable to read att of type 9"))?;
                // TODO find this value
                Ok(Some(_att2))
            }
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486e50
            0xa | 0xc => {
                let _val1 = input.read_de()?;
                Self::basic_att(input, att)
            }
            0x10.. => unreachable!(),
        }
    }

    fn basic_att(input: &mut impl IdaGenericBufUnpack, att: u64) -> Result<Option<u64>> {
        if att & 0x10 != 0 {
            // TODO this is diferent from the implementation, double check the read_de and this code
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486df0
            let _val1 = input.read_de()?;
            //let _val2 = input.read_de()?;
            //let _val3 = input.read_de()?;
            Ok(Some(att))
        } else {
            Ok(Some(att))
        }
    }
}

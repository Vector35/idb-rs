use std::num::{NonZeroU16, NonZeroU8};

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw, SDACL};
use anyhow::{anyhow, Result};

use super::{StructModifierRaw, TypeVariantRaw};

#[derive(Clone, Debug)]
pub struct Struct {
    pub effective_alignment: Option<NonZeroU8>,
    pub members: Vec<StructMember>,
    /// Unaligned struct
    pub is_unaligned: bool,
    /// Gcc msstruct attribute
    pub is_msstruct: bool,
    /// C++ object, not simple pod type
    pub is_cpp_obj: bool,
    /// Virtual function table
    pub is_vftable: bool,
    /// Alignment in bytes
    pub alignment: Option<NonZeroU8>,
    // TODO delete others, parse all values or return an error
    /// other unparsed values from the type attribute
    pub others: Option<NonZeroU16>,
}
impl Struct {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: StructRaw,
        fields: &mut impl Iterator<Item = Vec<u8>>,
    ) -> Result<Self> {
        let members = value
            .members
            .into_iter()
            .map(|member| StructMember::new(til, fields.next(), member, &mut *fields))
            .collect::<Result<_>>()?;
        Ok(Struct {
            effective_alignment: value.effective_alignment,
            members,
            is_unaligned: value.modifier.is_unaligned,
            is_msstruct: value.modifier.is_msstruct,
            is_cpp_obj: value.modifier.is_cpp_obj,
            is_vftable: value.modifier.is_vftable,
            alignment: value.modifier.alignment,
            others: value.modifier.others,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StructRaw {
    effective_alignment: Option<NonZeroU8>,
    modifier: StructModifierRaw,
    members: Vec<StructMemberRaw>,
}

impl StructRaw {
    pub fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> Result<TypeVariantRaw> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459883
        let Some(n) = input.read_dt_de()? else {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // simple reference
            let ref_type = TypeRaw::read_ref(&mut *input, header)?;
            let _taudt_bits = SDACL::read(&mut *input)?;
            return Ok(TypeVariantRaw::StructRef(Box::new(ref_type)));
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
        let mem_cnt = n >> 3;
        // TODO what is effective_alignment and how it's diferent from Modifier alignment?
        let alpow = n & 7;
        let effective_alignment = (alpow != 0).then(|| NonZeroU8::new(1 << (alpow - 1)).unwrap());
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459c97
        let taudt_bits = SDACL::read(&mut *input)?;
        let members = (0..mem_cnt)
            .map(|_| StructMemberRaw::read(&mut *input, header, taudt_bits.0 .0))
            .collect::<Result<_, _>>()?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x46c4fc print_til_types_att
        let modifier = StructModifierRaw::from_value(taudt_bits.0 .0);
        Ok(TypeVariantRaw::Struct(Self {
            effective_alignment,
            modifier,
            members,
        }))
    }
}

#[derive(Clone, Debug)]
pub struct StructMember {
    pub name: Option<Vec<u8>>,
    pub member_type: Type,
    pub sdacl: SDACL,
}

impl StructMember {
    fn new(
        til: &TILSectionHeader,
        name: Option<Vec<u8>>,
        m: StructMemberRaw,
        fields: &mut impl Iterator<Item = Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            name,
            member_type: Type::new(til, m.ty, fields)?,
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
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478256
            att1 = Self::read_member_att_1(input, header)?;
        }

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47825d
        let mut sdacl = SDACL(crate::til::TypeAttribute(0));
        if !is_bit_set || matches!(att1, Some(_att1)) {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47825d
            sdacl = SDACL::read(&mut *input)?;
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47822d
            if taudt_bits & 4 != 0 && sdacl.0 .0 & 0x200 == 0 {
                // TODO there is more to this impl?
                // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478411
                // todo!();
            }
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
            0xd..=0xf => Err(anyhow!("Invalid value for member attribute {att:#x}")),
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
        if (att >> 8) & 0x10 != 0 {
            // TODO this is diferent from the implementation, double check the read_de and this code
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x486df0
            let _val1 = input.read_de()?;
            let _val2 = input.read_de()?;
            let _val3 = input.read_de()?;
            Ok(Some(att))
        } else {
            Ok(Some(att))
        }
    }
}

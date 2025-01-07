use anyhow::Result;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw, TAH};

#[derive(Debug, Clone)]
pub struct Pointer {
    pub closure: PointerType,
    pub typ: Box<Type>,
    pub shifted: Option<(Box<Type>, u32)>,
    pub is_ptr32: bool,
    pub is_ptr64: bool,
    pub is_restricted: bool,
    pub is_unknown_ta10: bool,
    pub ta_lower: u8,
}

impl Pointer {
    pub(crate) fn new(
        til: &TILSectionHeader,
        raw: PointerRaw,
        fields: &mut impl Iterator<Item = Option<Vec<u8>>>,
    ) -> Result<Self> {
        let shifted = raw
            .shifted
            .map(|(t, v)| -> Result<_> {
                Ok((
                    // TODO if this type allow non typedef, this may consume fields
                    Type::new(til, *t, &mut vec![].into_iter()).map(Box::new)?,
                    v,
                ))
            })
            .transpose()?;
        let typ = Type::new(til, *raw.typ, fields).map(Box::new)?;
        Ok(Self {
            // TODO forward fields to closure?
            closure: PointerType::new(til, raw.closure)?,
            typ,
            shifted,
            is_ptr32: raw.is_ptr32,
            is_ptr64: raw.is_ptr64,
            is_restricted: raw.is_restricted,
            is_unknown_ta10: raw.is_unknown_ta10,
            ta_lower: raw.ta_lower,
        })
    }
}

#[derive(Debug, Clone)]
pub enum PointerType {
    Closure(Box<Type>),
    PointerBased(u8),
    Default,
    Far,
    Near,
}

impl PointerType {
    fn new(til: &TILSectionHeader, raw: PointerTypeRaw) -> Result<Self> {
        match raw {
            PointerTypeRaw::Closure(c) => {
                // TODO subtype get the fields?
                let mut sub_fields = vec![].into_iter();
                Type::new(til, *c, &mut sub_fields)
                    .map(Box::new)
                    .map(Self::Closure)
            }
            PointerTypeRaw::PointerBased(p) => Ok(Self::PointerBased(p)),
            PointerTypeRaw::Default => Ok(Self::Default),
            PointerTypeRaw::Far => Ok(Self::Far),
            PointerTypeRaw::Near => Ok(Self::Near),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PointerRaw {
    pub closure: PointerTypeRaw,
    pub typ: Box<TypeRaw>,
    pub is_ptr32: bool,
    pub is_ptr64: bool,
    pub is_restricted: bool,
    pub is_unknown_ta10: bool,
    pub shifted: Option<(Box<TypeRaw>, u32)>,
    pub ta_lower: u8,
}

impl PointerRaw {
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        metadata: u8,
    ) -> Result<Self> {
        use crate::til::flag::tattr_ptr::*;
        use crate::til::flag::tf_ptr::*;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x478d67
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459b54
        let closure = match metadata {
            BTMT_DEFPTR => PointerTypeRaw::Default,
            BTMT_CLOSURE => PointerTypeRaw::read(&mut *input, header)?,
            // TODO find the meaning of this
            BTMT_FAR => PointerTypeRaw::Far,
            BTMT_NEAR => PointerTypeRaw::Near,
            _ => unreachable!(),
        };
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4804fa
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459b7e
        let tah = TAH::read(&mut *input)?;
        let typ = TypeRaw::read(&mut *input, header)?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459bc6
        let shifted = (tah.0 .0 & TAPTR_SHIFTED != 0)
            .then(|| -> Result<_> {
                // TODO allow typedef only?
                // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459bc6 print_til_type_att
                let typ = TypeRaw::read(&mut *input, header)?;
                let value = input.read_de()?;
                Ok((Box::new(typ), value))
            })
            .transpose()?;
        let is_ptr32 = tah.0 .0 & TAPTR_PTR32 != 0;
        let is_ptr64 = tah.0 .0 & TAPTR_PTR64 != 0;
        let is_restricted = tah.0 .0 & TAPTR_RESTRICT != 0;
        // TODO find the flag or doc for this
        let is_unknown_ta10 = tah.0 .0 & 0x10 != 0;
        let ta_lower = (tah.0 .0 & 0xf) as u8;

        Ok(Self {
            closure,
            typ: Box::new(typ),
            shifted,
            is_ptr32,
            is_ptr64,
            is_restricted,
            is_unknown_ta10,
            ta_lower,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PointerTypeRaw {
    Closure(Box<TypeRaw>),
    // ptr size: {0}
    PointerBased(u8),
    Default,
    Far,
    Near,
}

impl PointerTypeRaw {
    fn read(input: &mut impl IdaGenericBufUnpack, header: &TILSectionHeader) -> Result<Self> {
        let closure_type = input.read_u8()?;
        if closure_type == 0xFF {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473b5a
            let closure = TypeRaw::read(&mut *input, header)?;
            Ok(Self::Closure(Box::new(closure)))
        } else {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4739f6
            let closure_ptr = input.read_u8()?;
            Ok(Self::PointerBased(closure_ptr))
        }
    }
}

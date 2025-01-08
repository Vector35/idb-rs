use anyhow::Result;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw};

#[derive(Debug, Clone)]
pub struct Pointer {
    pub closure: PointerType,
    pub modifier: Option<PointerModifier>,
    pub shifted: Option<(Box<Type>, u32)>,
    pub typ: Box<Type>,
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
            modifier: raw.modifier,
            shifted,
            typ,
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

#[derive(Debug, Clone, Copy)]
pub enum PointerModifier {
    Ptr32,
    Ptr64,
    Restricted,
}

#[derive(Debug, Clone)]
pub(crate) struct PointerRaw {
    pub closure: PointerTypeRaw,
    pub modifier: Option<PointerModifier>,
    pub shifted: Option<(Box<TypeRaw>, u32)>,
    pub typ: Box<TypeRaw>,
    pub is_unknown_ta10: bool,
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
        let tah = input.read_tah()?;
        // TODO handle ext att
        let tah = tah.map(|x| x.tattr).unwrap_or(0);
        let typ = TypeRaw::read(&mut *input, header)?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459bc6
        let shifted = (tah & TAPTR_SHIFTED != 0)
            .then(|| -> Result<_> {
                // TODO allow typedef only?
                let typ = TypeRaw::read(&mut *input, header)?;
                let value = input.read_de()?;
                Ok((Box::new(typ), value))
            })
            .transpose()?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459bc6 print_til_type_att
        let modifier = match tah & TAPTR_RESTRICT {
            0x00 => None,
            TAPTR_PTR32 => Some(PointerModifier::Ptr32),
            TAPTR_PTR64 => Some(PointerModifier::Ptr64),
            TAPTR_RESTRICT => Some(PointerModifier::Restricted),
            _ => unreachable!(),
        };
        // TODO find menaing: commonly set as true
        let is_unknown_ta10 = tah & 0x10 != 0;
        // TODO find meaning: normally 5 in one type at `vc10_64` and `ntddk64`
        let ta_lower = (tah & 0xf) as u8;

        Ok(Self {
            closure,
            modifier,
            shifted,
            typ: Box::new(typ),
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

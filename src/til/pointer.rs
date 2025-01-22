use std::collections::HashMap;

use anyhow::Result;

use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::{Type, TypeAttribute, TypeRaw};
use crate::IDBString;

use super::section::TILSectionHeader;
use super::CommentType;

#[derive(Debug, Clone)]
pub struct Pointer {
    pub closure: PointerType,
    pub modifier: Option<PointerModifier>,
    pub shifted: Option<(Box<Type>, u32)>,
    pub typ: Box<Type>,
}

impl Pointer {
    pub(crate) fn new(
        til: &TILSectionHeader,
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        raw: PointerRaw,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
    ) -> Result<Self> {
        let shifted = raw
            .shifted
            .map(|(t, v)| -> Result<_> {
                Ok((
                    // TODO if this type allow non typedef, this may consume fields
                    Type::new(
                        til,
                        type_by_name,
                        type_by_ord,
                        *t,
                        &mut vec![].into_iter(),
                        None,
                        &mut vec![].into_iter(),
                    )
                    .map(Box::new)?,
                    v,
                ))
            })
            .transpose()?;
        let typ = Type::new(
            til,
            type_by_name,
            type_by_ord,
            *raw.typ,
            fields,
            None,
            comments,
        )
        .map(Box::new)?;
        Ok(Self {
            // TODO forward fields to closure?
            closure: PointerType::new(
                til,
                type_by_name,
                type_by_ord,
                raw.closure,
            )?,
            modifier: raw.modifier,
            shifted,
            typ,
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
    fn new(
        til: &TILSectionHeader,
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        raw: PointerTypeRaw,
    ) -> Result<Self> {
        match raw {
            PointerTypeRaw::Closure(c) => {
                // TODO subtype get the fields?
                let mut sub_fields = vec![].into_iter();
                let mut sub_comments = vec![].into_iter();
                Type::new(
                    til,
                    type_by_name,
                    type_by_ord,
                    *c,
                    &mut sub_fields,
                    None,
                    &mut sub_comments,
                )
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
    // TODO find meaning: normally 5 in one type at `vc10_64` and `ntddk64`
    pub _ta_lower: u8,
}

impl PointerRaw {
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        metadata: u8,
    ) -> Result<Self> {
        use crate::til::flag::tattr::*;
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
        let (_ta_lower, is_shifted, ptr_type_raw) = match input.read_tah()? {
            None => (0, false, 0),
            Some(TypeAttribute {
                tattr,
                extended: _extended,
            }) => {
                // all bits of tattr are consumed
                let ta_lower = (tattr & MAX_DECL_ALIGN) as u8;
                let is_shifted = tattr & TAPTR_SHIFTED != 0;
                let ptr_type = tattr & TAPTR_RESTRICT;
                #[cfg(feature = "restrictive")]
                anyhow::ensure!(
                    tattr & !(TAPTR_SHIFTED | TAPTR_RESTRICT | MAX_DECL_ALIGN)
                        == 0,
                    "Invalid Pointer taenum_bits {tattr:x}"
                );
                if let Some(_extended) = _extended {
                    // TODO parse extended values, known:
                    // "__org_arrdim" :"\xac\xXX"
                    // "__org_typedef":...,
                    // "__argz_create":"\xac\xac"
                }
                (ta_lower, is_shifted, ptr_type)
            }
        };

        let typ = TypeRaw::read(&mut *input, header)?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459bc6
        let shifted = is_shifted
            .then(|| -> Result<_> {
                // TODO allow typedef only?
                let typ = TypeRaw::read(&mut *input, header)?;
                let value = input.read_de()?;
                Ok((Box::new(typ), value))
            })
            .transpose()?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x459bc6 print_til_type_att
        let modifier = match ptr_type_raw {
            0x00 => None,
            TAPTR_PTR32 => Some(PointerModifier::Ptr32),
            TAPTR_PTR64 => Some(PointerModifier::Ptr64),
            TAPTR_RESTRICT => Some(PointerModifier::Restricted),
            _ => unreachable!(),
        };

        Ok(Self {
            closure,
            modifier,
            shifted,
            typ: Box::new(typ),
            _ta_lower,
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
    fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> Result<Self> {
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

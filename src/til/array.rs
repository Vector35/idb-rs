use std::num::{NonZeroU16, NonZeroU8};

use serde::Serialize;

use crate::ida_reader::IdbBufRead;
use crate::til::{CommentType, Type, TypeAttribute};
use crate::IDBString;

use super::section::TILSectionHeader;

#[derive(Clone, Debug, Serialize)]
pub struct Array {
    pub alignment: Option<NonZeroU8>,
    pub base: u8,
    pub nelem: Option<NonZeroU16>,
    pub elem_type: Box<Type>,
}
impl Array {
    pub(crate) fn read(
        input: &mut impl IdbBufRead,
        header: &TILSectionHeader,
        metadata: u8,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
    ) -> anyhow::Result<Self> {
        use crate::til::flag::tattr::*;
        use crate::til::flag::tf_array::*;
        let (base, nelem) = match metadata {
            BTMT_NONBASED => {
                let nelem = input.read_dt()?;
                (0, nelem)
            }
            // I think is only for zero, but documentation says anything other than BTMT_NONBASED
            _ => {
                let (base, nelem) = input.read_da()?;
                (base, nelem.into())
            }
        };
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48078e
        let mut alignment = None;
        if let Some(Some(TypeAttribute {
            tattr,
            extended: _extended,
        })) = input.read_tah()?
        {
            let alignment_raw = (tattr & MAX_DECL_ALIGN) as u8;
            let _is_unknown_8 = alignment_raw & 0x8 != 0;
            #[cfg(feature = "restrictive")]
            anyhow::ensure!(!_is_unknown_8, "Unknown flat 8 set on Array");
            alignment = ((alignment_raw & 0x7) != 0).then(|| {
                NonZeroU8::new(1 << ((alignment_raw & 0x7) - 1)).unwrap()
            });
            #[cfg(feature = "restrictive")]
            anyhow::ensure!(
                tattr & !MAX_DECL_ALIGN == 0,
                "unknown TypeAttribute {tattr:x}"
            );
            #[cfg(feature = "restrictive")]
            anyhow::ensure!(
                _extended.is_none(),
                "unknown TypeAttribute ext {_extended:x?}"
            );
        }
        let elem_type =
            Type::read(&mut *input, header, None, fields, comments)?;
        Ok(Array {
            base,
            alignment,
            nelem: NonZeroU16::new(nelem),
            elem_type: Box::new(elem_type),
        })
    }
}

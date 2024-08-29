use crate::til::section::TILSectionHeader;
use crate::til::{read_da, read_dt, Type, TypeRaw, TAH};
use anyhow::anyhow;
use std::io::BufRead;

#[derive(Clone, Debug)]
pub struct Array {
    pub base: u8,
    pub nelem: u16,
    pub tah: TAH,
    pub elem_type: Box<Type>,
}
impl Array {
    pub(crate) fn new(til: &TILSectionHeader, value: ArrayRaw, fields: Option<Vec<String>>) -> anyhow::Result<Self> {
        if matches!(&fields, Some(f) if !f.is_empty()) {
            return Err(anyhow!("fields in a Array"));
        }
        Ok(Self {
            base: value.base,
            nelem: value.nelem,
            tah: value.tah,
            elem_type: Type::new(til, *value.elem_type, None).map(Box::new)?,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ArrayRaw {
    pub base: u8,
    pub nelem: u16,
    pub tah: TAH,
    pub elem_type: Box<TypeRaw>,
}

impl ArrayRaw {
    pub(crate) fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader, metadata: u8) -> anyhow::Result<Self> {
        use crate::til::flag::tf_array::*;
        let (base, nelem) = match metadata {
            BTMT_NONBASED => {
                // TODO if num_elem==0 then the array size is unknown
                let nelem = read_dt(&mut *input)?;
                (0, nelem)
            }
            // I think is only for zero, but documentation says anything other than BTMT_NONBASED
            _ => {
                let (base, nelem) = read_da(&mut *input)?;
                (base, nelem.into())
            }
        };
        let tah = TAH::read(&mut *input)?;
        let elem_type = TypeRaw::read(&mut *input, header)?;
        Ok(ArrayRaw {
            base,
            nelem,
            tah,
            elem_type: Box::new(elem_type),
        })
    }
}
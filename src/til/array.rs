use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw, TAH};

#[derive(Clone, Debug)]
pub struct Array {
    pub base: u8,
    // TODO make this Option<NonZeroU16>?
    pub nelem: u16,
    pub tah: TAH,
    pub elem_type: Box<Type>,
}
impl Array {
    pub(crate) fn new(
        til: &TILSectionHeader,
        value: ArrayRaw,
        fields: &mut impl Iterator<Item = Option<Vec<u8>>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            base: value.base,
            nelem: value.nelem,
            tah: value.tah,
            elem_type: Type::new(til, *value.elem_type, fields).map(Box::new)?,
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
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        metadata: u8,
    ) -> anyhow::Result<Self> {
        use crate::til::flag::tf_array::*;
        let (base, nelem) = match metadata {
            BTMT_NONBASED => {
                // TODO if num_elem==0 then the array size is unknown
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

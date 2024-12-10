use crate::ida_reader::IdaGenericBufUnpack;
use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw, TAH};

#[derive(Debug, Clone)]
pub struct Pointer {
    pub closure: PointerType,
    pub tah: TAH,
    pub typ: Box<Type>,
}

impl Pointer {
    pub(crate) fn new(
        til: &TILSectionHeader,
        raw: PointerRaw,
        fields: Option<Vec<Vec<u8>>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            closure: PointerType::new(til, raw.closure)?,
            tah: raw.tah,
            typ: Type::new(til, *raw.typ, fields).map(Box::new)?,
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
    fn new(til: &TILSectionHeader, raw: PointerTypeRaw) -> anyhow::Result<Self> {
        match raw {
            PointerTypeRaw::Closure(c) => Type::new(til, *c, None).map(Box::new).map(Self::Closure),
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
    pub tah: TAH,
    pub typ: Box<TypeRaw>,
}

impl PointerRaw {
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        metadata: u8,
    ) -> anyhow::Result<Self> {
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
        if tah.0 .0 & 0x80 != 0 {
            // TODO __shifted?
            let _typ = TypeRaw::read(&mut *input, header)?;
            let _value = input.read_de()?;
        }
        Ok(Self {
            closure,
            tah,
            typ: Box::new(typ),
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
    ) -> anyhow::Result<Self> {
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

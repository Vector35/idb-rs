use crate::til::section::TILSectionHeader;
use crate::til::{Type, TypeRaw, TAH};
use std::io::BufRead;

#[derive(Debug, Clone)]
pub struct Pointer {
    pub closure: Option<Closure>,
    pub tah: TAH,
    pub typ: Box<Type>,
}

impl Pointer {
    pub(crate) fn new(
        til: &TILSectionHeader,
        raw: PointerRaw,
        fields: Option<Vec<String>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            closure: raw.closure.map(|x| Closure::new(til, x)).transpose()?,
            tah: raw.tah,
            typ: Type::new(til, *raw.typ, fields).map(Box::new)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Closure {
    Closure(Box<Type>),
    PointerBased(u8),
}

impl Closure {
    fn new(til: &TILSectionHeader, raw: ClosureRaw) -> anyhow::Result<Self> {
        match raw {
            ClosureRaw::Closure(c) => Type::new(til, *c, None).map(Box::new).map(Self::Closure),
            ClosureRaw::PointerBased(p) => Ok(Self::PointerBased(p)),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PointerRaw {
    pub closure: Option<ClosureRaw>,
    pub tah: TAH,
    pub typ: Box<TypeRaw>,
}

impl PointerRaw {
    pub(crate) fn read<I: BufRead>(
        input: &mut I,
        header: &TILSectionHeader,
        metadata: u8,
    ) -> anyhow::Result<Self> {
        use crate::til::flag::tf_ptr::*;
        let closure = match metadata {
            BTMT_DEFPTR => None,
            BTMT_CLOSURE => Some(ClosureRaw::read(&mut *input, header)?),
            // TODO find the meaning of this
            BTMT_FAR => None,
            BTMT_NEAR => None,
            _ => unreachable!(),
        };
        let tah = TAH::read(&mut *input)?;
        let typ = TypeRaw::read(&mut *input, header)?;
        Ok(Self {
            closure,
            tah,
            typ: Box::new(typ),
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ClosureRaw {
    Closure(Box<TypeRaw>),
    PointerBased(u8),
}

impl ClosureRaw {
    fn read<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> anyhow::Result<Self> {
        let closure_type: u8 = bincode::deserialize_from(&mut *input)?;
        if closure_type == 0xFF {
            let closure = TypeRaw::read(&mut *input, header)?;
            Ok(Self::Closure(Box::new(closure)))
        } else {
            let closure_ptr = bincode::deserialize_from(&mut *input)?;
            Ok(Self::PointerBased(closure_ptr))
        }
    }
}

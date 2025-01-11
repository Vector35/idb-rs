use std::collections::{HashMap, HashSet};
use std::num::NonZeroU8;

use crate::til::bitfield::Bitfield;

use super::r#enum::Enum;
use super::r#struct::StructMember;
use super::section::TILSection;
use super::union::Union;
use super::{Basic, Type, TypeVariant, Typedef};

pub struct TILTypeSizeSolver<'a> {
    section: &'a TILSection,
    solved: HashMap<usize, u64>,
    // HACK used to avoid infinte lopping during recursive solving
    solving: HashSet<usize>,
}

impl<'a> TILTypeSizeSolver<'a> {
    pub fn new(section: &'a TILSection) -> Self {
        Self {
            section,
            solved: Default::default(),
            solving: Default::default(),
        }
    }

    // TODO make a type for type_idx and symbol_idx, accept both here
    /// NOTE that type_idx need to be specified if not a symbol
    pub fn type_size_bytes(
        &mut self,
        type_idx: Option<usize>,
        ty: &Type,
    ) -> Option<u64> {
        assert!(self.solving.is_empty());
        if let Some(idx) = type_idx {
            // if cached return it
            if let Some(solved) = self.cached(idx) {
                return Some(solved);
            }
            self.solving.insert(idx);
        }
        let result = self.inner_type_size_bytes(ty);
        if let Some(idx) = type_idx {
            assert!(self.solving.remove(&idx));
        }
        assert!(self.solving.is_empty());
        if let (Some(idx), Some(result)) = (type_idx, result) {
            assert!(self.solved.insert(idx, result).is_none());
        }
        result
    }

    fn cached(&self, idx: usize) -> Option<u64> {
        self.solved.get(&idx).copied()
    }

    fn inner_type_size_bytes(&mut self, ty: &Type) -> Option<u64> {
        Some(match &ty.type_variant {
            TypeVariant::Basic(Basic::Char) => 1,
            // TODO what is the SegReg size?
            TypeVariant::Basic(Basic::SegReg) => 1,
            TypeVariant::Basic(Basic::Void) => 0,
            TypeVariant::Basic(Basic::Unknown { bytes }) => (*bytes).into(),
            TypeVariant::Basic(Basic::Bool) => {
                self.section.size_bool.get().into()
            }
            TypeVariant::Basic(Basic::Short { .. }) => {
                self.section.sizeof_short().get().into()
            }
            TypeVariant::Basic(Basic::Int { .. }) => {
                self.section.size_int.get().into()
            }
            TypeVariant::Basic(Basic::Long { .. }) => {
                self.section.sizeof_long().get().into()
            }
            TypeVariant::Basic(Basic::LongLong { .. }) => {
                self.section.sizeof_long_long().get().into()
            }
            TypeVariant::Basic(Basic::IntSized { bytes, .. }) => {
                bytes.get().into()
            }
            TypeVariant::Basic(Basic::BoolSized { bytes }) => {
                bytes.get().into()
            }
            // TODO what's the long double default size if it's not defined?
            TypeVariant::Basic(Basic::LongDouble) => self
                .section
                .size_long_double
                .map(|x| x.get())
                .unwrap_or(8)
                .into(),
            TypeVariant::Basic(Basic::Float { bytes }) => bytes.get().into(),
            // TODO is pointer always near? Do pointer size default to 4?
            TypeVariant::Pointer(_) => self.section.addr_size().get().into(),
            TypeVariant::Function(_) => 0, // function type dont have a size, only a pointer to it
            TypeVariant::Array(array) => {
                let element_len =
                    self.inner_type_size_bytes(&array.elem_type)?;
                let nelem = array.nelem.map(|x| x.get()).unwrap_or(0) as u64;
                element_len * nelem
            }
            TypeVariant::StructRef(ref_type)
            | TypeVariant::UnionRef(ref_type)
            | TypeVariant::EnumRef(ref_type)
            | TypeVariant::Typedef(ref_type) => self.solve_typedef(ref_type)?,
            TypeVariant::Struct(til_struct) => {
                let mut sum = 0u64;
                // TODO default alignment, seems like default alignemnt is the field size
                let align: u64 = 1;
                let mut members = &til_struct.members[..];
                loop {
                    let Some(first_member) = members.first() else {
                        // no more members
                        break;
                    };
                    let field_size =
                        match &first_member.member_type.type_variant {
                            // if bit-field, condensate one or more to create a byte-field
                            TypeVariant::Bitfield(bitfield) => {
                                members = &members[1..];
                                // NOTE it skips 0..n members
                                condensate_bitfields_from_struct(
                                    *bitfield,
                                    &mut members,
                                )
                                .get()
                                .into()
                            }
                            // get the inner type size
                            _ => {
                                let first = &members[0];
                                members = &members[1..];
                                // next member
                                self.inner_type_size_bytes(&first.member_type)?
                            }
                        };
                    if !til_struct.is_unaligned {
                        let align = match (
                            first_member.alignment.map(|x| x.get().into()),
                            self.alignemnt(
                                &first_member.member_type,
                                field_size,
                            ),
                        ) {
                            (Some(a), Some(b)) => a.max(b),
                            (Some(a), None) | (None, Some(a)) => a,
                            (None, None) => align,
                        };
                        let align = align.max(1);
                        let align_diff = sum % align;
                        if align_diff != 0 {
                            sum += align - align_diff;
                        }
                    }
                    sum += field_size;
                }
                sum
            }
            TypeVariant::Union(Union { members, .. }) => {
                let mut max = 0;
                for (_, member) in members {
                    let size = self.inner_type_size_bytes(member)?;
                    max = max.max(size);
                }
                max
            }
            TypeVariant::Enum(Enum { storage_size, .. }) => storage_size
                .or(self.section.size_enum)
                .map(|x| x.get())
                .unwrap_or(4)
                .into(),
            TypeVariant::Bitfield(bitfield) => bitfield.width.into(),
        })
    }

    fn solve_typedef(&mut self, typedef: &Typedef) -> Option<u64> {
        let idx = match typedef {
            Typedef::Name(name) => {
                // NOTE missing names may indicate a external type, just return no size
                self.section.get_name_idx(name.as_ref()?)?
            }
            Typedef::Ordinal(ord) => self
                .section
                .get_ord_idx(crate::id0::Id0TilOrd { ord: (*ord).into() })?,
        };
        // if cached return it
        if let Some(solved) = self.cached(idx) {
            return Some(solved);
        }
        if !self.solving.insert(idx) {
            return None;
        }
        let inner_type = self.section.get_type_by_idx(idx);
        let result = self.inner_type_size_bytes(&inner_type.tinfo);
        self.solving.remove(&idx);
        if let Some(result) = result {
            assert!(self.solved.insert(idx, result).is_none());
        }
        result
    }

    fn alignemnt(&mut self, til: &Type, til_size: u64) -> Option<u64> {
        match &til.type_variant {
            // TODO basic types have a inherited alignment?
            TypeVariant::Basic(_)
            | TypeVariant::Enum(_)
            | TypeVariant::Pointer(_) => Some(til_size),
            TypeVariant::Array(array) => {
                let size = self.inner_type_size_bytes(&array.elem_type);
                self.alignemnt(&array.elem_type, size.unwrap_or(1))
            }
            TypeVariant::EnumRef(ty) => {
                let ty = match ty {
                    Typedef::Ordinal(ord) => self
                        .section
                        .get_ord(crate::id0::Id0TilOrd { ord: (*ord).into() }),
                    Typedef::Name(Some(name)) => self.section.get_name(name),
                    Typedef::Name(None) => None,
                };
                ty.and_then(|ty| self.inner_type_size_bytes(&ty.tinfo))
            }
            TypeVariant::Typedef(ty) => {
                let ty = match ty {
                    Typedef::Ordinal(ord) => self
                        .section
                        .get_ord(crate::id0::Id0TilOrd { ord: (*ord).into() }),
                    Typedef::Name(Some(name)) => self.section.get_name(name),
                    Typedef::Name(None) => None,
                };
                ty.and_then(|ty| {
                    let size =
                        self.inner_type_size_bytes(&ty.tinfo).unwrap_or(1);
                    self.alignemnt(&ty.tinfo, size)
                })
            }
            _ => None,
        }
    }
}

fn condensate_bitfields_from_struct(
    first_field: Bitfield,
    rest: &mut &[StructMember],
) -> NonZeroU8 {
    let field_bytes = first_field.nbytes;
    let field_bits: u16 = u16::from(first_field.nbytes.get()) * 8;
    let mut condensated_bits = first_field.width;

    loop {
        let Some(TypeVariant::Bitfield(member)) =
            rest.first().map(|x| &x.member_type.type_variant)
        else {
            // no more bit-fields to condensate
            break;
        };
        // condensate the bit-field into the byte-field
        condensated_bits += member.width;
        // check if this bit start the next field
        if field_bytes != member.nbytes || condensated_bits > field_bits {
            // NOTE this don't consume the current member
            break;
        }

        // advance to the next member
        *rest = &rest[1..];
    }
    field_bytes
}

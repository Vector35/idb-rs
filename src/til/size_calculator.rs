use std::collections::{HashMap, HashSet};
use std::num::NonZeroU8;

use crate::til::bitfield::Bitfield;

use super::r#enum::Enum;
use super::r#struct::StructMember;
use super::section::TILSection;
use super::union::Union;
use super::{Basic, Type, TypeVariant, Typeref, TyperefValue};

pub struct TILTypeSizeSolver<'a> {
    section: &'a TILSection,
    solved_size: HashMap<usize, u64>,
    solved_align: HashMap<usize, u64>,
    // HACK used to avoid infinte lopping during recursive solving
    solving: HashSet<usize>,
}

impl<'a> TILTypeSizeSolver<'a> {
    pub fn new(section: &'a TILSection) -> Self {
        Self {
            section,
            solved_size: Default::default(),
            solved_align: Default::default(),
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
        if let Some(idx) = type_idx {
            // if cached return it
            if let Some(solved) = self.solved_size.get(&idx) {
                return Some(*solved);
            }
            if !self.solving.insert(idx) {
                return None;
            }
        }
        let result = self.inner_type_size_bytes(ty);
        if let Some(idx) = type_idx {
            assert!(self.solving.remove(&idx));
        }
        if let (Some(idx), Some(result)) = (type_idx, result) {
            assert!(self.solved_size.insert(idx, result).is_none());
        }
        result
    }

    fn inner_type_size_bytes(&mut self, ty: &Type) -> Option<u64> {
        Some(match &ty.type_variant {
            TypeVariant::Basic(Basic::Char) => 1,
            // TODO what is the SegReg size?
            TypeVariant::Basic(Basic::SegReg) => 1,
            TypeVariant::Basic(Basic::Void) => 0,
            TypeVariant::Basic(Basic::Unknown { bytes }) => (*bytes).into(),
            TypeVariant::Basic(Basic::Bool) => {
                self.section.header.size_bool.get().into()
            }
            TypeVariant::Basic(Basic::Short { .. }) => {
                self.section.sizeof_short().get().into()
            }
            TypeVariant::Basic(Basic::Int { .. }) => {
                self.section.header.size_int.get().into()
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
                .header
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
            TypeVariant::Typeref(ref_type) => self.solve_typedef(ref_type)?,
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
                            self.inner_type_align_bytes(
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
                for member in members {
                    let size = self.inner_type_size_bytes(&member.ty)?;
                    max = max.max(size);
                }
                max
            }
            TypeVariant::Enum(Enum { storage_size, .. }) => storage_size
                .or(self.section.header.size_enum)
                .map(|x| x.get())
                .unwrap_or(4)
                .into(),
            TypeVariant::Bitfield(bitfield) => bitfield.width.into(),
        })
    }

    fn solve_typedef(&mut self, typedef: &Typeref) -> Option<u64> {
        let TyperefValue::Ref(idx) = &typedef.typeref_value else {
            return None;
        };
        let ty = self.section.get_type_by_idx(*idx);
        self.type_size_bytes(Some(*idx), &ty.tinfo)
    }

    pub fn type_align_bytes(
        &mut self,
        type_idx: Option<usize>,
        ty: &Type,
        til_size: u64,
    ) -> Option<u64> {
        if let Some(idx) = type_idx {
            // if cached return it
            if let Some(solved) = self.solved_align.get(&idx) {
                return Some(*solved);
            }
            if !self.solving.insert(idx) {
                return None;
            }
        }
        let result = self.inner_type_align_bytes(ty, til_size);
        if let Some(idx) = type_idx {
            assert!(self.solving.remove(&idx));
        }
        if let (Some(idx), Some(result)) = (type_idx, result) {
            assert!(self.solved_align.insert(idx, result).is_none());
        }
        result
    }

    fn inner_type_align_bytes(
        &mut self,
        til: &Type,
        til_size: u64,
    ) -> Option<u64> {
        match &til.type_variant {
            // TODO basic types have a inherited alignment?
            TypeVariant::Basic(_)
            | TypeVariant::Enum(_)
            | TypeVariant::Pointer(_) => Some(til_size),
            TypeVariant::Array(array) => {
                let size = self.inner_type_size_bytes(&array.elem_type);
                self.inner_type_align_bytes(&array.elem_type, size.unwrap_or(1))
            }
            TypeVariant::Typeref(ty) => {
                let TyperefValue::Ref(idx) = &ty.typeref_value else {
                    return None;
                };
                let ty = &self.section.types[*idx].tinfo;
                let size = self.inner_type_size_bytes(ty).unwrap_or(1);
                self.inner_type_align_bytes(ty, size)
            }
            TypeVariant::Struct(ty_struct) => {
                let max_member_align = ty_struct
                    .members
                    .iter()
                    .filter_map(|m| {
                        let type_bytes = self
                            .type_size_bytes(None, &m.member_type)
                            .unwrap_or(0);
                        self.inner_type_align_bytes(&m.member_type, type_bytes)
                    })
                    .max()
                    .unwrap_or(1);
                Some(
                    ty_struct
                        .alignment
                        .map(|x| u64::from(x.get()))
                        .unwrap_or(1)
                        .max(max_member_align),
                )
            }
            TypeVariant::Union(ty_union) => {
                let max_member_align = ty_union
                    .members
                    .iter()
                    .filter_map(|member| {
                        let type_bytes =
                            self.type_size_bytes(None, &member.ty).unwrap_or(0);
                        self.inner_type_align_bytes(&member.ty, type_bytes)
                    })
                    .max()
                    .unwrap_or(1);
                Some(
                    ty_union
                        .alignment
                        .map(|x| u64::from(x.get()))
                        .unwrap_or(1)
                        .max(max_member_align),
                )
            }
            TypeVariant::Function(_) | TypeVariant::Bitfield(_) => Some(1),
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

pub mod array;
pub mod bitfield;
pub mod r#enum;
/// The u8 values used to describes the type information records in IDA.
pub mod flag;
pub mod function;
pub mod pointer;
pub mod section;
pub mod r#struct;
pub mod union;

mod size_calculator;

use section::TILSectionHeader;
pub use size_calculator::*;

use std::collections::HashMap;
use std::num::NonZeroU8;

use anyhow::{anyhow, ensure, Context, Result};

use crate::ida_reader::{IdaGenericBufUnpack, IdaGenericUnpack};

use crate::til::array::{Array, ArrayRaw};
use crate::til::bitfield::Bitfield;
use crate::til::function::{Function, FunctionRaw};
use crate::til::pointer::{Pointer, PointerRaw};
use crate::til::r#enum::{Enum, EnumRaw};
use crate::til::r#struct::{Struct, StructRaw};
use crate::til::union::{Union, UnionRaw};
use crate::IDBString;

#[derive(Debug, Clone)]
pub struct TILTypeInfo {
    pub name: IDBString,
    pub ordinal: u64,
    pub tinfo: Type,
}

impl TILTypeInfo {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        til: &TILSectionHeader,
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        name: IDBString,
        ordinal: u64,
        tinfo_raw: TypeRaw,
        comment: Vec<u8>,
        fields: Vec<Vec<u8>>,
        comments: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let mut fields_iter = fields
            .into_iter()
            .map(|field| (!field.is_empty()).then_some(IDBString::new(field)));
        let mut comments_iter = [comment]
            .into_iter()
            .chain(comments)
            .map(|field| (!field.is_empty()).then_some(IDBString::new(field)));
        let tinfo = Type::new(
            til,
            type_by_name,
            type_by_ord,
            tinfo_raw,
            &mut fields_iter,
            &mut comments_iter,
        )?;
        #[cfg(feature = "restrictive")]
        ensure!(
            fields_iter.next().is_none(),
            "Extra fields found for til type \"{}\"",
            name.as_utf8_lossy()
        );
        #[cfg(feature = "restrictive")]
        ensure!(
            comments_iter.next().is_none(),
            "Extra fields found for til type \"{}\"",
            name.as_utf8_lossy()
        );
        Ok(Self {
            name,
            ordinal,
            tinfo,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TILTypeInfoRaw {
    _flags: u32,
    pub name: IDBString,
    pub ordinal: u64,
    pub tinfo: TypeRaw,
    cmt: Vec<u8>,
    fieldcmts: Vec<Vec<u8>>,
    fields: Vec<Vec<u8>>,
    _sclass: u8,
}

impl TILTypeInfoRaw {
    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        til: &TILSectionHeader,
        is_last: bool,
    ) -> Result<Self> {
        let data = if is_last {
            // HACK: for some reason the last type in a bucker could be smaller, so we can't
            // predict the size reliably
            let mut data = vec![];
            input.read_to_end(&mut data)?;
            data
        } else {
            input.read_raw_til_type(til.format)?
        };
        let mut cursor = &data[..];
        let result = Self::read_inner(&mut cursor, til)?;
        #[cfg(feature = "restrictive")]
        ensure!(
            cursor.is_empty(),
            "Unable to parse til type fully, left {} bytes",
            cursor.len()
        );
        Ok(result)
    }

    fn read_inner(cursor: &mut &[u8], til: &TILSectionHeader) -> Result<Self> {
        let flags: u32 = cursor.read_u32()?;
        // TODO verify if flags equal to 0x7fff_fffe?
        let name = IDBString::new(cursor.read_c_string_raw()?);
        let is_u64 = (flags >> 31) != 0;
        let ordinal = match (til.format, is_u64) {
            // formats below 0x12 doesn't have 64 bits ord
            (0..=0x11, _) | (_, false) => cursor.read_u32()?.into(),
            (_, true) => cursor.read_u64()?,
        };
        let tinfo = TypeRaw::read(&mut *cursor, til).with_context(|| {
            format!(
                "parsing `TILTypeInfo::tiinfo` for type \"{}\"",
                name.as_utf8_lossy()
            )
        })?;
        let _info = cursor.read_c_string_raw()?;
        let cmt = cursor.read_c_string_raw()?;
        let fields = cursor.read_c_string_vec()?;
        let fieldcmts = cursor.read_c_string_vec()?;
        let sclass: u8 = cursor.read_u8()?;

        Ok(Self {
            _flags: flags,
            name,
            ordinal,
            tinfo,
            cmt,
            fields,
            fieldcmts,
            _sclass: sclass,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Type {
    pub comment: Option<IDBString>,
    pub is_const: bool,
    pub is_volatile: bool,
    pub type_variant: TypeVariant,
}

#[derive(Debug, Clone)]
pub enum TypeVariant {
    Basic(Basic),
    Pointer(Pointer),
    Function(Function),
    Array(Array),
    Typeref(Typeref),
    Struct(Struct),
    Union(Union),
    Enum(Enum),
    Bitfield(Bitfield),
}

impl Type {
    pub(crate) fn new(
        til: &TILSectionHeader,
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        tinfo_raw: TypeRaw,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<IDBString>>,
    ) -> Result<Self> {
        let comment = comments.next().flatten();
        let type_variant = match tinfo_raw.variant {
            TypeVariantRaw::Basic(x) => TypeVariant::Basic(x),
            TypeVariantRaw::Bitfield(x) => TypeVariant::Bitfield(x),
            TypeVariantRaw::Typedef(x) => {
                Typeref::new(type_by_name, type_by_ord, x)
                    .map(TypeVariant::Typeref)?
            }
            TypeVariantRaw::Pointer(x) => Pointer::new(
                til,
                type_by_name,
                type_by_ord,
                x,
                fields,
                comments,
            )
            .map(TypeVariant::Pointer)?,
            TypeVariantRaw::Function(x) => Function::new(
                til,
                type_by_name,
                type_by_ord,
                x,
                fields,
                comments,
            )
            .map(TypeVariant::Function)?,
            TypeVariantRaw::Array(x) => {
                Array::new(til, type_by_name, type_by_ord, x, fields, comments)
                    .map(TypeVariant::Array)?
            }
            TypeVariantRaw::Struct(x) => {
                Struct::new(til, type_by_name, type_by_ord, x, fields, comments)
                    .map(TypeVariant::Struct)?
            }
            TypeVariantRaw::Union(x) => {
                Union::new(til, type_by_name, type_by_ord, x, fields, comments)
                    .map(TypeVariant::Union)?
            }
            TypeVariantRaw::Enum(x) => {
                Enum::new(til, x, fields, comments).map(TypeVariant::Enum)?
            }
            TypeVariantRaw::StructRef(x) => {
                Typeref::new_struct(type_by_name, type_by_ord, x)
                    .map(TypeVariant::Typeref)?
            }
            TypeVariantRaw::UnionRef(x) => {
                Typeref::new_union(type_by_name, type_by_ord, x)
                    .map(TypeVariant::Typeref)?
            }
            TypeVariantRaw::EnumRef(x) => {
                Typeref::new_enum(type_by_name, type_by_ord, x)
                    .map(TypeVariant::Typeref)?
            }
        };
        Ok(Self {
            comment,
            is_const: tinfo_raw.is_const,
            is_volatile: tinfo_raw.is_volatile,
            type_variant,
        })
    }
    // TODO find the best way to handle type parsing from id0
    pub(crate) fn new_from_id0(
        data: &[u8],
        fields: Vec<Vec<u8>>,
    ) -> Result<Self> {
        // TODO it's unclear what header information id0 types use to parse tils
        // maybe it just use the til sector header, or more likelly it's from
        // IDBParam  in the `Root Node`
        let header = ephemeral_til_header();
        let mut reader = data;
        let type_raw = TypeRaw::read(&mut reader, &header)?;
        match reader {
            // all types end with \x00, unknown if it have any meaning
            &[b'\x00'] => {}
            // in continuations, the \x00 may be missing
            &[] => {}
            _rest => {
                #[cfg(feature = "restrictive")]
                return Err(anyhow!(
                    "Extra {} bytes after reading TIL from ID0",
                    _rest.len()
                ));
            }
        }
        let mut fields_iter = fields.into_iter().map(|field| {
            if field.is_empty() {
                None
            } else {
                Some(IDBString::new(field))
            }
        });
        let result = Self::new(
            &header,
            &HashMap::new(),
            &HashMap::new(),
            type_raw,
            &mut fields_iter,
            &mut vec![].into_iter(),
        )?;
        #[cfg(feature = "restrictive")]
        ensure!(
            fields_iter.next().is_none(),
            "Extra fields found for id0 til"
        );
        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TypeRaw {
    is_const: bool,
    is_volatile: bool,
    variant: TypeVariantRaw,
}

#[derive(Debug, Clone)]
pub(crate) enum TypeVariantRaw {
    Basic(Basic),
    Pointer(PointerRaw),
    Function(FunctionRaw),
    Array(ArrayRaw),
    Typedef(TypedefRaw),
    Struct(StructRaw),
    Union(UnionRaw),
    Enum(EnumRaw),
    StructRef(TypedefRaw),
    UnionRef(TypedefRaw),
    EnumRef(TypedefRaw),
    Bitfield(Bitfield),
}

impl TypeRaw {
    pub fn read(
        input: &mut impl IdaGenericBufUnpack,
        til: &TILSectionHeader,
    ) -> Result<Self> {
        let metadata: u8 = input.read_u8()?;
        let type_base = metadata & flag::tf_mask::TYPE_BASE_MASK;
        let type_flags = metadata & flag::tf_mask::TYPE_FLAGS_MASK;

        // TODO find if this apply to all fields, or only a selected few?
        // TODO some fields can be both CONST and VOLATILE at the same time, what that means?
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473084 print_til_type
        let is_const = metadata & flag::tf_modifiers::BTM_CONST != 0;
        let is_volatile = metadata & flag::tf_modifiers::BTM_VOLATILE != 0;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480335
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x472e13 print_til_type
        let variant = match (type_base, type_flags) {
            (..=flag::tf_last_basic::BT_LAST_BASIC, _) => {
                Basic::new(til, type_base, type_flags)
                    .context("Type::Basic")
                    .map(TypeVariantRaw::Basic)?
            }
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4804d7
            (flag::tf_ptr::BT_PTR, _) => {
                PointerRaw::read(input, til, type_flags)
                    .context("Type::Pointer")
                    .map(TypeVariantRaw::Pointer)?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48075a
            (flag::tf_array::BT_ARRAY, _) => {
                ArrayRaw::read(input, til, type_flags)
                    .context("Type::Array")
                    .map(TypeVariantRaw::Array)?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48055d
            (flag::tf_func::BT_FUNC, _) => {
                FunctionRaw::read(input, til, type_flags)
                    .context("Type::Function")
                    .map(TypeVariantRaw::Function)?
            }

            (flag::tf_complex::BT_BITFIELD, _) => TypeVariantRaw::Bitfield(
                Bitfield::read(input, type_flags).context("Type::Bitfield")?,
            ),

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480369
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_TYPEDEF) => {
                TypedefRaw::read(input)
                    .context("Type::Typedef")
                    .map(TypeVariantRaw::Typedef)?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480378

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_UNION) => {
                UnionRaw::read(input, til).context("Type::Union")?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_STRUCT) => {
                StructRaw::read(input, til).context("Type::Struct")?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_ENUM) => {
                EnumRaw::read(input, til).context("Type::Enum")?
            }

            (flag::tf_complex::BT_COMPLEX, _) => unreachable!(),

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47395d print_til_type
            (flag::BT_RESERVED, _) => {
                return Err(anyhow!("Wrong/Unknown type: {metadata:02x}"))
            }

            (flag::BT_RESERVED.., _) => unreachable!(),
        };
        Ok(Self {
            is_const,
            is_volatile,
            variant,
        })
    }

    pub fn read_ref(
        input: &mut impl IdaGenericUnpack,
        header: &TILSectionHeader,
    ) -> Result<Self> {
        let mut bytes = input.unpack_dt_bytes()?;

        if !bytes.starts_with(b"=") {
            let dt = serialize_dt(bytes.len().try_into().unwrap())?;
            bytes = [b'='].into_iter().chain(dt).chain(bytes).collect();
        }

        let mut bytes = &bytes[..];
        let result = TypeRaw::read(&mut bytes, header)?;
        #[cfg(feature = "restrictive")]
        ensure!(bytes.is_empty(), "Unable to fully parser Type ref");
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Basic {
    Void,
    // NOTE Unknown with 0 bytes is NOT the same as Void
    Unknown {
        bytes: u8,
    },

    Bool,
    BoolSized {
        bytes: NonZeroU8,
    },
    Char,
    SegReg,
    Short {
        is_signed: Option<bool>,
    },
    Long {
        is_signed: Option<bool>,
    },
    LongLong {
        is_signed: Option<bool>,
    },
    Int {
        is_signed: Option<bool>,
    },
    IntSized {
        bytes: NonZeroU8,
        is_signed: Option<bool>,
    },
    Float {
        bytes: NonZeroU8,
    },
    LongDouble,
}

impl Basic {
    fn new(til: &TILSectionHeader, bt: u8, btmt: u8) -> Result<Self> {
        const fn bytes(bytes: u8) -> NonZeroU8 {
            if bytes == 0 {
                unreachable!()
            }
            unsafe { NonZeroU8::new_unchecked(bytes) }
        }

        use flag::{tf_bool::*, tf_float::*, tf_int::*, tf_unk::*};
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x472e2a print_til_type
        match bt {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480874
            BT_UNK => {
                let bytes = match btmt {
                    BTMT_SIZE0 => {
                        return Err(anyhow!("forbidden use of BT_UNK"))
                    }
                    BTMT_SIZE12 => 2,  // BT_UNK_WORD
                    BTMT_SIZE48 => 8,  // BT_UNK_QWORD
                    BTMT_SIZE128 => 0, // BT_UNKNOWN
                    _ => unreachable!(),
                };
                Ok(Self::Unknown { bytes })
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480694
            BT_VOID => {
                let bytes = match btmt {
                    // special case, void
                    BTMT_SIZE0 => return Ok(Self::Void), // BT_VOID
                    BTMT_SIZE12 => 1,                    // BT_UNK_BYTE
                    BTMT_SIZE48 => 4,                    // BT_UNK_DWORD
                    BTMT_SIZE128 => 16,                  // BT_UNK_OWORD
                    _ => unreachable!(),
                };
                // TODO extra logic
                // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480694
                Ok(Self::Unknown { bytes })
            }
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480474
            bt_int @ BT_INT8..=BT_INT => {
                let is_signed = match btmt {
                    BTMT_UNKSIGN => None,
                    BTMT_SIGNED => Some(true),
                    BTMT_UNSIGNED => Some(false),
                    // special case for char
                    BTMT_CHAR => {
                        return match bt_int {
                            BT_INT8 => Ok(Self::Char),
                            BT_INT => Ok(Self::SegReg), // BT_SEGREG
                            _ => Err(anyhow!(
                                "Reserved use of tf_int::BTMT_CHAR {:x}",
                                btmt
                            )),
                        };
                    }
                    _ => unreachable!(),
                };
                let bytes = match bt_int {
                    BT_INT8 => bytes(1),
                    BT_INT16 => bytes(2),
                    BT_INT32 => bytes(4),
                    BT_INT64 => bytes(8),
                    BT_INT128 => bytes(16),
                    BT_INT => return Ok(Self::Int { is_signed }),
                    _ => unreachable!(),
                };
                Ok(Self::IntSized { bytes, is_signed })
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4805c4
            BT_BOOL => {
                let bytes = match btmt {
                    BTMT_DEFBOOL => til.size_bool,
                    BTMT_BOOL1 => bytes(1),
                    BTMT_BOOL4 => bytes(4),
                    // TODO get the inf_is_64bit  field
                    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480d6f
                    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473a76
                    //BTMT_BOOL2 if !inf_is_64bit => Some(bytes(2)),
                    //BTMT_BOOL8 if inf_is_64bit => Some(bytes(8)),
                    BTMT_BOOL8 => bytes(2), // delete this
                    _ => unreachable!(),
                };
                Ok(Self::BoolSized { bytes })
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808b4
            BT_FLOAT => {
                let bytes = match btmt {
                    BTMT_FLOAT => bytes(4),
                    BTMT_DOUBLE => bytes(8),
                    // TODO error if none?
                    BTMT_LNGDBL => til.size_long_double.unwrap_or(bytes(8)),
                    // TODO find the tbyte_size field
                    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808e7
                    //BTMT_SPECFLT if til.tbyte_size() => Some(bytes),
                    BTMT_SPECFLT => bytes(2),
                    _ => unreachable!(),
                };
                Ok(Self::Float { bytes })
            }
            _ => Err(anyhow!("Unknown Unset Type {}", btmt)),
        }
    }
}

#[derive(Clone, Debug)]
pub enum TypedefRaw {
    Ordinal(u32),
    Name(Option<IDBString>),
}

impl TypedefRaw {
    fn read(input: &mut impl IdaGenericUnpack) -> Result<Self> {
        let buf = input.unpack_dt_bytes()?;
        match &buf[..] {
            [b'#', data @ ..] => {
                let mut tmp = data;
                let de = tmp.read_de()?;
                if !tmp.is_empty() {
                    return Err(anyhow!(
                        "Typedef Ordinal with more data then expected"
                    ));
                }
                Ok(Self::Ordinal(de))
            }
            _ => Ok(Self::Name(if buf.is_empty() {
                None
            } else {
                Some(IDBString::new(buf))
            })),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Typeref {
    pub ref_type: Option<TyperefType>,
    pub typeref_value: TyperefValue,
}

#[derive(Clone, Debug)]
pub enum TyperefValue {
    Ref(usize),
    UnsolvedName(Option<IDBString>),
    UnsolvedOrd(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TyperefType {
    Struct,
    Union,
    Enum,
}

impl Typeref {
    pub(crate) fn new(
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        tyref: TypedefRaw,
    ) -> Result<Self> {
        let pos = match tyref {
            // TODO check is ord is set on the header
            TypedefRaw::Ordinal(ord) => {
                let Some(pos) = type_by_ord.get(&(ord.into())) else {
                    return Ok(Self {
                        ref_type: None,
                        typeref_value: TyperefValue::UnsolvedOrd(ord),
                    });
                };
                pos
            }
            TypedefRaw::Name(None) => {
                return Ok(Self {
                    ref_type: None,
                    typeref_value: TyperefValue::UnsolvedName(None),
                })
            }
            TypedefRaw::Name(Some(name)) => {
                let Some(pos) = type_by_name.get(name.as_bytes()) else {
                    return Ok(Self {
                        ref_type: None,
                        typeref_value: TyperefValue::UnsolvedName(Some(name)),
                    });
                };
                pos
            }
        };
        Ok(Self {
            ref_type: None,
            typeref_value: TyperefValue::Ref(*pos),
        })
    }

    fn new_struct(
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        x: TypedefRaw,
    ) -> Result<Self> {
        let mut result = Self::new(type_by_name, type_by_ord, x)?;
        result.ref_type = Some(TyperefType::Struct);
        // TODO check the inner type is in fact a struct
        Ok(result)
    }

    fn new_union(
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        x: TypedefRaw,
    ) -> Result<Self> {
        let mut result = Self::new(type_by_name, type_by_ord, x)?;
        result.ref_type = Some(TyperefType::Union);
        // TODO check the inner type is in fact a union
        Ok(result)
    }

    fn new_enum(
        type_by_name: &HashMap<Vec<u8>, usize>,
        type_by_ord: &HashMap<u64, usize>,
        x: TypedefRaw,
    ) -> Result<Self> {
        let mut result = Self::new(type_by_name, type_by_ord, x)?;
        result.ref_type = Some(TyperefType::Enum);
        // TODO check the inner type is in fact a enum
        Ok(result)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum TILModifier {
    Const,
    Volatile,
}

#[derive(Debug, Clone)]
pub struct TILMacro {
    pub name: Vec<u8>,
    pub param_num: Option<u8>,
    pub value: Vec<TILMacroValue>,
}

#[derive(Debug, Clone)]
pub enum TILMacroValue {
    // 0x01..=0x7F
    Char(u8),
    // 0x80..0xFF => 0..127
    Param(u8),
}

impl TILMacro {
    fn read(input: &mut impl IdaGenericBufUnpack) -> Result<Self> {
        let name = input.read_c_string_raw()?;
        // TODO find what this is
        let flag: u16 = input.read_u16()?;
        ensure!(flag & 0xFE00 == 0, "Unknown Macro flag value {flag}");
        let have_param = flag & 0x100 != 0;
        let param_num = have_param.then_some((flag & 0xFF) as u8);
        if !have_param {
            #[cfg(feature = "restrictive")]
            ensure!(
                flag & 0xFF == 0,
                "Unknown/Invalid value for TILMacro flag"
            );
        }
        // TODO find the InnerRef for this
        let value = input.read_c_string_raw()?;
        let mut max_param = None;
        // TODO check the implementation using the InnerRef
        let value: Vec<TILMacroValue> = value
            .into_iter()
            .filter_map(|c| match c {
                0x00 => unreachable!(),
                0x01..=0x7F => Some(TILMacroValue::Char(c)),
                0x80..=0xFF => {
                    let param_idx = c & 0x7F;
                    if !have_param && matches!(param_idx, 0x20 | 0x25 | 0x29) {
                        // HACK: it's known that some macros, although having no params
                        // include some params in the value, It's unknown the meaning of those,
                        // maybe they are just bugs.
                        return None;
                    }
                    match (max_param, param_idx) {
                        (None, _) => max_param = Some(param_idx),
                        (Some(max), param_idx) if param_idx > max => {
                            max_param = Some(param_idx)
                        }
                        (Some(_), _) => {}
                    }
                    Some(TILMacroValue::Param(param_idx))
                }
            })
            .collect();
        match (param_num, max_param) {
            // the macro not using the defined params is allowed in all situations
            (_, None) => {}
            // having params, where should not
            (None, Some(_max)) => {
                #[cfg(feature = "restrictive")]
                return Err(anyhow!(
                    "Macro value have params but it is not declared in the flag",
                ))
            }
            // only using params that exist
            (Some(params), Some(max)) if max <= params => {
                #[cfg(feature = "restrictive")]
                ensure!(
                    max <= params,
                    "Macro value have more params then declared in the flag"
                );
            }
            // using only allowed params
            (Some(_params), Some(_max)) /* if _max <= _params */ => {}
        }
        Ok(Self {
            name,
            value,
            param_num,
        })
    }
}

// TODO make those inner fields into enums or private
#[derive(Clone, Copy, Debug)]
pub struct BaseTypeFlag(pub u8);
#[derive(Clone, Copy, Debug)]
pub struct FullTypeFlag(pub u8);
#[derive(Clone, Copy, Debug)]
pub struct TypeFlag(pub u8);
#[derive(Clone, Copy, Debug)]
pub struct CallingConventionFlag(pub u8);

#[derive(Clone, Debug)]
pub struct TypeAttribute {
    pub tattr: u16,
    pub extended: Option<Vec<TypeAttributeExt>>,
}

#[derive(Clone, Debug)]
pub struct TypeAttributeExt {
    pub _value1: Vec<u8>,
    pub _value2: Vec<u8>,
}

fn serialize_dt(value: u16) -> Result<Vec<u8>> {
    if value > 0x7FFE {
        return Err(anyhow!("Invalid value for DT"));
    }
    let lo = value + 1;
    let mut hi = value + 1;
    let mut result: Vec<u8> = Vec::with_capacity(2);
    if lo > 127 {
        result.push((lo & 0x7F | 0x80) as u8);
        hi = (lo >> 7) & 0xFF;
    }
    result.push(hi as u8);
    Ok(result)
}

pub fn ephemeral_til_header() -> TILSectionHeader {
    section::TILSectionHeader {
        format: 12,
        flags: section::TILSectionFlags(0),
        description: IDBString::new(Vec::new()),
        dependencies: Vec::new(),
        size_enum: None,
        size_int: 4.try_into().unwrap(),
        size_bool: 1.try_into().unwrap(),
        def_align: None,
        size_long_double: None,
        extended_sizeof_info: None,
        cc: None,
        cn: None,
        type_ordinal_alias: None,
        is_universal: true,
        compiler_id: crate::id0::Compiler::Unknown,
        cm: None,
    }
}

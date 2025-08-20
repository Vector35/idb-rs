pub mod array;
pub mod bitfield;
pub mod r#enum;
/// The u8 values used to describes the type information records in IDA.
pub mod flag;
pub mod function;
pub mod pointer;
pub mod section;
pub mod udt;

mod size_calculator;

use section::TILSectionHeader;
use serde::Serialize;
pub use size_calculator::*;

use std::num::NonZeroU8;

use anyhow::{anyhow, ensure, Context, Result};

use crate::id0::RootInfo;
use crate::ida_reader::{IdbBufRead, IdbRead};

use crate::til::array::Array;
use crate::til::bitfield::Bitfield;
use crate::til::function::Function;
use crate::til::pointer::Pointer;
use crate::til::r#enum::Enum;
use crate::til::udt::UDT;
use crate::{IDAKind, IDBString};

#[derive(Debug, Clone, Serialize)]
pub struct TILTypeInfo {
    pub name: IDBString,
    pub ordinal: u64,
    pub tinfo: Type,
    pub sclass: Option<SClass>,
}

impl TILTypeInfo {
    pub(crate) fn read(
        input: &mut impl IdbBufRead,
        header: &TILSectionHeader,
    ) -> Result<Self> {
        let flags: u32 = input.read_u32()?;
        ensure!(
            flags == 0xFFFF_FFFF || flags == 0x7FFF_FFFF,
            "Unknown TILTypeInfo flag value"
        );
        // TODO verify if flags equal to 0x7fff_fffe?
        let name = IDBString::new(input.read_c_string_raw()?);
        let is_u64 = (flags >> 31) != 0;
        let ordinal = match (header.format, is_u64) {
            // formats below 0x12 doesn't have 64 bits ord
            (0..=0x11, _) | (_, false) => input.read_u32()?.into(),
            (_, true) => input.read_u64()?,
        };
        let tinfo_raw = input.read_c_string_raw()?;
        let cmt = input.read_c_string_raw()?;
        let fields = input.read_c_string_vec()?;
        let fieldcmts: Vec<_> = input
            .read_c_string_vec()?
            .into_iter()
            .map(CommentType::from_raw)
            .collect::<Result<_>>()?;
        let sclass = SClass::from_raw(input.read_u8()?);

        let mut tinfo_cursor = &tinfo_raw[..];
        let mut fields_iter = fields
            .into_iter()
            .map(|x| (!x.is_empty()).then(|| IDBString::new(x)));
        let mut fieldcmts_iter = fieldcmts.into_iter();
        let tinfo = Type::read(
            &mut tinfo_cursor,
            header,
            (!cmt.is_empty()).then_some(cmt),
            &mut fields_iter,
            &mut fieldcmts_iter,
        )
        .with_context(|| {
            format!(
                "parsing `TILTypeInfo::tiinfo` for type \"{}\"",
                name.as_utf8_lossy()
            )
        })?;
        #[cfg(feature = "restrictive")]
        ensure!(
            tinfo_cursor.is_empty(),
            "Unable to parse til type fully, left {} bytes {}",
            tinfo_cursor.len(),
            (tinfo_cursor.len() < 10)
                .then(|| format!("{:02X?}", tinfo_cursor))
                .unwrap_or("[..]".into())
        );
        #[cfg(feature = "restrictive")]
        ensure!(fields_iter.next().is_none(), "Unparsed name fields");
        #[cfg(feature = "restrictive")]
        ensure!(fieldcmts_iter.next().is_none(), "Unparsed comment fields");

        Ok(Self {
            name,
            ordinal,
            tinfo,
            sclass,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum SClass {
    Typedef,
    Extern,
    Static,
    Register,
    Auto,
    Friend,
    Virtual,
    // TODO allow this unknown value?
    Other(u8),
}

impl SClass {
    pub(crate) fn from_raw(value: u8) -> Option<Self> {
        Some(match value {
            0 => return None,
            1 => Self::Typedef,
            2 => Self::Extern,
            3 => Self::Static,
            4 => Self::Register,
            5 => Self::Auto,
            6 => Self::Friend,
            7 => Self::Virtual,
            value => Self::Other(value),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Type {
    pub comment: Option<IDBString>,
    pub is_const: bool,
    pub is_volatile: bool,
    pub type_variant: TypeVariant,
}

#[derive(Debug, Clone, Serialize)]
pub enum TypeVariant {
    Basic(Basic),
    Pointer(Pointer),
    Function(Function),
    Array(Array),
    Typeref(Typeref),
    Struct(UDT),
    Union(UDT),
    Enum(Enum),
    Bitfield(Bitfield),
}

impl Type {
    pub fn read(
        input: &mut impl IdbBufRead,
        header: &TILSectionHeader,
        comment: Option<Vec<u8>>,
        fields: &mut impl Iterator<Item = Option<IDBString>>,
        comments: &mut impl Iterator<Item = Option<CommentType>>,
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
        let type_variant = match (type_base, type_flags) {
            (..=flag::tf_last_basic::BT_LAST_BASIC, _) => {
                Basic::new(input, header, type_base, type_flags)
                    .context("Type::Basic")
                    .map(TypeVariant::Basic)?
            }
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4804d7
            (flag::tf_ptr::BT_PTR, _) => {
                Pointer::read(input, header, type_flags, fields, comments)
                    .context("Type::Pointer")
                    .map(TypeVariant::Pointer)?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48075a
            (flag::tf_array::BT_ARRAY, _) => {
                Array::read(input, header, type_flags, fields, comments)
                    .context("Type::Array")
                    .map(TypeVariant::Array)?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48055d
            (flag::tf_func::BT_FUNC, _) => {
                Function::read(input, header, type_flags, fields, comments)
                    .context("Type::Function")
                    .map(TypeVariant::Function)?
            }

            (flag::tf_complex::BT_BITFIELD, _) => TypeVariant::Bitfield(
                Bitfield::read(input, type_flags).context("Type::Bitfield")?,
            ),

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480369
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_TYPEDEF) => {
                Typeref::read(input)
                    .context("Type::Typedef")
                    .map(TypeVariant::Typeref)?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480378

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_UNION) => {
                UDT::read_union(input, header, fields, comments)
                    .context("Type::Union")?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_STRUCT) => {
                UDT::read_struct(input, header, fields, comments)
                    .context("Type::Struct")?
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_ENUM) => {
                Enum::read(input, header, fields, comments)
                    .context("Type::Enum")?
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
            comment: comment.map(IDBString::new),
            type_variant,
        })
    }

    // TODO find the best way to handle type parsing from id0
    pub(crate) fn new_from_id0<K: IDAKind>(
        info: &RootInfo<K>,
        data: &[u8],
        fields: Vec<Vec<u8>>,
    ) -> Result<Self> {
        // TODO it's unclear what header information id0 types use to parse tils
        // maybe it just use the til sector header, or more likelly it's from
        // IDBParam  in the `Root Node`
        let header = info.til_header();
        let mut reader = data;
        let mut fields_iter = fields
            .into_iter()
            .map(|field| (!field.is_empty()).then(|| IDBString::new(field)));
        let result = Type::read(
            &mut reader,
            &header,
            None,
            &mut fields_iter,
            &mut vec![].into_iter(),
        )?;
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
        #[cfg(feature = "restrictive")]
        ensure!(
            fields_iter.next().is_none(),
            "Extra fields found for id0 til"
        );
        Ok(result)
    }

    pub fn read_ref(
        input: &mut impl IdbRead,
        header: &TILSectionHeader,
    ) -> Result<Self> {
        let mut bytes = input.unpack_dt_bytes()?;

        if !bytes.starts_with(b"=") {
            let dt = serialize_dt(bytes.len().try_into().unwrap())?;
            bytes = [b'='].into_iter().chain(dt).chain(bytes).collect();
        }

        // TODO extract fields and comments?
        let mut bytes = &bytes[..];
        let result = Type::read(
            &mut bytes,
            header,
            None,
            &mut vec![].into_iter(),
            &mut vec![].into_iter(),
        )?;
        #[cfg(feature = "restrictive")]
        ensure!(bytes.is_empty(), "Unable to fully parser Type ref");
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
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
    fn new(
        input: &mut impl IdbBufRead,
        til: &TILSectionHeader,
        bt: u8,
        btmt: u8,
    ) -> Result<Self> {
        let basic = Self::basic_from_value(til, bt, btmt)?;
        if bt != flag::tf_unk::BT_UNK {
            // TODO find the meaning of this value
            let _att =
                input.read_tah().context("Typedef Extended Att")?.flatten();
        }
        Ok(basic)
    }

    fn basic_from_value(
        til: &TILSectionHeader,
        bt: u8,
        btmt: u8,
    ) -> Result<Self> {
        const fn bytes(bytes: u8) -> NonZeroU8 {
            let Some(bytes) = NonZeroU8::new(bytes) else {
                unreachable!()
            };
            bytes
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

#[derive(Clone, Debug, Serialize)]
pub struct Typeref {
    pub ref_type: Option<TyperefType>,
    pub typeref_value: TyperefValue,
}

#[derive(Clone, Debug, Serialize)]
pub enum TyperefValue {
    Name(Option<IDBString>),
    Ordinal(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TyperefType {
    Struct,
    Union,
    Enum,
}

impl Typeref {
    fn read(input: &mut impl IdbBufRead) -> Result<Self> {
        let buf = input.unpack_dt_bytes()?;
        let ref_type = match &buf[..] {
            [b'#', data @ ..] => {
                // InnerRef 66961e377716596c17e2330a28c01eb3600be518 0x2fbf90
                let mut tmp = data;
                let de = tmp.read_de()?;
                if !tmp.is_empty() {
                    return Err(anyhow!(
                        "Typedef Ordinal with more data then expected"
                    ));
                }
                Self {
                    ref_type: None,
                    typeref_value: TyperefValue::Ordinal(de),
                }
            }
            _ => Self {
                ref_type: None,
                typeref_value: TyperefValue::Name(
                    (!buf.is_empty()).then(|| IDBString::new(buf)),
                ),
            },
        };

        // TODO find the meaning of this value
        let _att = input.read_tah().context("Typedef Extended Att")?.flatten();

        Ok(ref_type)
    }

    fn new_struct(mut x: Typeref) -> Self {
        x.ref_type = Some(TyperefType::Struct);
        // TODO check the inner type is in fact a struct
        x
    }

    fn new_union(mut x: Typeref) -> Self {
        x.ref_type = Some(TyperefType::Union);
        // TODO check the inner type is in fact a union
        x
    }

    fn new_enum(mut x: Typeref) -> Self {
        x.ref_type = Some(TyperefType::Enum);
        // TODO check the inner type is in fact a enum
        x
    }
}

#[derive(Debug, Copy, Clone)]
pub enum TILModifier {
    Const,
    Volatile,
}

#[derive(Debug, Clone, Serialize)]
pub struct TILMacro {
    pub name: IDBString,
    pub param_num: Option<u8>,
    pub value: Vec<TILMacroValue>,
}

#[derive(Debug, Clone, Serialize)]
pub enum TILMacroValue {
    // 0x01..=0x7F
    Char(u8),
    // 0x80..0xFF => 0..127
    Param(u8),
}

impl TILMacro {
    fn read(input: &mut impl IdbBufRead) -> Result<Self> {
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
            name: IDBString::new(name),
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

#[derive(Clone, Debug, Serialize)]
pub enum CommentType {
    Unknown5(u32),
    Comment(IDBString),
}
impl CommentType {
    fn from_raw(field: Vec<u8>) -> Result<Option<CommentType>> {
        if field.is_empty() {
            return Ok(None);
        }
        Ok(Some(match field[0] {
            5 if *field.last().unwrap() == b'.' => {
                Self::Unknown5(
                    // TODO base 10 or 16?
                    std::str::from_utf8(&field[1..field.len() - 1])?
                        .parse::<u32>()?,
                )
            }
            cmt_type @ 0..=0x1F => {
                return Err(anyhow!("Unknown comment type {cmt_type:#X}"))
            }
            _ => Self::Comment(IDBString::new(field)),
        }))
    }
}

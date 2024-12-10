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

use std::num::NonZeroU8;

use anyhow::{anyhow, ensure, Context, Result};

use crate::ida_reader::{IdaGenericBufUnpack, IdaGenericUnpack};
use crate::til::array::{Array, ArrayRaw};
use crate::til::bitfield::Bitfield;
use crate::til::function::{Function, FunctionRaw};
use crate::til::pointer::{Pointer, PointerRaw};
use crate::til::r#enum::{Enum, EnumRaw};
use crate::til::r#struct::{Struct, StructRaw};
use crate::til::section::TILSectionHeader;
use crate::til::union::{Union, UnionRaw};

#[derive(Debug, Clone)]
pub struct TILTypeInfo {
    _flags: u32,
    pub name: Vec<u8>,
    pub ordinal: u64,
    pub tinfo: Type,
    _cmt: Vec<u8>,
    _fieldcmts: Vec<u8>,
    _sclass: u8,
}

impl TILTypeInfo {
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
        let result = TILTypeInfo::read_inner(&mut cursor, til)?;
        ensure!(
            cursor.is_empty(),
            "Unable to parse til type fully, left {} bytes",
            cursor.len()
        );
        Ok(result)
    }

    fn read_inner(cursor: &mut &[u8], til: &TILSectionHeader) -> Result<Self> {
        let og_cu = *cursor;
        let flags: u32 = cursor.read_u32()?;
        // TODO verify if flags equal to 0x7fff_fffe?
        let name = cursor.read_c_string_raw()?;
        let is_u64 = (flags >> 31) != 0;
        let ordinal = match (til.format, is_u64) {
            // formats below 0x12 doesn't have 64 bits ord
            (0..=0x11, _) | (_, false) => cursor.read_u32()?.into(),
            (_, true) => cursor.read_u64()?,
        };
        let tinfo_raw = TypeRaw::read(&mut *cursor, til)
            .context("parsing `TILTypeInfo::tiinfo`")
            .inspect_err(|e| {
                println!(
                    "Error: {}: {e:?}\n{og_cu:02x?}",
                    core::str::from_utf8(&name).unwrap()
                );
            })?;
        let _info = cursor.read_c_string_raw()?;
        let cmt = cursor.read_c_string_raw()?;
        let fields = cursor.read_c_string_vec()?;
        let fieldcmts = cursor.read_c_string_raw()?;
        let sclass: u8 = cursor.read_u8()?;

        let tinfo = Type::new(til, tinfo_raw, Some(fields))?;

        Ok(Self {
            _flags: flags,
            name,
            ordinal,
            tinfo,
            _cmt: cmt,
            _fieldcmts: fieldcmts,
            _sclass: sclass,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Type {
    Basic(Basic),
    Pointer(Pointer),
    Function(Function),
    Array(Array),
    Typedef(Typedef),
    Struct(Struct),
    Union(Union),
    Enum(Enum),
    Bitfield(Bitfield),
}
impl Type {
    pub(crate) fn new(
        til: &TILSectionHeader,
        tinfo_raw: TypeRaw,
        fields: Option<Vec<Vec<u8>>>,
    ) -> Result<Self> {
        match tinfo_raw {
            TypeRaw::Basic(x) => {
                if let Some(fields) = fields {
                    ensure!(fields.is_empty(), "Basic type with fields");
                }
                Ok(Type::Basic(x))
            }
            TypeRaw::Bitfield(x) => {
                if matches!(fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Bitfield"));
                }
                Ok(Type::Bitfield(x))
            }
            TypeRaw::Typedef(x) => {
                if matches!(fields, Some(f) if !f.is_empty()) {
                    return Err(anyhow!("fields in a Typedef"));
                }
                Ok(Type::Typedef(x))
            }
            TypeRaw::Pointer(x) => Pointer::new(til, x, fields).map(Type::Pointer),
            TypeRaw::Function(x) => Function::new(til, x, fields).map(Type::Function),
            TypeRaw::Array(x) => Array::new(til, x, fields).map(Type::Array),
            TypeRaw::Struct(x) => Struct::new(til, x, fields).map(Type::Struct),
            TypeRaw::Union(x) => Union::new(til, x, fields).map(Type::Union),
            TypeRaw::Enum(x) => Enum::new(til, x, fields).map(Type::Enum),
        }
    }
    // TODO find the best way to handle type parsing from id0
    pub(crate) fn new_from_id0(data: &[u8], fields: Option<Vec<Vec<u8>>>) -> Result<Self> {
        // TODO it's unclear what header information id0 types use to parse tils
        // maybe it just use the til sector header, or more likelly it's from
        // IDBParam  in the `Root Node`
        let header = section::TILSectionHeader {
            format: 12,
            flags: section::TILSectionFlags(0),
            title: Vec::new(),
            description: Vec::new(),
            compiler_id: 0,
            cm: 0,
            size_enum: None,
            size_int: 4.try_into().unwrap(),
            size_bool: 1.try_into().unwrap(),
            def_align: 0,
            size_long_double: None,
            size_short: 2.try_into().unwrap(),
            size_long: 4.try_into().unwrap(),
            size_long_long: 8.try_into().unwrap(),
        };
        let mut reader = data;
        let type_raw = TypeRaw::read(&mut reader, &header)?;
        match reader {
            // all types end with \x00, unknown if it have any meaning
            &[b'\x00'] => {}
            // in continuations, the \x00 may be missing
            &[] => {}
            rest => {
                return Err(anyhow!(
                    "Extra {} bytes after reading TIL from ID0",
                    rest.len()
                ));
            }
        }
        Self::new(&header, type_raw, fields)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum TypeRaw {
    Basic(Basic),
    Pointer(PointerRaw),
    Function(FunctionRaw),
    Array(ArrayRaw),
    Typedef(Typedef),
    Struct(StructRaw),
    Union(UnionRaw),
    Enum(EnumRaw),
    Bitfield(Bitfield),
}

impl TypeRaw {
    pub fn read(input: &mut impl IdaGenericBufUnpack, til: &TILSectionHeader) -> Result<Self> {
        let metadata: u8 = input.read_u8()?;
        let type_base = metadata & flag::tf_mask::TYPE_BASE_MASK;
        let type_flags = metadata & flag::tf_mask::TYPE_FLAGS_MASK;

        // TODO find if this apply to all fields, or only a selected few?
        // TODO some fields can be both CONST and VOLATILE at the same time, what that means?
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x473084 print_til_type
        let _is_const = metadata & flag::tf_modifiers::BTM_CONST != 0;
        let _is_volatile = metadata & flag::tf_modifiers::BTM_VOLATILE != 0;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480335
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x472e13 print_til_type
        match (type_base, type_flags) {
            (..=flag::tf_last_basic::BT_LAST_BASIC, _) => {
                Basic::new(til, type_base, type_flags).map(TypeRaw::Basic)
            }
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4804d7
            (flag::tf_ptr::BT_PTR, _) => PointerRaw::read(input, til, type_flags)
                .context("Type::Pointer")
                .map(TypeRaw::Pointer),

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x48075a
            (flag::tf_array::BT_ARRAY, _) => ArrayRaw::read(input, til, type_flags)
                .context("Type::Array")
                .map(TypeRaw::Array),

            (flag::tf_func::BT_FUNC, _) => FunctionRaw::read(input, til, type_flags)
                .context("Type::Function")
                .map(TypeRaw::Function),

            (flag::tf_complex::BT_BITFIELD, _) => Ok(TypeRaw::Bitfield(
                Bitfield::read(input, type_flags).context("Type::Bitfield")?,
            )),

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480369

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480369
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_TYPEDEF) => Typedef::read(input)
                .context("Type::Typedef")
                .map(TypeRaw::Typedef),

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x480378

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_UNION) => {
                UnionRaw::read(input, til)
                    .context("Type::Union")
                    .map(TypeRaw::Union)
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4808f9
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_STRUCT) => {
                StructRaw::read(input, til)
                    .context("Type::Struct")
                    .map(TypeRaw::Struct)
            }

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x4803b4
            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_ENUM) => {
                EnumRaw::read(input, til)
                    .context("Type::Enum")
                    .map(TypeRaw::Enum)
            }

            (flag::tf_complex::BT_COMPLEX, _) => unreachable!(),

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x47395d print_til_type
            (flag::BT_RESERVED, _) => Err(anyhow!("Wrong/Unknown type: {metadata:02x}")),

            (flag::BT_RESERVED.., _) => unreachable!(),
        }
    }

    pub fn read_ref(input: &mut impl IdaGenericUnpack, header: &TILSectionHeader) -> Result<Self> {
        let mut bytes = input.unpack_dt_bytes()?;

        if !bytes.starts_with(b"=") {
            let dt = serialize_dt(bytes.len().try_into().unwrap())?;
            bytes = [b'='].into_iter().chain(dt).chain(bytes).collect();
        }

        let mut bytes = &bytes[..];
        let result = TypeRaw::read(&mut bytes, header)?;
        if !bytes.is_empty() {
            return Err(anyhow!("Unable to fully parser Type ref"));
        }
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

    Bool {
        bytes: NonZeroU8,
    },
    Char,
    SegReg,
    Int {
        bytes: NonZeroU8,
        is_signed: Option<bool>,
    },
    Float {
        bytes: NonZeroU8,
    },
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
                    BTMT_SIZE0 => return Err(anyhow!("forbidden use of BT_UNK")),
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
                            _ => Err(anyhow!("Reserved use of tf_int::BTMT_CHAR {:x}", btmt)),
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
                    BT_INT => til.size_int,
                    _ => unreachable!(),
                };
                Ok(Self::Int { bytes, is_signed })
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
                Ok(Self::Bool { bytes })
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
pub enum Typedef {
    Ordinal(u32),
    Name(Vec<u8>),
}

impl Typedef {
    fn read(input: &mut impl IdaGenericUnpack) -> Result<Self> {
        let buf = input.unpack_dt_bytes()?;
        match &buf[..] {
            [b'#', data @ ..] => {
                let mut tmp = data;
                let de = tmp.read_de()?;
                if !tmp.is_empty() {
                    return Err(anyhow!("Typedef Ordinal with more data then expected"));
                }
                Ok(Typedef::Ordinal(de))
            }
            _ => Ok(Typedef::Name(buf)),
        }
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
    pub value: Vec<u8>,
}

impl TILMacro {
    fn read(input: &mut impl IdaGenericBufUnpack) -> Result<Self> {
        let name = input.read_c_string_raw()?;
        // TODO find what this is
        let _flag: u16 = input.read_u16()?;
        let value = input.read_c_string_raw()?;
        Ok(Self { name, value })
    }
}

#[derive(Clone, Default, Debug)]
pub struct TypeMetadata(pub u8);
impl TypeMetadata {
    fn new(value: u8) -> Self {
        // TODO check for invalid values
        Self(value)
    }
    fn read(input: &mut impl IdaGenericUnpack) -> Result<Self> {
        Ok(Self::new(input.read_u8()?))
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

#[derive(Clone, Copy, Debug)]
pub struct TypeAttribute(pub u16);
impl TypeAttribute {
    // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452830
    fn read(input: &mut impl IdaGenericUnpack) -> Result<Self> {
        let byte0: u8 = input.read_u8()?;
        let mut val = 0;
        if byte0 != 0xfe {
            val = ((byte0 as u16 & 1) | ((byte0 as u16 >> 3) & 6)) + 1;
        }
        if byte0 == 0xFE || val == 8 {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452878
            let mut shift = 0;
            // TODO limit the loop to only 0..n
            loop {
                let next_byte: u8 = input.read_u8()?;
                ensure!(
                    next_byte != 0,
                    "Failed to parse TypeAttribute, byte is zero"
                );
                val |= ((next_byte & 0x7F) as u16) << shift;
                if next_byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
        }

        if val & 0x10 == 0 {
            return Ok(TypeAttribute(val));
        }

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x45289e
        let loop_cnt = input.read_dt()?;
        for _ in 0..loop_cnt {
            let _string = input.unpack_dt_bytes()?;
            let _other_thing = input.unpack_dt_bytes()?;
            // TODO maybe more...
        }
        Ok(TypeAttribute(val))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TAH(pub TypeAttribute);
impl TAH {
    fn read(input: &mut impl IdaGenericBufUnpack) -> Result<Self> {
        // TODO TAH in each type have a especial meaning, verify those
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x477080
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x452830
        let Some(tah) = input.fill_buf()?.first().copied() else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on DA"
            )));
        };
        if tah == 0xFE {
            Ok(Self(TypeAttribute::read(input)?))
        } else {
            Ok(Self(TypeAttribute(0)))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SDACL(pub TypeAttribute);
impl SDACL {
    fn read(input: &mut impl IdaGenericBufUnpack) -> Result<Self> {
        let Some(sdacl) = input.fill_buf()?.first().copied() else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on SDACL"
            )));
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x477eff
        match sdacl {
            //NOTE: original op ((sdacl & 0xcf) ^ 0xC0) <= 0x01
            0xd0..=0xff | 0xc0 | 0xc1 => Ok(Self(TypeAttribute::read(input)?)),
            _ => Ok(Self(TypeAttribute(0))),
        }
    }
}

impl CallingConventionFlag {
    fn is_spoiled(&self) -> bool {
        self.0 == 0xA0
    }

    fn is_void_arg(&self) -> bool {
        self.0 == 0x20
    }

    fn is_special_pe(&self) -> bool {
        self.0 == 0xD0 || self.0 == 0xE0 || self.0 == 0xF0
    }
}

impl TypeMetadata {
    pub fn get_base_type_flag(&self) -> BaseTypeFlag {
        BaseTypeFlag(self.0 & flag::tf_mask::TYPE_BASE_MASK)
    }

    pub fn get_full_type_flag(&self) -> FullTypeFlag {
        FullTypeFlag(self.0 & flag::tf_mask::TYPE_FULL_MASK)
    }

    pub fn get_type_flag(&self) -> TypeFlag {
        TypeFlag(self.0 & flag::tf_mask::TYPE_FLAGS_MASK)
    }

    pub fn get_calling_convention(&self) -> CallingConventionFlag {
        CallingConventionFlag(self.0 & 0xF0)
    }
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

fn associate_field_name_and_member<T>(
    fields: Option<Vec<Vec<u8>>>,
    members: Vec<T>,
) -> Result<impl Iterator<Item = (Option<Vec<u8>>, T)>> {
    let fields_len: usize = fields.iter().filter(|t| !t.is_empty()).count();
    ensure!(fields_len <= members.len(), "More fields then members");
    // allow to have fewer fields then members, first fields will have names, others not
    Ok(fields
        .into_iter()
        .flat_map(Vec::into_iter)
        .map(Some)
        .chain(std::iter::repeat(None))
        .zip(members))
}

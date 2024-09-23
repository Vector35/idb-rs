pub mod array;
pub mod bitfield;
pub mod r#enum;
/// The u8 values used to describes the type information records in IDA.
///
/// The recommended way of using type info is to use the [tinfo_t] class.
/// The type information is internally kept as an array of bytes terminated by 0.
///
/// Items in brackets [] are optional and sometimes are omitted.
/// ::type_t... means a sequence of ::type_t bytes which defines a type.
///
/// NOTE: to work with the types of instructions or data in the database,
/// use `get_tinfo()`/`set_tinfo()` and similar functions.
pub mod flag;
pub mod function;
pub mod pointer;
pub mod section;
pub mod r#struct;
pub mod union;

use std::io::{BufRead, Read};
use std::num::NonZeroU8;

use anyhow::{anyhow, ensure, Context, Result};

use crate::til::array::{Array, ArrayRaw};
use crate::til::bitfield::Bitfield;
use crate::til::function::{Function, FunctionRaw};
use crate::til::pointer::{Pointer, PointerRaw};
use crate::til::r#enum::{Enum, EnumRaw};
use crate::til::r#struct::{Struct, StructRaw};
use crate::til::section::TILSectionHeader;
use crate::til::union::{Union, UnionRaw};
use crate::{read_c_string, read_c_string_vec};

#[derive(Debug, Clone)]
pub struct TILTypeInfo {
    _flags: u32,
    pub name: String,
    pub ordinal: u64,
    pub tinfo: Type,
    _cmt: String,
    _fieldcmts: String,
    _sclass: u8,
}

impl TILTypeInfo {
    pub(crate) fn read<I: BufRead>(input: &mut I, til: &TILSectionHeader) -> Result<Self> {
        let flags: u32 = bincode::deserialize_from(&mut *input)?;
        let name = read_c_string(&mut *input)?;
        let is_u64 = (flags >> 31) != 0;
        let ordinal = match (til.format, is_u64) {
            // formats below 0x12 doesn't have 64 bits ord
            (0..=0x11, _) | (_, false) => bincode::deserialize_from::<_, u32>(&mut *input)?.into(),
            (_, true) => bincode::deserialize_from(&mut *input)?,
        };
        let tinfo_raw = TypeRaw::read(&mut *input, til).context("parsing `TILTypeInfo::tiinfo`")?;
        let _info = read_c_string(&mut *input)?;
        let cmt = read_c_string(&mut *input)?;
        let fields = read_c_string_vec(&mut *input)?;
        let fieldcmts = read_c_string(&mut *input)?;
        let sclass: u8 = bincode::deserialize_from(&mut *input)?;

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
        fields: Option<Vec<String>>,
    ) -> Result<Self> {
        match tinfo_raw {
            TypeRaw::Basic(x) => {
                if let Some(fields) = fields {
                    ensure!(fields.is_empty(), "Unset with fields");
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
    pub(crate) fn new_from_id0(data: &[u8]) -> Result<Self> {
        // TODO it's unclear what header information id0 types use to parse tils
        // maybe it just use the til sector header, or more likelly it's from
        // IDBParam  in the `Root Node`
        let header = section::TILSectionHeader {
            format: 700,
            flags: section::TILSectionFlag(0),
            title: String::new(),
            description: String::new(),
            id: 0,
            cm: 0,
            size_enum: 0,
            size_i: 4.try_into().unwrap(),
            size_b: 1.try_into().unwrap(),
            def_align: 0,
            size_s_l_ll: None,
            size_long_double: None,
        };
        let mut reader = data;
        let type_raw = TypeRaw::read(&mut reader, &header)?;
        match reader {
            //
            &[] => {}
            // for some reason there is an \x00 at the end???
            &[b'\x00'] => {}
            rest => {
                return Err(anyhow!(
                    "Extra {} bytes after reading TIL from ID0",
                    rest.len()
                ))
            }
        }
        Self::new(&header, type_raw, None)
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
    pub fn read<I: BufRead>(input: &mut I, til: &TILSectionHeader) -> Result<Self> {
        let metadata: u8 = bincode::deserialize_from(&mut *input)?;
        let type_base = metadata & flag::tf_mask::TYPE_BASE_MASK;
        let type_flags = metadata & flag::tf_mask::TYPE_FLAGS_MASK;
        match (type_base, type_flags) {
            (flag::BT_RESERVED, _) => Err(anyhow!("Reserved Basic Type")),
            (..=flag::tf_last_basic::BT_LAST_BASIC, _) => {
                Basic::new(til, type_base, type_flags).map(TypeRaw::Basic)
            }
            (flag::tf_ptr::BT_PTR, _) => PointerRaw::read(input, til, type_flags)
                .context("Type::Pointer")
                .map(TypeRaw::Pointer),

            (flag::tf_func::BT_FUNC, _) => FunctionRaw::read(input, til, type_flags)
                .context("Type::Function")
                .map(TypeRaw::Function),

            (flag::tf_array::BT_ARRAY, _) => ArrayRaw::read(input, til, type_flags)
                .context("Type::Array")
                .map(TypeRaw::Array),

            (flag::tf_complex::BT_BITFIELD, _) => Ok(TypeRaw::Bitfield(
                Bitfield::read(input, metadata).context("Type::Bitfield")?,
            )),

            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_TYPEDEF) => Typedef::read(input)
                .context("Type::Typedef")
                .map(TypeRaw::Typedef),

            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_UNION) => {
                UnionRaw::read(input, til)
                    .context("Type::Union")
                    .map(TypeRaw::Union)
            }

            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_STRUCT) => {
                StructRaw::read(input, til)
                    .context("Type::Struct")
                    .map(TypeRaw::Struct)
            }

            (flag::tf_complex::BT_COMPLEX, flag::tf_complex::BTMT_ENUM) => {
                EnumRaw::read(input, til)
                    .context("Type::Enum")
                    .map(TypeRaw::Enum)
            }
            _ => todo!(),
        }
    }

    pub fn read_ref<I: BufRead>(input: &mut I, header: &TILSectionHeader) -> Result<Self> {
        let mut bytes = read_dt_bytes(&mut *input)?;

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
        match bt {
            BT_VOID => {
                let bytes = match btmt {
                    // special case, void
                    BTMT_SIZE0 => return Ok(Self::Void),
                    BTMT_SIZE12 => 1,
                    BTMT_SIZE48 => 4,
                    BTMT_SIZE128 => 16,
                    _ => unreachable!(),
                };
                Ok(Self::Unknown { bytes })
            }
            BT_UNK => {
                let bytes = match btmt {
                    BTMT_SIZE0 => return Err(anyhow!("forbidden use of BT_UNK")),
                    BTMT_SIZE12 => 2,
                    BTMT_SIZE48 => 8,
                    BTMT_SIZE128 => 0,
                    _ => unreachable!(),
                };
                Ok(Self::Unknown { bytes })
            }

            bt_int @ BT_INT8..=BT_INT => {
                let is_signed = match btmt {
                    BTMT_UNKSIGN => None,
                    BTMT_SIGNED => Some(true),
                    BTMT_UNSIGNED => Some(false),
                    // special case for char
                    BTMT_CHAR => {
                        return match bt_int {
                            BT_INT8 => Ok(Self::Char),
                            BT_INT => Ok(Self::SegReg),
                            _ => Err(anyhow!("Reserved use of tf_int::BTMT_CHAR {:x}", btmt)),
                        }
                    }
                    _ => unreachable!(),
                };
                let bytes = match bt_int {
                    BT_INT8 => bytes(1),
                    BT_INT16 => bytes(2),
                    BT_INT32 => bytes(4),
                    BT_INT64 => bytes(8),
                    BT_INT128 => bytes(16),
                    BT_INT => til.size_i,
                    _ => unreachable!(),
                };
                Ok(Self::Int { bytes, is_signed })
            }

            BT_BOOL => {
                let bytes = match btmt {
                    BTMT_DEFBOOL => til.size_b,
                    BTMT_BOOL1 => bytes(1),
                    BTMT_BOOL4 => bytes(4),
                    // TODO get the inf_is_64bit  field
                    //BTMT_BOOL2 if !inf_is_64bit => Some(bytes(2)),
                    //BTMT_BOOL8 if inf_is_64bit => Some(bytes(8)),
                    BTMT_BOOL8 => bytes(2), // delete this
                    _ => unreachable!(),
                };
                Ok(Self::Bool { bytes })
            }

            BT_FLOAT => {
                let bytes = match btmt {
                    BTMT_FLOAT => bytes(4),
                    BTMT_DOUBLE => bytes(8),
                    // TODO error if none?
                    BTMT_LNGDBL => til.size_long_double.unwrap_or(bytes(8)),
                    // TODO find the tbyte_size field
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
    Name(String),
}

impl Typedef {
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let buf = read_dt_bytes(&mut *input)?;
        match &buf[..] {
            [b'#', data @ ..] => {
                let mut tmp = std::io::Cursor::new(data);
                let de = read_de(&mut tmp)?;
                if tmp.position() != data.len().try_into()? {
                    return Err(anyhow!("Typedef Ordinal with more data then expected"));
                }
                Ok(Typedef::Ordinal(de))
            }
            _ => Ok(Typedef::Name(String::from_utf8(buf)?)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TILMacro {
    pub name: String,
    pub value: String,
}

impl TILMacro {
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let name = read_c_string(&mut *input)?;
        // TODO find what this is
        let _flag: u16 = bincode::deserialize_from(&mut *input)?;
        let value = read_c_string(&mut *input)?;
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
    fn read<I: Read>(input: I) -> Result<Self> {
        Ok(Self::new(bincode::deserialize_from(input)?))
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
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let mut val: u16 = 0;
        let tah: u8 = bincode::deserialize_from(&mut *input)?;
        let tmp = ((tah & 1) | ((tah >> 3) & 6)) + 1;
        if tah == 0xFE || tmp == 8 {
            if tmp == 8 {
                val = tmp as u16;
            }
            let mut shift = 0;
            loop {
                let next_byte: u8 = bincode::deserialize_from(&mut *input)?;
                if next_byte == 0 {
                    return Err(anyhow!("Failed to parse TypeAttribute"));
                }
                val |= ((next_byte & 0x7F) as u16) << shift;
                if next_byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
        }
        if (val & 0x0010) > 0 {
            val = read_dt(&mut *input)?;
            for _ in 0..val {
                let _string = read_dt_string(&mut *input)?;
                let another_de = read_dt(&mut *input)?;
                let mut other_string = vec![0; another_de.into()];
                input.read_exact(&mut other_string)?;
            }
        }
        Ok(TypeAttribute(val))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TAH(pub TypeAttribute);
impl TAH {
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
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
    fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let Some(sdacl) = input.fill_buf()?.first().copied() else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on SDACL"
            )));
        };
        if ((sdacl & !0x30) ^ 0xC0) <= 0x01 {
            Ok(Self(TypeAttribute::read(input)?))
        } else {
            Ok(Self(TypeAttribute(0)))
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

fn read_dt_bytes<I: BufRead>(input: &mut I) -> Result<Vec<u8>> {
    let buf_len = read_dt(&mut *input)?;
    let mut buf = vec![0; buf_len.into()];
    input.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_dt_string<I: BufRead>(input: &mut I) -> Result<String> {
    let buf = read_dt_bytes(input)?;
    Ok(String::from_utf8(buf)?)
}

/// Reads 1 to 5 bytes
/// Value Range: 0-0xFFFFFFFF
/// Usage: Enum Deltas
fn read_de<I: Read>(input: &mut I) -> std::io::Result<u32> {
    let mut val: u32 = 0;
    for _ in 0..5 {
        let mut hi = val << 6;
        let mut b = [0; 1];
        input.read_exact(&mut b)?;
        let b: u32 = b[0].into();
        let sign = b & 0x80;
        if sign == 0 {
            let lo = b & 0x3F;
            val = lo | hi;
            return Ok(val);
        } else {
            let lo = 2 * hi;
            hi = b & 0x7F;
            val = lo | hi;
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Can't find the end of DE",
    ))
}

/// Reads 1 or 2 bytes.
/// Value Range: 0-0xFFFE
/// Usage: 16bit numbers
fn read_dt<I: Read>(input: &mut I) -> std::io::Result<u16> {
    let mut value = [0u8; 1];
    input.read_exact(&mut value)?;
    let value = value[0].into();

    let value = match value {
        0 => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DT can't have 0 value",
            ))
        }
        //SEG = 2
        value if value & 0x80 != 0 => {
            let mut iter = [0u8; 1];
            input.read_exact(&mut iter)?;
            let inter: u16 = iter[0].into();
            value & 0x7F | inter << 7
        }
        //SEG = 1
        _ => value,
    };
    Ok(value - 1)
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

/// Reads 1 to 9 bytes.
/// ValueRange: 0-0x7FFFFFFF, 0-0xFFFFFFFF
/// Usage: Arrays
fn read_da<I: BufRead>(input: &mut I) -> Result<(u8, u8)> {
    let mut a = 0;
    let mut b = 0;
    let mut da = 0;
    let mut base = 0;
    let mut nelem = 0;
    // TODO check no more then 9 bytes are read
    loop {
        let Some(typ) = input.fill_buf()?.first().copied() else {
            return Err(anyhow!(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EoF on DA"
            )));
        };
        if typ & 0x80 == 0 {
            break;
        }
        input.consume(1);

        da = (da << 7) | typ & 0x7F;
        b += 1;
        if b >= 4 {
            let z: u8 = bincode::deserialize_from(&mut *input)?;
            if z != 0 {
                base = (da << 4) | z & 0xF
            }
            nelem = (z >> 4) & 7;
            loop {
                let Some(y) = input.fill_buf()?.first().copied() else {
                    return Err(anyhow!(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Unexpected EoF on DA"
                    )));
                };
                if (y & 0x80) == 0 {
                    break;
                }
                input.consume(1);
                nelem = (nelem << 7) | y & 0x7F;
                a += 1;
                if a >= 4 {
                    return Ok((nelem, base));
                }
            }
        }
    }
    Ok((nelem, base))
}

/// Reads 2 to 7 bytes.
/// Value Range: Nothing or 0-0xFFFF_FFFF
/// Usage: some kind of size
fn read_dt_de<I: Read>(input: &mut I) -> std::io::Result<Option<u32>> {
    match read_dt(&mut *input)? {
        0 => Ok(None),
        0x7FFE => read_de(&mut *input).map(Some),
        n => Ok(Some(n.into())),
    }
}

fn associate_field_name_and_member<T>(
    fields: Option<Vec<String>>,
    members: Vec<T>,
) -> Result<impl Iterator<Item = (Option<String>, T)>> {
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

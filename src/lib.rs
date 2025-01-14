#[forbid(unsafe_code)]
pub mod id0;
pub mod id1;
pub(crate) mod ida_reader;
pub mod nam;
pub mod til;

use std::borrow::Cow;
use std::fmt::Debug;
use std::fmt::Write;
use std::io::SeekFrom;
use std::num::NonZeroU64;

use id0::ID0Section;
use ida_reader::IdaGenericUnpack;
use ida_reader::IdbReader;
use serde::Deserialize;

use crate::id1::ID1Section;
use crate::nam::NamSection;
use crate::til::section::TILSection;
use anyhow::{anyhow, ensure, Result};

#[derive(Debug, Clone, Copy)]
pub struct IDBParser<I> {
    input: I,
    header: IDBHeader,
}

trait Sealed {}
#[allow(private_bounds)]
pub trait IDBOffset: Sealed {
    fn idb_offset(&self) -> u64;
}

macro_rules! impl_idb_offset {
    ($name:ident) => {
        impl Sealed for $name {}
        impl IDBOffset for $name {
            fn idb_offset(&self) -> u64 {
                self.0.get()
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID0Offset(NonZeroU64);
impl_idb_offset!(ID0Offset);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID1Offset(NonZeroU64);
impl_idb_offset!(ID1Offset);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamOffset(NonZeroU64);
impl_idb_offset!(NamOffset);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TILOffset(NonZeroU64);
impl_idb_offset!(TILOffset);

impl<I: IdbReader> IDBParser<I> {
    pub fn new(mut input: I) -> Result<Self> {
        let header = IDBHeader::read(&mut input)?;
        Ok(Self { input, header })
    }

    pub fn id0_section_offset(&self) -> Option<ID0Offset> {
        self.header.id0_offset.map(ID0Offset)
    }

    pub fn id1_section_offset(&self) -> Option<ID1Offset> {
        self.header.id1_offset.map(ID1Offset)
    }

    pub fn nam_section_offset(&self) -> Option<NamOffset> {
        self.header.nam_offset.map(NamOffset)
    }

    pub fn til_section_offset(&self) -> Option<TILOffset> {
        self.header.til_offset.map(TILOffset)
    }

    pub fn read_id0_section(&mut self, id0: ID0Offset) -> Result<ID0Section> {
        read_section(
            &mut self.input,
            &self.header,
            id0.0.get(),
            ID0Section::read,
        )
    }

    pub fn read_id1_section(&mut self, id1: ID1Offset) -> Result<ID1Section> {
        read_section(
            &mut self.input,
            &self.header,
            id1.0.get(),
            ID1Section::read,
        )
    }

    pub fn read_nam_section(&mut self, nam: NamOffset) -> Result<NamSection> {
        read_section(
            &mut self.input,
            &self.header,
            nam.0.get(),
            NamSection::read,
        )
    }

    pub fn read_til_section(&mut self, til: TILOffset) -> Result<TILSection> {
        read_section(
            &mut self.input,
            &self.header,
            til.0.get(),
            |input, _header, compressed| TILSection::read(input, compressed),
        )
    }

    pub fn decompress_section(
        &mut self,
        offset: impl IDBOffset,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        self.input.seek(SeekFrom::Start(offset.idb_offset()))?;
        let section_header =
            IDBSectionHeader::read(&self.header, &mut self.input)?;
        // makes sure the reader doesn't go out-of-bounds
        let mut input =
            std::io::Read::take(&mut self.input, section_header.len);
        match section_header.compress {
            IDBSectionCompression::Zlib => {
                let mut input = flate2::bufread::ZlibDecoder::new(input);
                let _ = std::io::copy(&mut input, output)?;
            }
            IDBSectionCompression::None => {
                let _ = std::io::copy(&mut input, output)?;
            }
        }
        Ok(())
    }

    pub fn decompress_til_section(
        &mut self,
        til: TILOffset,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        self.input.seek(SeekFrom::Start(til.0.get()))?;
        let section_header =
            IDBSectionHeader::read(&self.header, &mut self.input)?;
        // makes sure the reader doesn't go out-of-bounds
        let mut input =
            std::io::Read::take(&mut self.input, section_header.len);
        TILSection::decompress(&mut input, output, section_header.compress)
    }
}

fn read_section<'a, I, T, F>(
    input: &'a mut I,
    header: &IDBHeader,
    offset: u64,
    mut process: F,
) -> Result<T>
where
    I: IdbReader,
    F: FnMut(
        &mut std::io::Take<&'a mut I>,
        &IDBHeader,
        IDBSectionCompression,
    ) -> Result<T>,
{
    input.seek(SeekFrom::Start(offset))?;
    let section_header = IDBSectionHeader::read(header, &mut *input)?;
    // makes sure the reader doesn't go out-of-bounds
    let mut input = std::io::Read::take(input, section_header.len);
    let result = process(&mut input, header, section_header.compress)?;

    // TODO seems its normal to have a few extra bytes at the end of the sector, maybe
    // because of the compressions stuff, anyway verify that
    ensure!(
        if matches!(section_header.compress, IDBSectionCompression::None) {
            input.limit() == 0
        } else {
            input.limit() <= 16
        },
        "Sector have more data then expected, left {} bytes",
        input.limit()
    );
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBMagic {
    IDA0,
    IDA1,
    IDA2,
}

impl TryFrom<[u8; 4]> for IDBMagic {
    type Error = anyhow::Error;

    fn try_from(value: [u8; 4]) -> Result<Self, Self::Error> {
        match &value {
            b"IDA0" => Ok(IDBMagic::IDA0),
            b"IDA1" => Ok(IDBMagic::IDA1),
            b"IDA2" => Ok(IDBMagic::IDA2),
            _ => Err(anyhow!("Invalid IDB Magic number")),
        }
    }
}

impl IDBMagic {
    fn is_64(&self) -> bool {
        match self {
            IDBMagic::IDA0 | IDBMagic::IDA1 => false,
            IDBMagic::IDA2 => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBVersion {
    // TODO add other versions
    V1,
    V4,
    V5,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeader {
    magic_version: IDBMagic,
    version: IDBVersion,
    id0_offset: Option<NonZeroU64>,
    id1_offset: Option<NonZeroU64>,
    nam_offset: Option<NonZeroU64>,
    til_offset: Option<NonZeroU64>,
    checksums: [u32; 3],
    unk0_checksum: u32,
    data: IDBHeaderVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBHeaderVersion {
    V1 {
        seg_offset: Option<NonZeroU64>,
    },
    V4 {
        seg_offset: Option<NonZeroU64>,
    },
    V5 {
        unk16: u32,
        unk1_checksum: u32,
    },
    V6 {
        unk16: u32,
        id2_offset: Option<NonZeroU64>,
        unk1_checksum: u32,
    },
}

#[derive(Debug, Clone, Copy)]
struct IDBSectionHeader {
    compress: IDBSectionCompression,
    len: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum IDBSectionCompression {
    None = 0,
    Zlib = 2,
}

impl TryFrom<u8> for IDBSectionCompression {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            2 => Ok(Self::Zlib),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct IDBHeaderRaw {
    magic: [u8; 4],
    _padding_0: u16,
    offsets: [u32; 5],
    signature: u32,
    version: u16,
    // more, depending on the version
}

impl IDBHeader {
    pub fn read(mut input: impl IdaGenericUnpack) -> Result<Self> {
        let header_raw: IDBHeaderRaw = bincode::deserialize_from(&mut input)?;
        let magic = IDBMagic::try_from(header_raw.magic)?;
        ensure!(
            header_raw.signature == 0xAABB_CCDD,
            "Invalid header signature {:#x}",
            header_raw.signature
        );
        // TODO associate header.version and magic?
        match header_raw.version {
            1 => Self::read_v1(&header_raw, magic, input),
            4 => Self::read_v4(&header_raw, magic, input),
            5 => Self::read_v5(&header_raw, magic, input),
            6 => Self::read_v6(&header_raw, magic, input),
            v => Err(anyhow!("Unable to parse version `{v}`")),
        }
    }

    fn read_v1(
        header_raw: &IDBHeaderRaw,
        magic: IDBMagic,
        input: impl IdaGenericUnpack,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V1Raw {
            _id2_offset: u32,
            checksums: [u32; 3],
            _unk30_zeroed: u32,
            unk33_checksum: u32,
        }

        let v1_raw: V1Raw = bincode::deserialize_from(input)?;
        #[cfg(feature = "restrictive")]
        {
            ensure!(v1_raw._unk30_zeroed == 0, "unk30 not zeroed");
            ensure!(v1_raw._id2_offset == 0, "id2 in V1 is not zeroed");
        }
        // TODO ensure all offsets point to after the header

        Ok(Self {
            magic_version: magic,
            version: IDBVersion::V1,
            id0_offset: NonZeroU64::new(header_raw.offsets[0].into()),
            id1_offset: NonZeroU64::new(header_raw.offsets[1].into()),
            nam_offset: NonZeroU64::new(header_raw.offsets[2].into()),
            til_offset: NonZeroU64::new(header_raw.offsets[4].into()),
            checksums: v1_raw.checksums,
            unk0_checksum: v1_raw.unk33_checksum,
            data: IDBHeaderVersion::V1 {
                seg_offset: NonZeroU64::new(header_raw.offsets[3].into()),
            },
        })
    }

    fn read_v4(
        header_raw: &IDBHeaderRaw,
        magic: IDBMagic,
        input: impl IdaGenericUnpack,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V4Raw {
            _id2_offset: u32,
            checksums: [u32; 3],
            _unk30_zeroed: u32,
            unk33_checksum: u32,
            _unk38_zeroed: [u8; 8],
            _unk40_v5c: u32,
        }

        let v4_raw: V4Raw = bincode::deserialize_from(input)?;

        #[cfg(feature = "restrictive")]
        {
            ensure!(v4_raw._unk30_zeroed == 0, "unk30 not zeroed");
            ensure!(v4_raw._id2_offset == 0, "id2 in V4 is not zeroed");
            ensure!(v4_raw._unk38_zeroed == [0; 8], "unk38 is not zeroed");
            ensure!(v4_raw._unk40_v5c == 0x5c, "unk40 is not 0x5C");
        }
        // TODO ensure all offsets point to after the header

        Ok(Self {
            magic_version: magic,
            version: IDBVersion::V4,
            id0_offset: NonZeroU64::new(header_raw.offsets[0].into()),
            id1_offset: NonZeroU64::new(header_raw.offsets[1].into()),
            nam_offset: NonZeroU64::new(header_raw.offsets[2].into()),
            til_offset: NonZeroU64::new(header_raw.offsets[4].into()),
            checksums: v4_raw.checksums,
            unk0_checksum: v4_raw.unk33_checksum,
            data: IDBHeaderVersion::V4 {
                seg_offset: NonZeroU64::new(header_raw.offsets[3].into()),
            },
        })
    }

    fn read_v5(
        header_raw: &IDBHeaderRaw,
        magic: IDBMagic,
        input: impl IdaGenericUnpack,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V5Raw {
            nam_offset: u64,
            _seg_offset_zeroed: u64,
            til_offset: u64,
            initial_checksums: [u32; 3],
            _unk4_zeroed: u32,
            unk_checksum: u32,
            _id2_offset_zeroed: u64,
            final_checksum: u32,
            _unk0_v7c: u32,
        }
        let v5_raw: V5Raw = bincode::deserialize_from(input)?;
        let id0_offset = u64::from_le(
            u64::from(header_raw.offsets[1]) << 32
                | u64::from(header_raw.offsets[0]),
        );
        let id1_offset = u64::from_le(
            u64::from(header_raw.offsets[3]) << 32
                | u64::from(header_raw.offsets[2]),
        );

        // TODO Final checksum is always zero on v5?
        #[cfg(feature = "restrictive")]
        {
            ensure!(v5_raw._unk4_zeroed == 0, "unk4 not zeroed");
            ensure!(v5_raw._id2_offset_zeroed == 0, "id2 in V5 is not zeroed");
            ensure!(v5_raw._seg_offset_zeroed == 0, "seg in V5 is not zeroed");
            ensure!(v5_raw._unk0_v7c == 0x7C, "unk0 not 0x7C");
        }
        // TODO ensure all offsets point to after the header

        Ok(Self {
            magic_version: magic,
            version: IDBVersion::V5,
            id0_offset: NonZeroU64::new(id0_offset),
            id1_offset: NonZeroU64::new(id1_offset),
            nam_offset: NonZeroU64::new(v5_raw.nam_offset),
            til_offset: NonZeroU64::new(v5_raw.til_offset),
            checksums: v5_raw.initial_checksums,
            unk0_checksum: v5_raw.unk_checksum,
            data: IDBHeaderVersion::V5 {
                unk16: header_raw.offsets[4],
                unk1_checksum: v5_raw.final_checksum,
            },
        })
    }

    fn read_v6(
        header_raw: &IDBHeaderRaw,
        magic: IDBMagic,
        input: impl IdaGenericUnpack,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V6Raw {
            nam_offset: u64,
            _seg_offset_zeroed: u64,
            til_offset: u64,
            initial_checksums: [u32; 3],
            _unk4_zeroed: [u8; 4],
            unk5_checksum: u32,
            id2_offset: u64,
            final_checksum: u32,
            _unk0_v7c: u32,
        }
        let v6_raw: V6Raw = bincode::deserialize_from(input)?;
        let id0_offset = u64::from_le(
            u64::from(header_raw.offsets[1]) << 32
                | u64::from(header_raw.offsets[0]),
        );
        let id1_offset = u64::from_le(
            u64::from(header_raw.offsets[3]) << 32
                | u64::from(header_raw.offsets[2]),
        );

        #[cfg(feature = "restrictive")]
        {
            ensure!(v6_raw._unk4_zeroed == [0; 4], "unk4 not zeroed");
            ensure!(v6_raw._seg_offset_zeroed == 0, "seg in V6 is not zeroed");
            ensure!(v6_raw._unk0_v7c == 0x7C, "unk0 not 0x7C");
        }
        // TODO ensure all offsets point to after the header

        Ok(Self {
            magic_version: magic,
            version: IDBVersion::V6,
            id0_offset: NonZeroU64::new(id0_offset),
            id1_offset: NonZeroU64::new(id1_offset),
            nam_offset: NonZeroU64::new(v6_raw.nam_offset),
            til_offset: NonZeroU64::new(v6_raw.til_offset),
            checksums: v6_raw.initial_checksums,
            unk0_checksum: v6_raw.unk5_checksum,
            data: IDBHeaderVersion::V6 {
                unk16: header_raw.offsets[4],
                id2_offset: NonZeroU64::new(v6_raw.id2_offset),
                unk1_checksum: v6_raw.final_checksum,
            },
        })
    }
}

impl IDBSectionHeader {
    pub fn read(
        header: &IDBHeader,
        input: impl IdaGenericUnpack,
    ) -> Result<Self> {
        match header.version {
            IDBVersion::V1 | IDBVersion::V4 => {
                #[derive(Debug, Deserialize)]
                struct Section32Raw {
                    compress: u8,
                    len: u32,
                }
                let header: Section32Raw = bincode::deserialize_from(input)?;
                Ok(IDBSectionHeader {
                    compress: header
                        .compress
                        .try_into()
                        .map_err(|_| anyhow!("Invalid compression code"))?,
                    len: header.len.into(),
                })
            }
            IDBVersion::V5 | IDBVersion::V6 => {
                #[derive(Debug, Deserialize)]
                struct Section64Raw {
                    compress: u8,
                    len: u64,
                }
                let header: Section64Raw = bincode::deserialize_from(input)?;
                Ok(IDBSectionHeader {
                    compress: header
                        .compress
                        .try_into()
                        .map_err(|_| anyhow!("Invalid compression code"))?,
                    len: header.len,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum VaVersion {
    Va0,
    Va1,
    Va2,
    Va3,
    Va4,
    VaX,
}

impl VaVersion {
    fn read(mut input: impl IdaGenericUnpack) -> Result<Self> {
        let mut magic: [u8; 4] = [0; 4];
        input.read_exact(&mut magic)?;
        match &magic[..] {
            b"Va0\x00" => Ok(Self::Va0),
            b"Va1\x00" => Ok(Self::Va1),
            b"Va2\x00" => Ok(Self::Va2),
            b"Va3\x00" => Ok(Self::Va3),
            b"Va4\x00" => Ok(Self::Va4),
            b"VA*\x00" => Ok(Self::VaX),
            other_magic => Err(anyhow!("Invalid Va magic: {other_magic:?}")),
        }
    }
}

#[derive(Clone)]
pub struct IDBString(Vec<u8>);

impl IDBString {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_utf8_lossy(&self) -> Cow<str> {
        String::from_utf8_lossy(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for IDBString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_char('"')?;
        f.write_str(&self.as_utf8_lossy())?;
        f.write_char('"')?;
        Ok(())
    }
}

fn write_string_len_u8<O: std::io::Write>(
    mut output: O,
    value: &[u8],
) -> Result<()> {
    output.write_all(&[u8::try_from(value.len()).unwrap()])?;
    Ok(output.write_all(value)?)
}

#[cfg(test)]
mod test {
    use crate::til::section::TILSection;
    use crate::*;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{BufReader, Seek};
    use std::path::{Path, PathBuf};

    #[test]
    fn parse_id0_til() {
        let function = [
            0x0c, // Function Type
            0xaf, 0x81, 0x42, 0x01, 0x53, // TODO
            0x01, // void ret
            0x03, //n args
            0x3d, 0x08, 0x48, 0x4d, 0x4f, 0x44, 0x55, 0x4c, 0x45, 0x3d, 0x06,
            0x44, 0x57, 0x4f, 0x52, 0x44, 0x00,
        ];
        let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
    }

    #[test]
    fn parse_destructor_function() {
        // from ComRAT-Orchestrator.i64 0x180007cf0
        // ```c
        // void __fastcall stringstream__basic_ios__sub_180007CF0_Destructor(
        //   basic_ios *__shifted(stringstream,0x94) a1
        // );
        // ```
        let function = [
            0x0c, // Function Type
            0x70, // TODO
            0x01, // void ret
            0x02, // n args (2 - 1 = 1)
            0x0a, // arg0 type is pointer
            0xfe, 0x80, 0x01, // pointer tah
            0x3d, // pointer type is typedef
            0x04, 0x23, 0x83, 0x69, // typedef ord is 233 -> basic_ios
            // ?????
            0x3d, // second typedef?
            0x04, 0x23, 0x83, 0x66, // typedef ord is 230 => stringstream
            0x82, 0x54, // ???? the 0x94 value?
            0x00, // the final value always present
        ];
        let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
    }

    #[test]
    fn parse_function_ext_att() {
        // ```
        // Function {
        //   ret: Basic(Int { bytes: 4, is_signed: None }),
        //   args: [(
        //     Some("env"),
        //     Pointer(Pointer {
        //       closure: Default,
        //       tah: TAH(TypeAttribute(1)),
        //       typ: Struct(Ref {
        //         ref_type: Typedef("__jmp_buf_tag"),
        //         taudt_bits: SDACL(TypeAttribute(0))
        //       })
        //     }),
        //     None
        //   )],
        //   retloc: None }
        // ```
        let function = [
            0x0c, // func type
            0x13, // TODO
            0x07, // return int
            0x02, // 1 parameter
            0xff, 0x48, // TODO
            0x0a, // arg1 type pointer
            0xfe, 0x10, // TypeAttribute val
            0x02, // dt len 1
            0x0d, 0x5f, 0x5f, 0x6f, 0x72, 0x67, 0x5f, 0x61, 0x72, 0x72, 0x64,
            0x69, 0x6d, // TODO some _string: "__org_arrdim"
            0x03, 0xac, 0x01, // TODO _other_thing
            0x0d, // arg1 pointer type struct
            0x01, // struct ref
            0x0e, 0x5f, 0x5f, 0x6a, 0x6d, 0x70, 0x5f, 0x62, 0x75, 0x66, 0x5f,
            0x74, 0x61, 0x67, // "__jmp_buf_tag"
            0x00, // end of type
        ];
        let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
    }

    #[test]
    fn parse_aes_encrypt() {
        // ```c
        // void AES_ctr128_encrypt(
        //   const unsigned __int8 *in,
        //   unsigned __int8 *out,
        //   const unsigned int length,
        //   const AES_KEY *key,
        //   unsigned __int8 ivec[16],
        //   unsigned __int8 ecount_buf[16],
        //   unsigned int *num
        // );
        // ```
        let function = [
            0x0c, // type function
            0x13, 0x01, // ???
            0x08, // 7 args
            // arg1 ...
            0x0a, // pointer
            0x62, // const unsigned __int8
            // arg2 ...
            0x0a, // pointer
            0x22, // unsigned __int8
            // arg3 ...
            0x67, // const unsigned int
            // arg4 ...
            0x0a, // pointer
            0x7d, // const typedef
            0x08, 0x41, 0x45, 0x53, 0x5f, 0x4b, 0x45,
            0x59, // ordinal "AES_KEY"
            // arg5
            0xff, 0x48, // some flag in function arg
            0x0a, // pointer
            0xfe, 0x10, // TypeAttribute val
            0x02, // TypeAttribute loop once
            0x0d, 0x5f, 0x5f, 0x6f, 0x72, 0x67, 0x5f, 0x61, 0x72, 0x72, 0x64,
            0x69, 0x6d, // string "__org_arrdim"
            0x03, 0xac, 0x10, // ???? some other TypeAttribute field
            0x22, // type unsigned __int8
            // arg6
            0xff, 0x48, // some flag in function arg
            0x0a, // pointer
            0xfe, 0x10, // TypeAttribute val
            0x02, // TypeAttribute loop once
            0x0d, 0x5f, 0x5f, 0x6f, 0x72, 0x67, 0x5f, 0x61, 0x72, 0x72, 0x64,
            0x69, 0x6d, // string "__org_arrdim"
            0x03, 0xac, 0x10, // ???? some other TypeAttribute field
            0x22, // type unsigned __int8
            // arg7 ...
            0x0a, // pointer
            0x27, // unsigned int
            0x00,
        ];
        let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
    }

    #[test]
    fn parse_spoiled_function_kernel_32() {
        // ```
        // TilType(Type { is_const: false, is_volatile: false, type_variant:
        //   Function(Function {
        //     ret: Type { is_const: false, is_volatile: false, type_variant: Basic(Void) },
        //     args: [
        //       (
        //         Some([117, 69, 120, 105, 116, 67, 111, 100, 101]),
        //         Type {
        //           is_const: false,
        //           is_volatile: false,
        //           type_variant: Typedef(Name([85, 73, 78, 84])) }, None)],
        //           retloc: None
        //         }
        //       )
        // })
        // ```
        let function = [
            0x0c, // function type
            0xaf, 0x81, // function cc extended...
            0x42, // flag
            0x01, // 0 regs nspoiled
            0x53, // cc
            0x01, // return type void
            0x02, // 1 param
            0x3d, // param 1 typedef
            0x05, 0x55, 0x49, 0x4e, 0x54, // typedef name
            0x00, //end
        ];
        let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
    }

    #[test]
    fn parse_spoiled_function_invalid_reg() {
        // ```
        // 0x180001030:
        // TilType(Type { is_const: false, is_volatile: false, type_variant:
        //   Function(Function {
        //     ret: Type { is_const: false, is_volatile: false, type_variant: Basic(Void) },
        //     args: [], retloc: None
        //   })
        // })
        // ```
        let function = [
            0x0c, // function type
            0xaa, // extended function cc, 10 nspoiled
            0x71, // spoiled reg 0
            0x72, // spoiled reg 1
            0x73, // spoiled reg 2
            0x79, // spoiled reg 3
            0x7a, // spoiled reg 4
            0x7b, // spoiled reg 5
            0x7c, // spoiled reg 6
            0xc0, 0x08, // spoiled reg 7
            0xc4, 0x08, // spoiled reg 8
            0xc5, 0x08, // spoiled reg 9
            0x30, // cc
            0x01, // return type void
            0x01, // no params
            0x00, // end
        ];
        let _til = til::Type::new_from_id0(&function, vec![]).unwrap();
    }

    #[test]
    fn parse_idb_param() {
        let param = b"IDA\xbc\x02\x06metapc#\x8a\x03\x03\x02\x00\x00\x00\x00\xff_\xff\xff\xf7\x03\x00\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x0d\x00\x0d \x0d\x10\xff\xff\x00\x00\x00\xc0\x80\x00\x00\x00\x02\x02\x01\x0f\x0f\x06\xce\xa3\xbeg\xc6@\x00\x07\x00\x07\x10(FP\x87t\x09\x03\x00\x01\x13\x0a\x00\x00\x01a\x00\x07\x00\x13\x04\x04\x04\x00\x02\x04\x08\x00\x00\x00";
        let _parsed = id0::IDBParam::read(param, false).unwrap();
    }

    #[test]
    fn parse_idbs() {
        let files = find_all(
            "resources/idbs".as_ref(),
            &["idb".as_ref(), "i64".as_ref()],
        )
        .unwrap();
        for filename in files {
            parse_idb(filename)
        }
    }

    fn parse_idb(filename: impl AsRef<Path>) {
        let filename = filename.as_ref();
        println!("{}", filename.to_str().unwrap());
        let file = BufReader::new(File::open(&filename).unwrap());
        let mut parser = IDBParser::new(file).unwrap();
        // parse sectors
        let id0 = parser
            .read_id0_section(parser.id0_section_offset().unwrap())
            .unwrap();
        let til = parser
            .til_section_offset()
            .map(|til| parser.read_til_section(til).unwrap());
        let _ = parser
            .id1_section_offset()
            .map(|idx| parser.read_id1_section(idx));
        let _ = parser
            .nam_section_offset()
            .map(|idx| parser.read_nam_section(idx));

        // parse all id0 information
        let _ida_info = id0.ida_info().unwrap();
        let version = match _ida_info {
            id0::IDBParam::V1(x) => x.version,
            id0::IDBParam::V2(x) => x.version,
        };

        let _: Vec<_> = id0.segments().unwrap().map(Result::unwrap).collect();
        let _: Vec<_> =
            id0.loader_name().unwrap().map(Result::unwrap).collect();
        let _: Vec<_> = id0.root_info().unwrap().map(Result::unwrap).collect();
        let _: Vec<_> = id0
            .file_regions(version)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let _: Vec<_> = id0
            .functions_and_comments()
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let _ = id0.entry_points().unwrap();
        let _ = id0.dirtree_bpts().unwrap();
        let _ = id0.dirtree_enums().unwrap();
        let _dirtree_names = id0.dirtree_names().unwrap();
        _dirtree_names.visit_leafs(|addr| {
            // NOTE it's know that some label are missing in some databases
            let _name = id0.label_at(*addr).unwrap();
        });
        let _dirtree_tinfos = id0.dirtree_tinfos().unwrap();
        if let Some(til) = til {
            _dirtree_tinfos.visit_leafs(|ord| {
                let _til = til.get_ord(*ord).unwrap();
            });
        }
        let _ = id0.dirtree_imports().unwrap();
        let _ = id0.dirtree_structs().unwrap();
        let _ = id0.dirtree_function_address().unwrap();
        let _ = id0.dirtree_bookmarks_tiplace().unwrap();
        let _ = id0.dirtree_bookmarks_idaplace().unwrap();
        let _ = id0.dirtree_bookmarks_structplace().unwrap();
        let _: Vec<_> = id0
            .address_info(version)
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
    }

    #[test]
    fn parse_tils() {
        let files =
            find_all("resources/tils".as_ref(), &["til".as_ref()]).unwrap();
        let _results = files
            .into_iter()
            .map(|file| {
                println!("{}", file.to_str().unwrap());
                // makes sure it don't read out-of-bounds
                let mut input = BufReader::new(File::open(file)?);
                // TODO make a SmartReader
                TILSection::read(&mut input, IDBSectionCompression::None).and_then(|_til| {
                    let current = input.seek(SeekFrom::Current(0))?;
                    let end = input.seek(SeekFrom::End(0))?;
                    ensure!(
                        current == end,
                        "unable to consume the entire TIL file, {current} != {end}"
                    );
                    Ok(())
                })
            })
            .collect::<Result<(), _>>()
            .unwrap();
    }

    fn find_all(path: &Path, exts: &[&OsStr]) -> Result<Vec<PathBuf>> {
        fn inner_find_all(
            path: &Path,
            exts: &[&OsStr],
            buf: &mut Vec<PathBuf>,
        ) -> Result<()> {
            for entry in std::fs::read_dir(path)?.map(Result::unwrap) {
                let entry_type = entry.metadata()?.file_type();
                if entry_type.is_dir() {
                    inner_find_all(&entry.path(), exts, buf)?;
                    continue;
                }

                if !entry_type.is_file() {
                    continue;
                }

                let filename = entry.file_name();
                let Some(ext) = Path::new(&filename).extension() else {
                    continue;
                };

                if exts.contains(&ext) {
                    buf.push(entry.path())
                }
            }
            Ok(())
        }
        let mut result = vec![];
        inner_find_all(path, exts, &mut result)?;
        Ok(result)
    }
}

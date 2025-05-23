#![forbid(unsafe_code)]
pub mod id0;
pub mod id1;
pub(crate) mod ida_reader;
pub mod nam;
pub mod til;

use std::borrow::Cow;
use std::fmt::Write;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::num::NonZeroU64;

use id0::{ID0Section, ID0SectionVariants};
use ida_reader::{IdbBufRead, IdbRead, IdbReadKind};
use serde::Deserialize;

use crate::id1::ID1Section;
use crate::nam::NamSection;
use crate::til::section::TILSection;
use anyhow::{anyhow, ensure, Result};

use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Clone)]
enum IDBParserInput<I> {
    File(I),
    // TODO find a better way to handle Zstd data,
    // this could be problematic with big files
    Buffer(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct IDBParser<I, K: IDAKind> {
    input: IDBParserInput<I>,
    header: IDBHeader,
    _kind: std::marker::PhantomData<K>,
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
                self.0
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID0Offset(u64);
impl_idb_offset!(ID0Offset);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID1Offset(u64);
impl_idb_offset!(ID1Offset);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamOffset(u64);
impl_idb_offset!(NamOffset);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TILOffset(u64);
impl_idb_offset!(TILOffset);

macro_rules! call_parser_discrimiant {
    ($slf:ident, $name:ident, $call:tt) => {
        match $slf {
            Self::IDA32($name) => $call,
            Self::IDA64($name) => $call,
        }
    };
}

pub type IDBParserVariants<I> =
    IDAVariants<IDBParser<I, IDA32>, IDBParser<I, IDA64>>;

impl<I: BufRead + Seek> IDBParserVariants<I> {
    pub fn new(mut input: I) -> Result<Self> {
        let header = IDBHeader::read(&mut input)?;
        let input = match &header.version {
            IDBHeaderVersion::V910(h)
                if h.compression != IDBSectionCompression::None =>
            {
                let mut output = vec![];
                input.seek(SeekFrom::Start(h.data_start.get()))?;
                match h.compression {
                    IDBSectionCompression::None => unreachable!(),
                    IDBSectionCompression::Zlib => {
                        flate2::read::ZlibDecoder::new(input)
                            .read_to_end(&mut output)?;
                    }
                    IDBSectionCompression::Zstd => {
                        zstd::Decoder::new(input)?.read_to_end(&mut output)?;
                    }
                }
                IDBParserInput::Buffer(output)
            }
            _ => IDBParserInput::File(input),
        };
        if header.magic_version.is_64() {
            Ok(Self::IDA64(IDBParser {
                input,
                header,
                _kind: std::marker::PhantomData,
            }))
        } else {
            Ok(Self::IDA32(IDBParser {
                input,
                header,
                _kind: std::marker::PhantomData,
            }))
        }
    }
    pub fn id0_section_offset(&self) -> Option<ID0Offset> {
        call_parser_discrimiant!(self, x, { x.id0_section_offset() })
    }

    pub fn id1_section_offset(&self) -> Option<ID1Offset> {
        call_parser_discrimiant!(self, x, { x.id1_section_offset() })
    }

    pub fn nam_section_offset(&self) -> Option<NamOffset> {
        call_parser_discrimiant!(self, x, { x.nam_section_offset() })
    }

    pub fn til_section_offset(&self) -> Option<TILOffset> {
        call_parser_discrimiant!(self, x, { x.til_section_offset() })
    }

    pub fn read_id0_section(
        &mut self,
        id0: ID0Offset,
    ) -> Result<ID0SectionVariants> {
        match self {
            Self::IDA32(parser) => {
                parser.read_id0_section(id0).map(IDAVariants::IDA32)
            }
            Self::IDA64(parser) => {
                parser.read_id0_section(id0).map(IDAVariants::IDA64)
            }
        }
    }

    pub fn read_id1_section(&mut self, id1: ID1Offset) -> Result<ID1Section> {
        call_parser_discrimiant!(self, x, { x.read_id1_section(id1) })
    }

    pub fn read_nam_section(&mut self, nam: NamOffset) -> Result<NamSection> {
        call_parser_discrimiant!(self, x, { x.read_nam_section(nam) })
    }

    pub fn read_til_section(&mut self, til: TILOffset) -> Result<TILSection> {
        call_parser_discrimiant!(self, x, { x.read_til_section(til) })
    }

    pub fn decompress_til_section(
        &mut self,
        til: TILOffset,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        call_parser_discrimiant!(self, x, {
            x.decompress_til_section(til, output)
        })
    }
}

impl<I: BufRead + Seek, K: IDAKind> IDBParser<I, K> {
    pub fn id0_section_offset(&self) -> Option<ID0Offset> {
        match self.header.version {
            IDBHeaderVersion::V1(v) => v.id0_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V4(v) => v.id0_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V5(v) => v.id0_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V6(v) => v.id0_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V910(v) => v.id0.map(|x| x.offset),
        }
        .map(ID0Offset)
    }

    pub fn id1_section_offset(&self) -> Option<ID1Offset> {
        match self.header.version {
            IDBHeaderVersion::V1(v) => v.id1_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V4(v) => v.id1_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V5(v) => v.id1_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V6(v) => v.id1_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V910(v) => v.id1.map(|x| x.offset),
        }
        .map(ID1Offset)
    }

    pub fn nam_section_offset(&self) -> Option<NamOffset> {
        match self.header.version {
            IDBHeaderVersion::V1(v) => v.nam_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V4(v) => v.nam_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V5(v) => v.nam_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V6(v) => v.nam_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V910(v) => v.nam.map(|x| x.offset),
        }
        .map(NamOffset)
    }

    pub fn til_section_offset(&self) -> Option<TILOffset> {
        match self.header.version {
            IDBHeaderVersion::V1(v) => v.til_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V4(v) => v.til_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V5(v) => v.til_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V6(v) => v.til_offset.map(NonZeroU64::get),
            IDBHeaderVersion::V910(v) => v.til.map(|x| x.offset),
        }
        .map(TILOffset)
    }

    pub fn read_id0_section(
        &mut self,
        id0: ID0Offset,
    ) -> Result<ID0Section<K>> {
        read_section_from_main_header::<ID0Section<K>, I, K>(
            &mut self.input,
            id0.0,
            &self.header,
        )
    }

    pub fn read_id1_section(&mut self, id1: ID1Offset) -> Result<ID1Section> {
        read_section_from_main_header::<ID1Section, I, K>(
            &mut self.input,
            id1.0,
            &self.header,
        )
    }

    pub fn read_nam_section(&mut self, nam: NamOffset) -> Result<NamSection> {
        read_section_from_main_header::<NamSection, I, K>(
            &mut self.input,
            nam.0,
            &self.header,
        )
    }

    pub fn read_til_section(&mut self, til: TILOffset) -> Result<TILSection> {
        read_section_from_main_header::<TILSection, I, K>(
            &mut self.input,
            til.0,
            &self.header,
        )
    }

    pub fn decompress_section(
        &mut self,
        offset: impl IDBOffset,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        match &mut self.input {
            IDBParserInput::Buffer(buf) => {
                let offset = usize::try_from(offset.idb_offset()).unwrap();
                let IDBHeaderVersion::V910(h) = &self.header.version else {
                    unreachable!();
                };
                let size = usize::try_from(h.til.unwrap().size.get()).unwrap();
                output
                    .write_all(&buf[offset..offset + size])
                    .map_err(anyhow::Error::from)
            }
            IDBParserInput::File(input) => {
                input.seek(SeekFrom::Start(offset.idb_offset()))?;
                let section_header =
                    IDBSectionHeader::read(&self.header, &mut *input)?;
                // makes sure the reader doesn't go out-of-bounds
                match section_header.compress {
                    IDBSectionCompression::Zlib => {
                        let input =
                            std::io::Read::take(input, section_header.len);
                        let mut input =
                            flate2::bufread::ZlibDecoder::new(input);
                        let _ = std::io::copy(&mut input, output)?;
                    }
                    IDBSectionCompression::None => {
                        let mut input =
                            std::io::Read::take(input, section_header.len);
                        let _ = std::io::copy(&mut input, output)?;
                    }
                    IDBSectionCompression::Zstd => {
                        let input = zstd::Decoder::new(input)?;
                        let mut input =
                            std::io::Read::take(input, section_header.len);
                        let _ = std::io::copy(&mut input, output)?;
                    }
                }
                Ok(())
            }
        }
    }

    pub fn decompress_til_section(
        &mut self,
        til: TILOffset,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        let offset = til.0;
        match &mut self.input {
            IDBParserInput::Buffer(buf) => {
                let offset = usize::try_from(offset).unwrap();
                let IDBHeaderVersion::V910(h) = &self.header.version else {
                    unreachable!();
                };
                let size = usize::try_from(h.til.unwrap().size.get()).unwrap();
                output
                    .write_all(&buf[offset..offset + size])
                    .map_err(anyhow::Error::from)
            }
            IDBParserInput::File(input) => {
                input.seek(SeekFrom::Start(offset))?;
                let section_header =
                    IDBSectionHeader::read(&self.header, &mut *input)?;
                // makes sure the reader doesn't go out-of-bounds
                let mut input = std::io::Read::take(input, section_header.len);
                TILSection::decompress(
                    &mut input,
                    output,
                    section_header.compress,
                )
            }
        }
    }
}

trait SectionReader<K: IDAKind> {
    type Result;
    fn read_section<I: IdbReadKind<K> + IdbBufRead>(
        reader: &mut I,
    ) -> Result<Self::Result>;
    fn size_from_v910(header: &IDBHeaderV910) -> u64;
}

// decided, based on the version, where the size compress data is stored
fn read_section_from_main_header<F, I, K>(
    input: &mut IDBParserInput<I>,
    offset: u64,
    header: &IDBHeader,
) -> Result<F::Result>
where
    I: IdbBufRead + Seek,
    K: IDAKind,
    F: SectionReader<K>,
{
    match input {
        IDBParserInput::Buffer(buf) => {
            let offset = usize::try_from(offset).unwrap();
            let IDBHeaderVersion::V910(h) = &header.version else {
                unreachable!();
            };
            let size = usize::try_from(F::size_from_v910(h)).unwrap();
            read_section::<F, _, _>(
                &mut &buf[offset..offset + size],
                IDBSectionCompression::None,
                F::size_from_v910(h),
            )
        }
        IDBParserInput::File(input) => {
            input.seek(SeekFrom::Start(offset))?;
            match &header.version {
                IDBHeaderVersion::V910(h) => read_section::<F, _, _>(
                    input,
                    h.compression,
                    F::size_from_v910(h),
                ),
                IDBHeaderVersion::V1(_)
                | IDBHeaderVersion::V4(_)
                | IDBHeaderVersion::V5(_)
                | IDBHeaderVersion::V6(_) => {
                    read_section_from_header::<F, _, _>(input, header)
                }
            }
        }
    }
}

// read the header from the disk
fn read_section_from_header<F, I, K>(
    input: &mut I,
    header: &IDBHeader,
) -> Result<F::Result>
where
    I: IdbBufRead,
    K: IDAKind,
    F: SectionReader<K>,
{
    let section_header = IDBSectionHeader::read(header, &mut *input)?;
    read_section::<F, _, _>(input, section_header.compress, section_header.len)
}

fn read_section<F, I, K>(
    input: &mut I,
    compress: IDBSectionCompression,
    len: u64,
) -> Result<F::Result>
where
    I: IdbBufRead,
    K: IDAKind,
    F: SectionReader<K>,
{
    let result = match compress {
        IDBSectionCompression::None => {
            let mut input = std::io::Read::take(input, len);
            let result = F::read_section(&mut input)?;
            ensure!(
                input.limit() == 0,
                "Sector have more data then expected, left {} bytes",
                input.limit()
            );
            result
        }
        IDBSectionCompression::Zlib => {
            // TODO seems its normal to have a few extra bytes at the end of the sector, maybe
            // because of the compressions stuff, anyway verify that
            let input = std::io::Read::take(input, len);
            let mut flate_reader =
                BufReader::new(flate2::read::ZlibDecoder::new(input));
            let result = F::read_section(&mut flate_reader)?;
            let limit = flate_reader.into_inner().into_inner().limit();
            ensure!(
                limit <= 16,
                "Compressed Zlib Sector have more data then expected, left {limit} bytes",
            );
            result
        }
        IDBSectionCompression::Zstd => {
            let zstd_reader = BufReader::new(zstd::Decoder::new(input)?);
            let mut input = std::io::Read::take(zstd_reader, len);
            let result = F::read_section(&mut input)?;
            let limit = input.limit();
            ensure!(
                limit <= 16,
                "Compressed Zlib Sector have more data then expected, left {limit} bytes",
            );
            result
        }
    };

    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBMagic {
    IDA0,
    IDA1,
    IDA2,
}

impl TryFrom<[u8; 5]> for IDBMagic {
    type Error = anyhow::Error;

    fn try_from(value: [u8; 5]) -> Result<Self, Self::Error> {
        match &value {
            b"IDA0\x00" => Ok(IDBMagic::IDA0),
            b"IDA1\x00" => Ok(IDBMagic::IDA1),
            b"IDA2\x00" => Ok(IDBMagic::IDA2),
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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive,
)]
#[repr(u16)]
enum IDBVersion {
    // TODO add other versions
    V1 = 1,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    V910 = 910,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeader {
    magic_version: IDBMagic,
    version: IDBHeaderVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBHeaderVersion {
    V1(IDBHeaderV1),
    V4(IDBHeaderV4),
    V5(IDBHeaderV5),
    V6(IDBHeaderV6),
    V910(IDBHeaderV910),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeaderV1 {
    pub id0_offset: Option<NonZeroU64>,
    pub id1_offset: Option<NonZeroU64>,
    pub nam_offset: Option<NonZeroU64>,
    pub seg_offset: Option<NonZeroU64>,
    pub til_offset: Option<NonZeroU64>,
    pub checksums: [u32; 5],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeaderV4 {
    pub id0_offset: Option<NonZeroU64>,
    pub id1_offset: Option<NonZeroU64>,
    pub nam_offset: Option<NonZeroU64>,
    pub seg_offset: Option<NonZeroU64>,
    pub til_offset: Option<NonZeroU64>,
    pub checksums: [u32; 5],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeaderV5 {
    pub id0_offset: Option<NonZeroU64>,
    pub id1_offset: Option<NonZeroU64>,
    pub nam_offset: Option<NonZeroU64>,
    pub til_offset: Option<NonZeroU64>,
    pub checksums: [u32; 5],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeaderV6 {
    pub id0_offset: Option<NonZeroU64>,
    pub id1_offset: Option<NonZeroU64>,
    pub id2_offset: Option<std::num::NonZero<u64>>,
    pub nam_offset: Option<NonZeroU64>,
    pub til_offset: Option<NonZeroU64>,
    pub checksums: [u32; 5],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeaderV910 {
    pub compression: IDBSectionCompression,
    pub data_start: NonZeroU64,
    pub id0: Option<IDBHeaderV910Sector>,
    pub id1: Option<IDBHeaderV910Sector>,
    pub id2: Option<IDBHeaderV910Sector>,
    pub nam: Option<IDBHeaderV910Sector>,
    pub til: Option<IDBHeaderV910Sector>,
    pub seg: Option<IDBHeaderV910Sector>,
    pub md5: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IDBHeaderV910Sector {
    pub offset: u64,
    pub size: NonZeroU64,
}

// NOTE V910 ditched the SectionHeader
#[derive(Debug, Clone, Copy)]
struct IDBSectionHeader {
    compress: IDBSectionCompression,
    len: u64,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, IntoPrimitive, TryFromPrimitive,
)]
#[repr(u8)]
pub enum IDBSectionCompression {
    None = 0,
    Zlib = 2,
    /// Introduced in version 9.1
    Zstd = 3,
}

#[derive(Debug, Deserialize)]
struct IDBHeaderRaw {
    magic: [u8; 5],
    _padding_0: u8,
    offsets: [u32; 5],
    signature: u32,
    version: u16,
    // more, depending on the version
}

impl IDBHeader {
    pub fn read(mut input: impl Read) -> Result<Self> {
        // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x77eef0
        // InnerRef expects the file to be at least 112 bytes,
        // always read 109 bytes at the start
        // read 32 bytes
        let header_raw: IDBHeaderRaw = bincode::deserialize_from(&mut input)?;
        let magic = IDBMagic::try_from(header_raw.magic)?;
        ensure!(
            header_raw.signature == 0xAABB_CCDD,
            "Invalid header signature {:#x}",
            header_raw.signature
        );
        // TODO associate header.version and magic?
        let version = match IDBVersion::try_from_primitive(header_raw.version)
            .map_err(|_| {
            anyhow!("Unable to parse version `{}`", header_raw.version)
        })? {
            IDBVersion::V1 => {
                IDBHeaderVersion::V1(Self::read_v1(&header_raw, input)?)
            }
            IDBVersion::V4 => {
                IDBHeaderVersion::V4(Self::read_v4(&header_raw, input)?)
            }
            IDBVersion::V5 => {
                IDBHeaderVersion::V5(Self::read_v5(&header_raw, input)?)
            }
            IDBVersion::V6 => {
                IDBHeaderVersion::V6(Self::read_v6(&header_raw, input)?)
            }
            IDBVersion::V910 => {
                IDBHeaderVersion::V910(Self::read_v910(&header_raw, input)?)
            }
        };
        Ok(Self {
            magic_version: magic,
            version,
        })
    }

    fn read_v1(
        header_raw: &IDBHeaderRaw,
        input: impl Read,
    ) -> Result<IDBHeaderV1> {
        #[derive(Debug, Deserialize)]
        struct V1Raw {
            _id2_offset: u32,
            checksums: [u32; 5],
        }

        let v1_raw: V1Raw = bincode::deserialize_from(input)?;

        // TODO ensure all offsets point to after the header
        #[cfg(feature = "restrictive")]
        {
            ensure!(v1_raw._id2_offset == 0, "id2 in V1 is not zeroed");
        }

        Ok(IDBHeaderV1 {
            id0_offset: NonZeroU64::new(header_raw.offsets[0].into()),
            id1_offset: NonZeroU64::new(header_raw.offsets[1].into()),
            nam_offset: NonZeroU64::new(header_raw.offsets[2].into()),
            seg_offset: NonZeroU64::new(header_raw.offsets[3].into()),
            til_offset: NonZeroU64::new(header_raw.offsets[4].into()),
            checksums: v1_raw.checksums,
        })
    }

    fn read_v4(
        header_raw: &IDBHeaderRaw,
        input: impl Read,
    ) -> Result<IDBHeaderV4> {
        #[derive(Debug, Deserialize)]
        struct V4Raw {
            _id2_offset: u32,
            checksums: [u32; 5],
            _unk38_zeroed: [u8; 8],
            _unk40_v5c: u32,
        }

        let v4_raw: V4Raw = bincode::deserialize_from(input)?;

        #[cfg(feature = "restrictive")]
        {
            ensure!(v4_raw._id2_offset == 0, "id2 in V4 is not zeroed");
            ensure!(v4_raw._unk38_zeroed == [0; 8], "unk38 is not zeroed");
            ensure!(v4_raw._unk40_v5c == 0x5c, "unk40 is not 0x5C");
        }
        // TODO ensure all offsets point to after the header

        Ok(IDBHeaderV4 {
            id0_offset: NonZeroU64::new(header_raw.offsets[0].into()),
            id1_offset: NonZeroU64::new(header_raw.offsets[1].into()),
            nam_offset: NonZeroU64::new(header_raw.offsets[2].into()),
            seg_offset: NonZeroU64::new(header_raw.offsets[3].into()),
            til_offset: NonZeroU64::new(header_raw.offsets[4].into()),
            checksums: v4_raw.checksums,
        })
    }

    fn read_v5(
        header_raw: &IDBHeaderRaw,
        input: impl Read,
    ) -> Result<IDBHeaderV5> {
        #[derive(Debug, Deserialize)]
        struct V5Raw {
            nam_offset: u64,
            _seg_offset_zeroed: u64,
            til_offset: u64,
            checksums: [u32; 5],
            _id2_offset_zeroed: u64,
            _final_checksum: u32,
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
            ensure!(v5_raw._id2_offset_zeroed == 0, "id2 in V5 is not zeroed");
            ensure!(v5_raw._seg_offset_zeroed == 0, "seg in V5 is not zeroed");
            ensure!(v5_raw._unk0_v7c == 0x7C, "unk0 not 0x7C");
        }
        // TODO ensure all offsets point to after the header

        Ok(IDBHeaderV5 {
            id0_offset: NonZeroU64::new(id0_offset),
            id1_offset: NonZeroU64::new(id1_offset),
            nam_offset: NonZeroU64::new(v5_raw.nam_offset),
            til_offset: NonZeroU64::new(v5_raw.til_offset),
            checksums: v5_raw.checksums,
        })
    }

    fn read_v6(
        header_raw: &IDBHeaderRaw,
        input: impl Read,
    ) -> Result<IDBHeaderV6> {
        #[derive(Debug, Deserialize)]
        struct V6Raw {
            nam_offset: u64,
            _seg_offset_zeroed: u64,
            til_offset: u64,
            checksums: [u32; 5],
            id2_offset: u64,
            _final_checksum: u32,
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
            ensure!(v6_raw._seg_offset_zeroed == 0, "seg in V6 is not zeroed");
            ensure!(v6_raw._unk0_v7c == 0x7C, "unk0 not 0x7C");
        }
        // TODO ensure all offsets point to after the header

        Ok(IDBHeaderV6 {
            id0_offset: NonZeroU64::new(id0_offset),
            id1_offset: NonZeroU64::new(id1_offset),
            id2_offset: NonZeroU64::new(v6_raw.id2_offset),
            nam_offset: NonZeroU64::new(v6_raw.nam_offset),
            til_offset: NonZeroU64::new(v6_raw.til_offset),
            checksums: v6_raw.checksums,
        })
    }

    fn read_v910(
        header_raw: &IDBHeaderRaw,
        input: impl Read,
    ) -> Result<IDBHeaderV910> {
        #[derive(Debug, Deserialize)]
        struct V91Raw {
            compression: u8,
            sectors: [u64; 6],
            _unk1: u64,
            _unk2: u32,
            md5: [u8; 16],
        }
        let raw: V91Raw = bincode::deserialize_from(input)?;
        let header_size = u64::from_le(
            u64::from(header_raw.offsets[1]) << 32
                | u64::from(header_raw.offsets[0]),
        );
        let data_start = u64::from_le(
            u64::from(header_raw.offsets[3]) << 32
                | u64::from(header_raw.offsets[2]),
        );
        // TODO find meanings, seeing value 0 and 2
        let _unk3 = header_raw.offsets[4];
        #[cfg(feature = "restrictive")]
        {
            ensure!(raw._unk1 == 0);
            ensure!(raw._unk2 == 0);
        }

        ensure!(header_size != 0);
        // TODO ensure other header data is empty based on the header_size

        let data_start = NonZeroU64::new(data_start)
            .ok_or_else(|| anyhow!("Invalid Header data start offset"))?;

        // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x077f669 read
        // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x077ebf9 unpack
        let mut current_offset =
            if raw.compression != IDBSectionCompression::None.into() {
                0
            } else {
                data_start.get()
            };
        let sectors: [Option<IDBHeaderV910Sector>; 6] = raw
            .sectors
            .iter()
            .copied()
            .map(|size| {
                let sector =
                    NonZeroU64::new(size).map(|size| IDBHeaderV910Sector {
                        offset: current_offset,
                        size,
                    });
                current_offset += size;
                Ok(sector)
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .try_into()
            .unwrap();

        let compression =
            IDBSectionCompression::try_from_primitive(raw.compression)
                .map_err(|_| anyhow!("Invalid V910 header compression"))?;

        Ok(IDBHeaderV910 {
            compression,
            data_start,
            id0: sectors[0],
            id1: sectors[1],
            nam: sectors[2],
            id2: sectors[3],
            til: sectors[4],
            seg: sectors[5],
            md5: raw.md5,
        })
    }
}

impl IDBSectionHeader {
    fn read(header: &IDBHeader, input: impl Read) -> Result<Self> {
        match header.version {
            IDBHeaderVersion::V1(_) | IDBHeaderVersion::V4(_) => {
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
            IDBHeaderVersion::V5(_) | IDBHeaderVersion::V6(_) => {
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
            IDBHeaderVersion::V910(_) => {
                unreachable!()
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
    fn read(mut input: impl Read) -> Result<Self> {
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
    fn parse_struct_with_fixed() {
        let function = [
            0x0d, // stuct type
            0x31, // n = 0x30, mem_cnt = 6, packalig = 0
            0xf1, 0x80, 0x08, // struct att
            0x32, // member 0 => char
            0x01, // member 0 fixed_ext_att
            0x03, // member 1 => int16
            0x02, 0x10, // member 1 fixed_ext_att
            0x07, // member 2 => int
            0x02, 0x10, // member 2 fixed_ext_att
            0x3d, 0x03, 0x23, 0x48, // member 3 => typeref(8)
            0x02, 0x20, // member 3 fixed_ext_att
            0x08, // member 4 => bool
            0x02, 0x40, // member 4 fixed_ext_att
            0x1b, // member 5 array
            0x01, // member 5 nelem = 0
            0x32, // member 5 inner_type = char
            0x02, 0x08, // member 5 fixed_ext_att
            0x02, 0x13, // struct stuff
            0x00, //end
        ];
        let til = til::Type::new_from_id0(&function, vec![]).unwrap();
        let til::TypeVariant::Struct(til_struct) = til.type_variant else {
            unreachable!()
        };
        assert!(til_struct.extra_padding == Some(19));
    }

    #[test]
    fn parse_idb_param() {
        let param = b"IDA\xbc\x02\x06metapc#\x8a\x03\x03\x02\x00\x00\x00\x00\xff_\xff\xff\xf7\x03\x00\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x0d\x00\x0d \x0d\x10\xff\xff\x00\x00\x00\xc0\x80\x00\x00\x00\x02\x02\x01\x0f\x0f\x06\xce\xa3\xbeg\xc6@\x00\x07\x00\x07\x10(FP\x87t\x09\x03\x00\x01\x13\x0a\x00\x00\x01a\x00\x07\x00\x13\x04\x04\x04\x00\x02\x04\x08\x00\x00\x00";
        let _parsed = id0::IDBParam::<IDA32>::read(param).unwrap();
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
        let parser = IDAVariants::new(file).unwrap();
        match parser {
            IDAVariants::IDA32(idbparser) => parse_idb_inner(idbparser),
            IDAVariants::IDA64(idbparser) => parse_idb_inner(idbparser),
        }
    }

    fn parse_idb_inner<I, K>(mut parser: IDBParser<I, K>)
    where
        I: BufRead + Seek,
        K: IDAKind,
    {
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
        let _: Option<Vec<_>> = id0
            .loader_name()
            .unwrap()
            .map(|iter| iter.map(Result::unwrap).collect());
        let root_info_idx = id0.root_info_node().unwrap();
        let _: Vec<_> = id0
            .root_info(root_info_idx)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let file_regions_idx = id0.file_regions_idx().unwrap();
        let _: Vec<_> = id0
            .file_regions(file_regions_idx, version)
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
                TILSection::read(&mut input).and_then(|_til| {
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

pub enum IDAVariants<I32, I64> {
    IDA32(I32),
    IDA64(I64),
}

pub trait IDAKind: std::fmt::Debug + Clone + Copy {
    type Usize: IDAUsize;
}

pub trait IDAUsize:
    Sized
    + Sync
    + Send
    + 'static
    + Copy
    + Clone
    + std::fmt::Debug
    + std::fmt::Display
    + std::fmt::LowerHex
    + std::fmt::UpperHex
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + core::hash::Hash
    + core::iter::Sum
    + num_traits::PrimInt
    + num_traits::NumAssign
    + num_traits::WrappingAdd
    + num_traits::WrappingSub
    + num_traits::FromBytes
    + num_traits::ToBytes
    + num_traits::ToBytes
    + num_traits::AsPrimitive<u8>
    + num_traits::AsPrimitive<u16>
    + num_traits::AsPrimitive<u32>
    + num_traits::AsPrimitive<u64>
    + num_traits::AsPrimitive<Self::Isize>
    + TryInto<usize, Error: std::fmt::Debug>
    + Into<u64>
    + TryInto<u32, Error: std::fmt::Debug>
    + TryInto<u16, Error: std::fmt::Debug>
    + TryInto<u8, Error: std::fmt::Debug>
    + From<u8>
    + From<u16>
    + From<u32>
    + TryFrom<u64, Error: std::fmt::Debug>
    + TryFrom<usize, Error: std::fmt::Debug>
    + Into<i128>
{
    type Isize: num_traits::Signed + Into<i64> + Copy;
    const BYTES: u8;

    /// helper fo call into u64
    fn into_u64(self) -> u64 {
        self.into()
    }
    /// cast the inner type as a signed version of itself, then call into i64
    fn into_i64(self) -> i64 {
        let signed: Self::Isize = self.as_();
        signed.into()
    }
    fn is_max(self) -> bool {
        self == Self::max_value()
    }
    // parse the bytes and only return Some if data is the exact size of type
    fn from_le_bytes(data: &[u8]) -> Option<Self>;
    fn from_be_bytes(data: &[u8]) -> Option<Self>;
    // read the type from a reader
    fn from_le_reader(data: &mut impl std::io::Read) -> Result<Self>;
    fn from_be_reader(data: &mut impl std::io::Read) -> Result<Self>;
    fn unpack_from_reader(read: &mut impl std::io::Read) -> Result<Self>;
}

macro_rules! declare_idb_kind {
    ($bytes:literal, $utype:ident, $itype:ident, $name:ident, $unapack_fun:ident) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $name;
        impl IDAKind for $name {
            type Usize = $utype;
        }
        impl IDAUsize for $utype {
            type Isize = $itype;
            const BYTES: u8 = $bytes;

            fn from_le_bytes(data: &[u8]) -> Option<Self> {
                Some(Self::from_le_bytes(data.try_into().ok()?))
            }
            fn from_be_bytes(data: &[u8]) -> Option<Self> {
                Some(Self::from_be_bytes(data.try_into().ok()?))
            }
            fn from_le_reader(read: &mut impl std::io::Read) -> Result<Self> {
                let mut data = [0; $bytes];
                read.read_exact(&mut data)?;
                Ok(Self::from_le_bytes(data))
            }
            fn from_be_reader(read: &mut impl std::io::Read) -> Result<Self> {
                let mut data = [0; $bytes];
                read.read_exact(&mut data)?;
                Ok(Self::from_be_bytes(data))
            }
            fn unpack_from_reader(
                read: &mut impl std::io::Read,
            ) -> Result<Self> {
                read.$unapack_fun()
            }
        }
    };
}

declare_idb_kind!(4, u32, i32, IDA32, unpack_dd);
declare_idb_kind!(8, u64, i64, IDA64, unpack_dq);

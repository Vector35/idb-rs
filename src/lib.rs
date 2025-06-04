#![forbid(unsafe_code)]
pub mod id0;
pub mod id1;
pub(crate) mod ida_reader;
pub mod nam;
pub mod til;

#[allow(non_camel_case_types)]
pub mod api;

use std::borrow::Cow;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU64;

use id0::{ID0Section, ID0SectionVariants};
use ida_reader::{IdbBufRead, IdbRead, IdbReadKind};
use serde::Deserialize;

use crate::id1::ID1Section;
use crate::nam::NamSection;
use crate::til::section::TILSection;
use anyhow::{anyhow, ensure, Result};

#[macro_export]
macro_rules! flag_to_function {
    ($flag_name:ident $fun_name:ident $comment:literal) => {
        #[doc = $comment]
        pub fn $fun_name(&self) -> bool {
            self.0 & $flag_name != 0
        }
    };
}

#[macro_export]
macro_rules! flags_to_struct {
    ($struct_name:ident, $struct_type:ty, $($flag_name:ident $flag_fun_name:ident $flag_doc:literal),* $(,)?) => {
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
        pub struct $struct_name($struct_type);
        impl $struct_name {
            pub(crate) fn from_raw(value: $struct_type) -> Result<Self> {
                let invalid_bits = value & !(0 $(| $flag_name)*);
                if invalid_bits != 0 {
                    Err(anyhow!("Flag {} with invalid bits {invalid_bits:X}", stringify!($struct_name)))
                } else {
                    Ok(Self(value))
                }
            }

            pub fn into_raw(&self) -> $struct_type {
                self.0
            }

            $(
                $crate::flag_to_function!($flag_name $flag_fun_name $flag_doc);
            )*
        }
    }
}

trait Sealed {}

pub fn identify_idb_file<I: Read>(input: &mut I) -> Result<IDBFormats> {
    IDBFormats::identify_file(input)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IDBFormats {
    /// File that contains sections, the header will contain the header offsets,
    /// and each section will be preceded by a section-header containing a size
    /// and a compression (if any), each section can be accessed separately
    /// and can always be read directly from the IDB file.
    Separated(SeparatedSections),
    /// File that's fully inlined, version v9.1 started using this by
    /// default.
    ///
    /// The file have a header and the rest is composed of sections one after
    /// the other with no section-header.
    InlineUncompressed(InlineUnCompressedSections),
    /// The same as InlineSectionsCompressed, but compressed, because
    /// the section sizes are for the decompressed sections,
    /// it's necessary to decompress the data into a separated file or ram
    /// memory before accessing the section data.
    InlineCompressed(InlineCompressedSections),
}

#[allow(private_bounds)]
pub trait IDBFormat: Sealed {
    type ID0Location;
    type ID1Location;
    type NamLocation;
    type TilLocation;
    fn id0_location(&self) -> Option<Self::ID0Location>;
    fn read_id0<I: BufRead + Seek>(
        &self,
        input: I,
        id0: Self::ID0Location,
    ) -> Result<ID0SectionVariants>;
    fn id1_location(&self) -> Option<Self::ID1Location>;
    fn read_id1<I: BufRead + Seek>(
        &self,
        input: I,
        id1: Self::ID1Location,
    ) -> Result<ID1Section>;
    fn nam_location(&self) -> Option<Self::NamLocation>;
    fn read_nam<I: BufRead + Seek>(
        &self,
        input: I,
        nam: Self::NamLocation,
    ) -> Result<NamSection>;
    fn til_location(&self) -> Option<Self::TilLocation>;
    fn read_til<I: BufRead + Seek>(
        &self,
        input: I,
        til: Self::TilLocation,
    ) -> Result<TILSection>;
    fn decompress_til<I: BufRead + Seek, O: Write>(
        &self,
        input: I,
        output: O,
        til: Self::TilLocation,
    ) -> Result<()>;
}
impl<S: IDBFormat> Sealed for S {}

#[derive(Debug, Clone, Copy, Deserialize)]
struct IDBHeaderRaw {
    magic: IDBMagic,
    _padding_0: u16,
    offsets: [u8; 20],
    signature: u32,
    version: IDBVersion,
}

impl IDBFormats {
    /// Identify the file IDB format.
    pub fn identify_file<I: Read>(input: &mut I) -> Result<Self> {
        // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x77eef0
        // InnerRef expects the file to be at least 112 bytes,
        // always read 109 bytes.
        let raw: IDBHeaderRaw = bincode::deserialize_from(&mut *input)?;
        ensure!(
            raw.signature == 0xAABB_CCDD,
            "Invalid header signature {:#x}",
            raw.signature
        );
        // TODO associate header.version and magic?
        match raw.version {
            // TODO what about 2 and 3?
            IDBVersion::PreV910(version) => {
                SeparatedSections::read(raw, version, input)
                    .map(IDBFormats::Separated)
            }
            IDBVersion::PostV910(version @ IDBInlineVersion::V910) => {
                Self::read_post_910(raw, version, input)
            }
        }
    }

    fn read_post_910(
        raw_header: IDBHeaderRaw,
        version: IDBInlineVersion,
        input: impl Read,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V910Raw {
            compression: u8,
            sectors: [u64; 6],
            // TODO the offset of the unknown data betwen the header and
            // compressed data
            _unk1: u64,
            // TODO the strange data from _unk1 seems to be this number of u64s
            _unk2: u32,
            md5: [u8; 16],
        }
        let raw: V910Raw = bincode::deserialize_from(input)?;

        let header_size =
            u64::from_le_bytes(raw_header.offsets[0..8].try_into().unwrap());
        let data_start =
            u64::from_le_bytes(raw_header.offsets[8..16].try_into().unwrap());
        let _unk3 =
            u32::from_le_bytes(raw_header.offsets[16..20].try_into().unwrap());

        ensure!(header_size != 0);
        // TODO ensure other header data is empty based on the header_size

        let data_start = NonZeroU64::new(data_start)
            .ok_or_else(|| anyhow!("Invalid Header data start offset"))?;

        // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x077f669 read
        // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x077ebf9 unpack
        let sectors: [Option<_>; 6] = raw.sectors.map(NonZeroU64::new);

        let compression = IDBSectionCompression::from_raw(raw.compression)
            .map_err(|_| anyhow!("Invalid V910 header compression"))?;

        let sections = InlineSections {
            magic: raw_header.magic,
            version,
            id0_size: sectors[0],
            id1_size: sectors[1],
            nam_size: sectors[2],
            id2_size: sectors[3],
            til_size: sectors[4],
            seg_size: sectors[5],
            md5: raw.md5,
        };

        match compression {
            Some(compression) => {
                Ok(Self::InlineCompressed(InlineCompressedSections {
                    compression,
                    data_start,
                    sections,
                }))
            }
            None => Ok(Self::InlineUncompressed(InlineUnCompressedSections {
                data_start: data_start.get(),
                sections,
            })),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeparatedSections {
    magic: IDBMagic,
    version: IDBSeparatedVersion,
    id0: Option<SeparatedSection>,
    id1: Option<SeparatedSection>,
    id2: Option<SeparatedSection>,
    nam: Option<SeparatedSection>,
    seg: Option<SeparatedSection>,
    til: Option<SeparatedSection>,
}

impl SeparatedSections {
    pub fn id0_location(&self) -> Option<ID0Offset> {
        self.id0.map(|x| x.offset.get()).map(ID0Offset)
    }

    pub fn id1_location(&self) -> Option<ID1Offset> {
        self.id1.map(|x| x.offset.get()).map(ID1Offset)
    }

    pub fn nam_location(&self) -> Option<NamOffset> {
        self.nam.map(|x| x.offset.get()).map(NamOffset)
    }

    pub fn til_location(&self) -> Option<TILOffset> {
        self.til.map(|x| x.offset.get()).map(TILOffset)
    }

    pub fn read_id0<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        id0: ID0Offset,
    ) -> Result<ID0SectionVariants> {
        input.seek(SeekFrom::Start(id0.0))?;
        // TODO find the InnerRef and check the magic/version relation here
        if self.magic.is_64() {
            read_section_from_header::<ID0Section<IDA64>, _, IDA64>(
                input,
                self.version,
            )
            .map(ID0SectionVariants::IDA64)
        } else {
            read_section_from_header::<ID0Section<IDA32>, _, IDA32>(
                input,
                self.version,
            )
            .map(ID0SectionVariants::IDA32)
        }
    }

    pub fn read_id1<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        id1: ID1Offset,
    ) -> Result<ID1Section> {
        input.seek(SeekFrom::Start(id1.0))?;
        // TODO find the InnerRef and check the magic/version relation here
        if self.magic.is_64() {
            read_section_from_header::<ID1Section, _, IDA64>(
                input,
                self.version,
            )
        } else {
            read_section_from_header::<ID1Section, _, IDA32>(
                input,
                self.version,
            )
        }
    }

    pub fn read_nam<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        nam: NamOffset,
    ) -> Result<NamSection> {
        input.seek(SeekFrom::Start(nam.0))?;
        // TODO find the InnerRef and check the magic/version relation here
        if self.magic.is_64() {
            read_section_from_header::<NamSection, _, IDA64>(
                input,
                self.version,
            )
        } else {
            read_section_from_header::<NamSection, _, IDA32>(
                input,
                self.version,
            )
        }
    }

    pub fn read_til<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        til: TILOffset,
    ) -> Result<TILSection> {
        input.seek(SeekFrom::Start(til.0))?;
        // TODO find the InnerRef and check the magic/version relation here
        if self.magic.is_64() {
            read_section_from_header::<TILSection, _, IDA64>(
                input,
                self.version,
            )
        } else {
            read_section_from_header::<TILSection, _, IDA32>(
                input,
                self.version,
            )
        }
    }

    pub fn decompress_til<I: IdbBufRead + Seek, O: Write>(
        &self,
        mut input: I,
        output: O,
        til: TILOffset,
    ) -> Result<()> {
        input.seek(SeekFrom::Start(til.0))?;
        let section_header = IDBSectionHeader::read(self.version, &mut input)?;
        match section_header.compress {
            Some(IDBSectionCompression::Zlib) => {
                let mut input =
                    BufReader::new(flate2::bufread::ZlibDecoder::new(input));
                TILSection::decompress(&mut input, output)
            }
            None => TILSection::decompress(input, output),
            Some(IDBSectionCompression::Zstd) => {
                let mut input =
                    BufReader::new(zstd::Decoder::with_buffer(input)?);
                TILSection::decompress(&mut input, output)
            }
        }
    }
}

impl IDBFormat for SeparatedSections {
    type ID0Location = ID0Offset;
    type ID1Location = ID1Offset;
    type NamLocation = NamOffset;
    type TilLocation = TILOffset;

    fn id0_location(&self) -> Option<Self::ID0Location> {
        self.id0_location()
    }

    fn read_id0<I: IdbBufRead + Seek>(
        &self,
        input: I,
        id0: Self::ID0Location,
    ) -> Result<ID0SectionVariants> {
        self.read_id0(input, id0)
    }

    fn id1_location(&self) -> Option<Self::ID1Location> {
        self.id1_location()
    }

    fn read_id1<I: IdbBufRead + Seek>(
        &self,
        input: I,
        id1: Self::ID1Location,
    ) -> Result<ID1Section> {
        self.read_id1(input, id1)
    }

    fn nam_location(&self) -> Option<Self::NamLocation> {
        self.nam_location()
    }

    fn read_nam<I: IdbBufRead + Seek>(
        &self,
        input: I,
        nam: Self::NamLocation,
    ) -> Result<NamSection> {
        self.read_nam(input, nam)
    }

    fn til_location(&self) -> Option<Self::TilLocation> {
        self.til_location()
    }

    fn read_til<I: IdbBufRead + Seek>(
        &self,
        input: I,
        til: Self::TilLocation,
    ) -> Result<TILSection> {
        self.read_til(input, til)
    }

    fn decompress_til<I: BufRead + Seek, O: Write>(
        &self,
        input: I,
        output: O,
        til: Self::TilLocation,
    ) -> Result<()> {
        self.decompress_til(input, output, til)
    }
}

#[derive(Debug, Clone, Copy)]
enum IDBVersion {
    PreV910(IDBSeparatedVersion),
    PostV910(IDBInlineVersion),
}

impl<'de> Deserialize<'de> for IDBVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = IDBVersion;
            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                write!(formatter, "an IDB version u16")
            }

            fn visit_u16<E: serde::de::Error>(
                self,
                v: u16,
            ) -> std::result::Result<Self::Value, E> {
                match v {
                    1 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V1)),
                    // TODO what about 2 and 3?
                    4 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V4)),
                    5 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V5)),
                    6 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V6)),
                    910 => Ok(IDBVersion::PostV910(IDBInlineVersion::V910)),
                    value => Err(E::invalid_value(
                        serde::de::Unexpected::Unsigned(value.into()),
                        &"u16 value (1 | 4..=6 | 910)",
                    )),
                }
            }
        }
        deserializer.deserialize_u16(Visitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IDBSeparatedVersion {
    // TODO add other versions
    V1 = 1,
    V4 = 4,
    V5 = 5,
    V6 = 6,
    // NOTE after V6 comes the V910 in IDBInlineVersion
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBInlineVersion {
    V910 = 910,
    // NOTE more will be added in the future
}

fn get_section_u32(
    offset: &[u8],
    checksum: u32,
) -> Result<Option<SeparatedSection>> {
    let offset = u32::from_le_bytes(offset.try_into().unwrap());
    get_section(offset.into(), checksum)
}

fn get_section_u64(
    offset: &[u8],
    checksum: u32,
) -> Result<Option<SeparatedSection>> {
    let offset = u64::from_le_bytes(offset.try_into().unwrap());
    get_section(offset, checksum)
}

fn get_section(offset: u64, checksum: u32) -> Result<Option<SeparatedSection>> {
    #[cfg(feature = "restrictive")]
    if offset == 0 && checksum != 0 {
        return Err(anyhow!("Section have no offset but a valid checksum"));
    }
    SeparatedSection::new(offset, checksum)
}

impl SeparatedSections {
    fn read<I: Read>(
        raw_header: IDBHeaderRaw,
        version: IDBSeparatedVersion,
        input: I,
    ) -> Result<Self> {
        match version {
            IDBSeparatedVersion::V1 | IDBSeparatedVersion::V4 => {
                SeparatedSections::read_v1_4(raw_header, version, input)
            }
            IDBSeparatedVersion::V5 | IDBSeparatedVersion::V6 => {
                SeparatedSections::read_v5_6(raw_header, version, input)
            }
        }
    }

    fn read_v1_4<I: Read>(
        raw_header: IDBHeaderRaw,
        version: IDBSeparatedVersion,
        input: I,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct Raw {
            _id2_offset: u32,
            checksums: [u32; 5],
            //// TODO check that on V4
            //_unk38_zeroed: [u8; 8],
            //_unk40_v5c: u32,
        }
        let raw: Raw = bincode::deserialize_from(input)?;

        let id0 = get_section_u32(&raw_header.offsets[0..4], raw.checksums[0])?;
        let id1 = get_section_u32(&raw_header.offsets[4..8], raw.checksums[1])?;
        let nam =
            get_section_u32(&raw_header.offsets[8..12], raw.checksums[2])?;
        let seg =
            get_section_u32(&raw_header.offsets[12..16], raw.checksums[3])?;
        let til =
            get_section_u32(&raw_header.offsets[16..20], raw.checksums[4])?;

        #[cfg(feature = "restrictive")]
        {
            // TODO ensure the rest of the header is just zeros
        }

        Ok(Self {
            magic: raw_header.magic,
            version,
            id0,
            id1,
            nam,
            seg,
            til,
            id2: None,
        })
    }

    fn read_v5_6<I: Read>(
        raw_header: IDBHeaderRaw,
        version: IDBSeparatedVersion,
        input: I,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct Raw {
            nam_offset: u64,
            seg_offset: u64,
            til_offset: u64,
            checksums: [u32; 5],
            id2_offset: u64,
            id2_checksum: u32,
        }
        let raw: Raw = bincode::deserialize_from(input)?;

        #[cfg(feature = "restrictive")]
        {
            // TODO ensure the rest of the header is just zeros
        }

        let id0 = get_section_u64(&raw_header.offsets[0..8], raw.checksums[0])?;
        let id1 =
            get_section_u64(&raw_header.offsets[8..16], raw.checksums[1])?;
        // TODO always 0?
        let _unknown =
            u32::from_le_bytes(raw_header.offsets[16..20].try_into().unwrap());
        let nam = SeparatedSection::new(raw.nam_offset, raw.checksums[2])?;
        let seg = SeparatedSection::new(raw.seg_offset, raw.checksums[3])?;
        let til = SeparatedSection::new(raw.til_offset, raw.checksums[4])?;
        let id2 = SeparatedSection::new(raw.id2_offset, raw.id2_checksum)?;

        Ok(Self {
            magic: raw_header.magic,
            version,
            id0,
            id1,
            nam,
            seg,
            til,
            id2,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeparatedSection {
    offset: NonZeroU64,
    checksum: u32,
}

impl SeparatedSection {
    fn new(offset: u64, checksum: u32) -> Result<Option<Self>> {
        match (offset, checksum) {
            // no offset, no checksum, this section simply don't exit
            (0, 0) => Ok(None),
            // have a valid offset, there is a section there
            (1.., _) => Ok(Some(Self {
                offset: NonZeroU64::new(offset).unwrap(),
                checksum,
            })),
            // don't have the section offset, but have a valid checksum,
            // we can ignore it, but this checksum is invalid
            #[cfg(not(feature = "restrictive"))]
            (0, 1..) => Ok(None),
            #[cfg(feature = "restrictive")]
            (0, 1..) => {
                Err(anyhow!("Missing section offset with set checksum"))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InlineSectionsTypes {
    Compressed(InlineCompressedSections),
    Uncompressed(InlineUnCompressedSections),
}

#[allow(private_bounds)]
pub trait IDBLocation: Sealed {
    fn idb_offset(&self) -> u64;
    fn idb_size(&self) -> u64;
}

macro_rules! impl_idb_location {
    ($name:ident) => {
        impl Sealed for $name {}
        impl IDBLocation for $name {
            fn idb_offset(&self) -> u64 {
                self.0
            }
            fn idb_size(&self) -> u64 {
                self.1
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID0Location(u64, u64);
impl_idb_location!(ID0Location);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID1Location(u64, u64);
impl_idb_location!(ID1Location);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamLocation(u64, u64);
impl_idb_location!(NamLocation);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TILLocation(u64, u64);
impl_idb_location!(TILLocation);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InlineCompressedSections {
    /// compression used on the section data
    compression: IDBSectionCompression,
    data_start: NonZeroU64,
    sections: InlineSections,
}

impl InlineCompressedSections {
    /// Decompress the IDB data into memory, all sections should be read from
    /// the produced Vec.
    pub fn decompress_into_memory<I: IdbRead + Seek>(
        self,
        input: I,
        output: &mut Vec<u8>,
    ) -> Result<InlineUnCompressedSections> {
        let mut output = std::io::Cursor::new(output);
        Self::decompress_into_file(self, input, &mut output)
    }

    pub fn decompress_into_file<I: IdbRead + Seek, O: Write>(
        self,
        mut input: I,
        mut output: O,
    ) -> Result<InlineUnCompressedSections> {
        input.seek(SeekFrom::Start(self.data_start.get()))?;
        match self.compression {
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                let _ = std::io::copy(&mut input, &mut output)?;
            }
            IDBSectionCompression::Zstd => {
                let mut input = zstd::Decoder::new(input)?;
                let _ = std::io::copy(&mut input, &mut output)?;
            }
        }
        let sections = InlineUnCompressedSections {
            data_start: 0,
            sections: self.sections,
        };
        Ok(sections)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InlineUnCompressedSections {
    /// section data start in the IDB file
    data_start: u64,
    /// section sizes
    sections: InlineSections,
}

impl InlineUnCompressedSections {
    pub fn id0_location(&self) -> Option<ID0Location> {
        self.sections.id0_size.map(|size| {
            ID0Location(
                self.sections.id0_offset_raw(self.data_start),
                size.get(),
            )
        })
    }

    pub fn id1_location(&self) -> Option<ID1Location> {
        self.sections.id1_size.map(|size| {
            ID1Location(
                self.sections.id1_offset_raw(self.data_start),
                size.get(),
            )
        })
    }

    pub fn nam_location(&self) -> Option<NamLocation> {
        self.sections.nam_size.map(|size| {
            NamLocation(
                self.sections.nam_offset_raw(self.data_start),
                size.get(),
            )
        })
    }

    pub fn til_location(&self) -> Option<TILLocation> {
        self.sections.til_size.map(|size| {
            TILLocation(
                self.sections.til_offset_raw(self.data_start),
                size.get(),
            )
        })
    }

    pub fn read_id0<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        ID0Location(offset, len): ID0Location,
    ) -> Result<ID0SectionVariants> {
        input.seek(SeekFrom::Start(offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        if self.sections.magic.is_64() {
            read_section_uncompressed::<ID0Section<IDA64>, _, IDA64>(input, len)
                .map(ID0SectionVariants::IDA64)
        } else {
            read_section_uncompressed::<ID0Section<IDA32>, _, IDA32>(input, len)
                .map(ID0SectionVariants::IDA32)
        }
    }

    pub fn read_id1<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        ID1Location(offset, len): ID1Location,
    ) -> Result<ID1Section> {
        input.seek(SeekFrom::Start(offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        if self.sections.magic.is_64() {
            read_section_uncompressed::<ID1Section, _, IDA64>(input, len)
        } else {
            read_section_uncompressed::<ID1Section, _, IDA32>(input, len)
        }
    }

    pub fn read_nam<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        NamLocation(offset, len): NamLocation,
    ) -> Result<NamSection> {
        input.seek(SeekFrom::Start(offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        input.seek(SeekFrom::Start(offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        if self.sections.magic.is_64() {
            read_section_uncompressed::<NamSection, _, IDA64>(input, len)
        } else {
            read_section_uncompressed::<NamSection, _, IDA32>(input, len)
        }
    }

    pub fn read_til<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        TILLocation(offset, len): TILLocation,
    ) -> Result<TILSection> {
        input.seek(SeekFrom::Start(offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        if self.sections.magic.is_64() {
            read_section_uncompressed::<TILSection, _, IDA64>(input, len)
        } else {
            read_section_uncompressed::<TILSection, _, IDA32>(input, len)
        }
    }

    pub fn decompress_til<I: IdbBufRead + Seek, O: Write>(
        &self,
        mut input: I,
        output: O,
        TILLocation(offset, size): TILLocation,
    ) -> Result<()> {
        input.seek(SeekFrom::Start(offset))?;
        let input = input.take(size);
        TILSection::decompress(input, output)
    }
}

impl IDBFormat for InlineUnCompressedSections {
    type ID0Location = ID0Location;
    type ID1Location = ID1Location;
    type NamLocation = NamLocation;
    type TilLocation = TILLocation;

    fn id0_location(&self) -> Option<Self::ID0Location> {
        self.id0_location()
    }

    fn read_id0<I: BufRead + Seek>(
        &self,
        input: I,
        id0: Self::ID0Location,
    ) -> Result<ID0SectionVariants> {
        self.read_id0(input, id0)
    }

    fn id1_location(&self) -> Option<Self::ID1Location> {
        self.id1_location()
    }

    fn read_id1<I: BufRead + Seek>(
        &self,
        input: I,
        id1: Self::ID1Location,
    ) -> Result<ID1Section> {
        self.read_id1(input, id1)
    }

    fn nam_location(&self) -> Option<Self::NamLocation> {
        self.nam_location()
    }

    fn read_nam<I: BufRead + Seek>(
        &self,
        input: I,
        nam: Self::NamLocation,
    ) -> Result<NamSection> {
        self.read_nam(input, nam)
    }

    fn til_location(&self) -> Option<Self::TilLocation> {
        self.til_location()
    }

    fn read_til<I: BufRead + Seek>(
        &self,
        input: I,
        til: Self::TilLocation,
    ) -> Result<TILSection> {
        self.read_til(input, til)
    }

    fn decompress_til<I: BufRead + Seek, O: Write>(
        &self,
        input: I,
        output: O,
        til: Self::TilLocation,
    ) -> Result<()> {
        self.decompress_til(input, output, til)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InlineSections {
    magic: IDBMagic,
    version: IDBInlineVersion,
    id0_size: Option<NonZeroU64>,
    id1_size: Option<NonZeroU64>,
    nam_size: Option<NonZeroU64>,
    id2_size: Option<NonZeroU64>,
    til_size: Option<NonZeroU64>,
    seg_size: Option<NonZeroU64>,
    md5: [u8; 16],
}

impl InlineSections {
    const fn id0_offset_raw(&self, start: u64) -> u64 {
        start
    }
    const fn id1_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.id0_offset_raw(start);
        if let Some(size) = self.id0_size {
            offset += size.get()
        }
        offset
    }
    const fn nam_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.id1_offset_raw(start);
        if let Some(size) = self.id1_size {
            offset += size.get()
        }
        offset
    }
    const fn id2_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.nam_offset_raw(start);
        if let Some(size) = self.nam_size {
            offset += size.get()
        }
        offset
    }
    const fn til_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.id2_offset_raw(start);
        if let Some(size) = self.id2_size {
            offset += size.get()
        }
        offset
    }
    const fn _seg_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.til_offset_raw(start);
        if let Some(size) = self.til_size {
            offset += size.get()
        }
        offset
    }
}

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

trait SectionReader<K: IDAKind> {
    type Result;
    fn read_section<I: IdbReadKind<K> + IdbBufRead>(
        reader: &mut I,
    ) -> Result<Self::Result>;
}

// read the header from the disk
fn read_section_from_header<F, I, K>(
    mut input: I,
    version: IDBSeparatedVersion,
) -> Result<F::Result>
where
    I: IdbBufRead,
    K: IDAKind,
    F: SectionReader<K>,
{
    let section_header = IDBSectionHeader::read(version, &mut input)?;
    read_section::<F, _, _>(input, section_header.compress, section_header.len)
}

fn read_section<F, I, K>(
    input: I,
    compress: Option<IDBSectionCompression>,
    len: u64,
) -> Result<F::Result>
where
    I: IdbBufRead,
    K: IDAKind,
    F: SectionReader<K>,
{
    match compress {
        None => read_section_uncompressed::<F, I, K>(input, len),
        Some(IDBSectionCompression::Zlib) => {
            // TODO seems its normal to have a few extra bytes at the end of the sector, maybe
            // because of the compressions stuff, anyway verify that
            let input = std::io::Read::take(input, len);
            let mut flate_reader =
                BufReader::new(flate2::read::ZlibDecoder::new(input));
            let result = F::read_section(&mut flate_reader)?;
            let input_inner = flate_reader.into_inner().into_inner();
            let limit = input_inner.limit();
            ensure!(
                limit <= 16,
                "Compressed Zlib Sector have more data then expected, left {limit} bytes",
            );
            Ok(result)
        }
        Some(IDBSectionCompression::Zstd) => {
            let input = std::io::Read::take(input, len);
            let mut zstd_reader = BufReader::new(zstd::Decoder::new(input)?);
            let result = F::read_section(&mut zstd_reader)?;
            let input_inner = zstd_reader.into_inner().finish().into_inner();
            let limit = input_inner.limit();
            ensure!(
                limit <= 16,
                "Compressed Zstd Sector have more data then expected, left {limit} bytes",
            );
            Ok(result)
        }
    }
}

fn read_section_uncompressed<F, I, K>(input: I, len: u64) -> Result<F::Result>
where
    I: IdbBufRead,
    K: IDAKind,
    F: SectionReader<K>,
{
    let mut input = std::io::Read::take(input, len);
    let result = F::read_section(&mut input)?;
    ensure!(
        input.limit() == 0,
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

impl<'de> Deserialize<'de> for IDBMagic {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor {}
        impl serde::de::Visitor<'_> for Visitor {
            type Value = IDBMagic;
            fn expecting(
                &self,
                formatter: &mut core::fmt::Formatter,
            ) -> core::fmt::Result {
                write!(formatter, "4 bytes")
            }
            fn visit_u32<E: serde::de::Error>(
                self,
                v: u32,
            ) -> Result<Self::Value, E> {
                match &v.to_le_bytes()[..] {
                    b"IDA0" => Ok(IDBMagic::IDA0),
                    b"IDA1" => Ok(IDBMagic::IDA1),
                    b"IDA2" => Ok(IDBMagic::IDA2),
                    _value => Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(v.into()),
                        &"IDA0, IDA1 or IDA2",
                    )),
                }
            }
        }
        deserializer.deserialize_u32(Visitor {})
    }
}

// TODO delete this
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

// NOTE V910 ditched the SectionHeader
#[derive(Debug, Clone, Copy)]
struct IDBSectionHeader {
    compress: Option<IDBSectionCompression>,
    len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IDBSectionCompression {
    Zlib,
    /// Introduced in version 9.1
    Zstd,
}

impl IDBSectionCompression {
    pub fn from_raw(value: u8) -> Result<Option<Self>> {
        match value {
            0 => Ok(None),
            2 => Ok(Some(Self::Zlib)),
            3 => Ok(Some(Self::Zstd)),
            // TODO find the value 1, maybe in a deprecated old version?
            _ => Err(anyhow!("Invalid value for IDBSection Compression")),
        }
    }

    pub fn into_raw(value: Option<Self>) -> u8 {
        match value {
            None => 0,
            Some(Self::Zlib) => 2,
            Some(Self::Zstd) => 3,
        }
    }
}

impl IDBSectionHeader {
    fn read(version: IDBSeparatedVersion, input: impl Read) -> Result<Self> {
        use IDBSeparatedVersion::*;
        // TODO use Magic version here? it seems related. Check the InnerRef
        match version {
            V1 | V4 => {
                #[derive(Debug, Deserialize)]
                struct Section32Raw {
                    compress: u8,
                    len: u32,
                }
                let header: Section32Raw = bincode::deserialize_from(input)?;
                Ok(IDBSectionHeader {
                    compress: IDBSectionCompression::from_raw(header.compress)
                        .map_err(|_| anyhow!("Invalid compression code"))?,
                    len: header.len.into(),
                })
            }
            V5 | V6 => {
                #[derive(Debug, Deserialize)]
                struct Section64Raw {
                    compress: u8,
                    len: u64,
                }
                let header: Section64Raw = bincode::deserialize_from(input)?;
                Ok(IDBSectionHeader {
                    compress: IDBSectionCompression::from_raw(header.compress)
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
        use std::fmt::Write;
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
    use std::io::{BufRead, BufReader, Cursor, Seek};
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
        let mut input = BufReader::new(File::open(&filename).unwrap());
        let format = IDBFormats::identify_file(&mut input).unwrap();
        match format {
            IDBFormats::Separated(sections) => {
                parse_idb_separated(&mut input, &sections)
            }
            IDBFormats::InlineUncompressed(sections) => {
                parse_idb_inlined(&mut input, &sections)
            }
            IDBFormats::InlineCompressed(compressed) => {
                let mut decompressed = Vec::new();
                let sections = compressed
                    .decompress_into_memory(input, &mut decompressed)
                    .unwrap();
                parse_idb_inlined(&mut Cursor::new(decompressed), &sections);
            }
        }
    }

    fn parse_idb_separated<I>(input: &mut I, sections: &SeparatedSections)
    where
        I: BufRead + Seek,
    {
        // parse sectors
        let id0 = sections
            .read_id0(&mut *input, sections.id0_location().unwrap())
            .unwrap();
        let til = sections
            .til_location()
            .map(|til| sections.read_til(&mut *input, til).unwrap());
        match id0 {
            IDAVariants::IDA32(id0_32) => parse_idb_data(&id0_32, til.as_ref()),
            IDAVariants::IDA64(id0_64) => parse_idb_data(&id0_64, til.as_ref()),
        }
        let _ = sections
            .id1_location()
            .map(|idx| sections.read_id1(&mut *input, idx));
        let _ = sections
            .nam_location()
            .map(|idx| sections.read_nam(&mut *input, idx));
    }

    fn parse_idb_inlined<I>(
        input: &mut I,
        sections: &InlineUnCompressedSections,
    ) where
        I: BufRead + Seek,
    {
        // parse sectors
        let id0 = sections
            .read_id0(&mut *input, sections.id0_location().unwrap())
            .unwrap();
        let til = sections
            .til_location()
            .map(|til| sections.read_til(&mut *input, til).unwrap());
        match id0 {
            IDAVariants::IDA32(id0_32) => parse_idb_data(&id0_32, til.as_ref()),
            IDAVariants::IDA64(id0_64) => parse_idb_data(&id0_64, til.as_ref()),
        }
        let _ = sections
            .id1_location()
            .map(|idx| sections.read_id1(&mut *input, idx));
        let _ = sections
            .nam_location()
            .map(|idx| sections.read_nam(&mut *input, idx));
    }

    fn parse_idb_data<K>(id0: &ID0Section<K>, til: Option<&TILSection>)
    where
        K: IDAKind,
    {
        // parse all id0 information
        let _ida_info = id0.ida_info().unwrap();
        let version = match _ida_info {
            id0::IDBParam::V1(x) => x.version,
            id0::IDBParam::V2(x) => x.version,
        };

        let seg_idx = id0.segments_idx().unwrap().unwrap();
        let _: Vec<_> = id0.segments(seg_idx).map(Result::unwrap).collect();
        let _: Option<Vec<_>> = id0
            .loader_name()
            .unwrap()
            .map(|iter| iter.map(Result::unwrap).collect());
        let root_info_idx = id0.root_node().unwrap();
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
        if let Some(func_idx) = id0.funcs_idx().unwrap() {
            let _: Vec<_> = id0
                .functions_and_comments(func_idx)
                .map(Result::unwrap)
                .collect();
        }
        let _ = id0.entry_points().unwrap();
        let _ = id0.dirtree_bpts().unwrap();
        let _ = id0.dirtree_enums().unwrap();
        if let Some(_dirtree_names) = id0.dirtree_names().unwrap() {
            _dirtree_names.visit_leafs(|addr| {
                // NOTE it's know that some label are missing in some databases
                let _name = id0.label_at(*addr).unwrap();
            });
        }
        if let Some((_dirtree_tinfos, til)) =
            id0.dirtree_tinfos().unwrap().zip(til)
        {
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

pub trait IDAKind: std::fmt::Debug + Clone + Copy + 'static {
    const BYTES: u8;
    type Usize: IDAUsize
        + num_traits::AsPrimitive<Self::Isize>
        + num_traits::FromBytes<Bytes = Self::AddrBytes>;
    type Isize: IDAIsize
        + num_traits::AsPrimitive<Self::Usize>
        + num_traits::FromBytes<Bytes = Self::AddrBytes>;
    type AddrBytes: IDAUsizeBytes;

    /// helper function, try convert bytes into Usize
    fn usize_try_from_be_bytes<'a, I: IntoIterator<Item = &'a u8>>(
        bytes: I,
    ) -> Option<Self::Usize> {
        let bytes: Self::AddrBytes = bytes
            .into_iter()
            .copied()
            .collect::<Vec<u8>>()
            .try_into()
            .ok()?;
        let value =
            <Self::Usize as num_traits::FromBytes>::from_be_bytes(&bytes);
        Some(value)
    }

    /// helper function, try convert bytes into Usize
    fn usize_try_from_le_bytes<'a, I: IntoIterator<Item = &'a u8>>(
        bytes: I,
    ) -> Option<Self::Usize> {
        let bytes: Self::AddrBytes = bytes
            .into_iter()
            .copied()
            .collect::<Vec<u8>>()
            .try_into()
            .ok()?;
        let value =
            <Self::Usize as num_traits::FromBytes>::from_le_bytes(&bytes);
        Some(value)
    }
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
    + num_traits::Bounded
    + num_traits::FromBytes
    + num_traits::ToBytes
    + num_traits::AsPrimitive<u8>
    + num_traits::AsPrimitive<u16>
    + num_traits::AsPrimitive<u32>
    + num_traits::AsPrimitive<u64>
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
    + TryFrom<i128>
{
    /// helper fo call into u64
    fn into_u64(self) -> u64 {
        self.into()
    }
    fn is_max(self) -> bool {
        self == Self::max_value()
    }
    fn unpack_from_reader(read: &mut impl std::io::Read) -> Result<Self>;
}

pub trait IDAIsize:
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
    + num_traits::Bounded
    + num_traits::FromBytes
    + num_traits::ToBytes
    + num_traits::AsPrimitive<i8>
    + num_traits::AsPrimitive<i16>
    + num_traits::AsPrimitive<i32>
    + num_traits::AsPrimitive<i64>
    + TryInto<usize, Error: std::fmt::Debug>
    + Into<i64>
    + TryInto<u32, Error: std::fmt::Debug>
    + TryInto<u16, Error: std::fmt::Debug>
    + TryInto<u8, Error: std::fmt::Debug>
    + From<i8>
    + From<i16>
    + From<i32>
    + TryFrom<i64, Error: std::fmt::Debug>
    + TryFrom<usize, Error: std::fmt::Debug>
    + Into<i128>
    + TryFrom<i128>
{
}

pub trait IDAUsizeBytes:
    'static
    + AsRef<[u8]>
    + TryFrom<Vec<u8>, Error: core::fmt::Debug>
    + for<'a> TryFrom<&'a [u8], Error: core::fmt::Debug>
{
    fn from_reader(read: &mut impl std::io::Read) -> Result<Self>;
}

macro_rules! declare_idb_kind {
    ($bytes:literal, $utype:ident, $itype:ident, $name:ident, $unapack_fun:ident) => {
        #[derive(Debug, Clone, Copy)]
        pub struct $name;
        impl IDAKind for $name {
            const BYTES: u8 = $bytes;
            type Usize = $utype;
            type Isize = $itype;
            type AddrBytes = [u8; $bytes];
        }
        impl IDAUsize for $utype {
            fn unpack_from_reader(
                read: &mut impl std::io::Read,
            ) -> Result<Self> {
                read.$unapack_fun()
            }
        }
        impl IDAIsize for $itype {}

        impl IDAUsizeBytes for [u8; $bytes] {
            fn from_reader(read: &mut impl std::io::Read) -> Result<Self> {
                let mut data = [0; $bytes];
                read.read_exact(&mut data)?;
                Ok(data)
            }
        }
    };
}

declare_idb_kind!(4, u32, i32, IDA32, unpack_dd);
declare_idb_kind!(8, u64, i64, IDA64, unpack_dq);

#![forbid(unsafe_code)]
pub mod addr_info;
pub mod bytes_info;
pub mod id0;
pub mod id1;
pub mod id2;
pub(crate) mod ida_reader;
pub mod nam;
#[allow(non_camel_case_types)]
pub mod sdk_comp;
pub mod til;

#[cfg(test)]
mod test;

use id0::ID0Section;
use id1::ID1Section;
use ida_reader::{IdbBufRead, IdbRead, IdbReadKind};
use nam::NamSection;
use til::section::TILSection;

use std::borrow::Cow;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::num::NonZeroU64;

use anyhow::{anyhow, ensure, Result};
use serde::{Deserialize, Serialize};

use crate::id2::ID2Section;

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
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize)]
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

/// Identify the file IDB format.
pub fn identify_idb_file<I: Read>(input: &mut I) -> Result<IDBFormats> {
    // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x77eef0
    // InnerRef expects the file to be at least 112 bytes,
    // always read 109 bytes.
    let mut magic_raw = [0u8; 4];
    input.read_exact(&mut magic_raw)?;
    let magic = IDBMagic::from_raw(magic_raw)?;
    let _padding_0 = input.read_u16()?;
    ensure!(_padding_0 == 0);
    let mut offsets = [0u8; 20];
    input.read_exact(&mut offsets)?;
    let signature = input.read_u32()?;
    let version = (signature == 0xAABB_CCDD)
        .then(|| input.read_u16().and_then(IDBVersion::from_raw))
        .transpose()?;

    // TODO associate header.version and magic?
    use IDBMagic::*;
    use IDBSeparatedVersion::*;
    use IDBVersion::*;
    match (magic, version) {
        (IDA0, None) => read_pre_500_header(offsets)
            .map(IDAVariants::IDA32)
            .map(IDBFormats::Separated),
        (IDA0, version) => {
            Err(anyhow!("Invalid version for ID0 magic: {version:?}"))
        }
        (_, None) => Err(anyhow!("Invalid IDA0 magic for ID0 version")),
        (IDA1 | IDA2, Some(PreV910(version @ (V1 | V3 | V4)))) => {
            read_500_600_header(magic.is_64(), offsets, version, input)
        }
        (IDA1 | IDA2, Some(PreV910(version @ (V5 | V6)))) => {
            read_600_900_header(magic.is_64(), offsets, version, input)
        }
        (IDA2, Some(PostV910(version))) => {
            read_910_header(offsets, version, input)
        }
        (IDA1, Some(PostV910(_))) => Err(anyhow!(
            "After version 910 the 32bits version of IDA was dropped"
        )),
    }
}

fn read_pre_500_header(offsets: [u8; 20]) -> Result<SeparatedSections<IDA32>> {
    let id0 = SeparatedSection::new::<IDA32>(&offsets[0..4], None)?;
    let id1 = SeparatedSection::new::<IDA32>(&offsets[4..8], None)?;
    let nam = SeparatedSection::new::<IDA32>(&offsets[8..12], None)?;
    let seg = SeparatedSection::new::<IDA32>(&offsets[12..16], None)?;
    let til = SeparatedSection::new::<IDA32>(&offsets[16..20], None)?;

    #[cfg(feature = "restrictive")]
    {
        // TODO ensure the rest of the header is just zeros
    }

    Ok(SeparatedSections {
        _kind: PhantomData,
        magic: IDBMagic::IDA0,
        version: None,
        id0,
        id1,
        nam,
        seg,
        til,
        id2: None,
    })
}

fn read_500_600_header<I: IdbRead>(
    is_64: bool,
    offsets: [u8; 20],
    version: IDBSeparatedVersion,
    input: &mut I,
) -> Result<IDBFormats> {
    let id2_offset = input.read_u32()?;
    ensure!(id2_offset == 0);
    let checksums: [u32; 5] = bincode::deserialize_from(input)?;

    let id0 =
        SeparatedSection::new::<IDA32>(&offsets[0..4], Some(checksums[0]))?;
    let id1 =
        SeparatedSection::new::<IDA32>(&offsets[4..8], Some(checksums[1]))?;
    let nam =
        SeparatedSection::new::<IDA32>(&offsets[8..12], Some(checksums[2]))?;
    let seg =
        SeparatedSection::new::<IDA32>(&offsets[12..16], Some(checksums[3]))?;
    let til =
        SeparatedSection::new::<IDA32>(&offsets[16..20], Some(checksums[4]))?;

    #[cfg(feature = "restrictive")]
    {
        // TODO ensure the rest of the header is just zeros
    }

    let magic = if is_64 {
        IDBMagic::IDA2
    } else {
        IDBMagic::IDA1
    };
    if is_64 {
        Ok(IDBFormats::Separated(IDAVariants::IDA64(
            SeparatedSections {
                _kind: PhantomData,
                magic,
                version: Some(version),
                id0,
                id1,
                nam,
                seg,
                til,
                id2: None,
            },
        )))
    } else {
        Ok(IDBFormats::Separated(IDAVariants::IDA32(
            SeparatedSections {
                _kind: PhantomData,
                magic,
                version: Some(version),
                id0,
                id1,
                nam,
                seg,
                til,
                id2: None,
            },
        )))
    }
}

fn read_600_900_header<I: IdbRead>(
    is_64: bool,
    offsets: [u8; 20],
    version: IDBSeparatedVersion,
    input: &mut I,
) -> Result<IDBFormats> {
    let nam_offset = input.read_u64()?;
    let seg_offset = input.read_u64()?;
    let til_offset = input.read_u64()?;
    let checksums: [u32; 5] = bincode::deserialize_from(&mut *input)?;
    let id2_offset = input.read_u64()?;
    let _unk2 = input.read_u32()?;

    #[cfg(feature = "restrictive")]
    {
        // TODO ensure the rest of the header is just zeros
    }

    let id0 =
        SeparatedSection::new::<IDA64>(&offsets[0..8], Some(checksums[0]))?;
    let id1 =
        SeparatedSection::new::<IDA64>(&offsets[8..16], Some(checksums[1]))?;
    // TODO always 0?
    let _unknown = u32::from_le_bytes(offsets[16..20].try_into().unwrap());
    let nam =
        SeparatedSection::new_inner::<IDA64>(nam_offset, Some(checksums[2]))?;
    let seg =
        SeparatedSection::new_inner::<IDA64>(seg_offset, Some(checksums[3]))?;
    let til =
        SeparatedSection::new_inner::<IDA64>(til_offset, Some(checksums[4]))?;
    // TODO find the checksums
    let id2 = SeparatedSection::new_inner::<IDA64>(id2_offset, None)?;

    if is_64 {
        Ok(IDBFormats::Separated(IDAVariants::IDA64(
            SeparatedSections {
                _kind: PhantomData,
                magic: IDBMagic::IDA2,
                version: Some(version),
                id0,
                id1,
                nam,
                seg,
                til,
                id2,
            },
        )))
    } else {
        Ok(IDBFormats::Separated(IDAVariants::IDA32(
            SeparatedSections {
                _kind: PhantomData,
                version: Some(version),
                magic: IDBMagic::IDA1,
                id0,
                id1,
                nam,
                seg,
                til,
                id2,
            },
        )))
    }
}

fn read_910_header(
    offsets: [u8; 20],
    version: IDBInlineVersion,
    input: &mut impl IdbRead,
) -> Result<IDBFormats> {
    match version {
        // This code is here just to cause an error on compilation when a new
        // version is added
        IDBInlineVersion::V910 => {}
    }
    let compression = input.read_u8()?;
    let compression = IDBSectionCompression::from_raw(compression)
        .map_err(|_| anyhow!("Invalid V910 header compression"))?;
    let id0_size = input.read_u64()?;
    let id1_size = input.read_u64()?;
    let nam_size = input.read_u64()?;
    let id2_size = input.read_u64()?;
    let til_size = input.read_u64()?;
    let seg_size = input.read_u64()?;
    // TODO the offset of the unknown data betwen the header and
    // compressed data
    let _unk1 = input.read_u64();
    // TODO the strange data from _unk1 seems to be this number of u64s
    let _unk2 = input.read_u32();
    let md5: [u8; 16] = bincode::deserialize_from(input)?;

    let header_size = u64::from_le_bytes(offsets[0..8].try_into().unwrap());
    ensure!(header_size != 0);
    let data_start = u64::from_le_bytes(offsets[8..16].try_into().unwrap());
    ensure!(data_start != 0, "Invalid Header data start offset");
    let _unk3 = u32::from_le_bytes(offsets[16..20].try_into().unwrap());
    // TODO ensure other header data is empty based on the header_size

    let sections = InlineSections {
        version,
        id0_size: NonZeroU64::new(id0_size),
        id1_size: NonZeroU64::new(id1_size),
        nam_size: NonZeroU64::new(nam_size),
        id2_size: NonZeroU64::new(id2_size),
        til_size: NonZeroU64::new(til_size),
        seg_size: NonZeroU64::new(seg_size),
        md5,
    };

    match compression {
        Some(compression) => {
            Ok(IDBFormats::InlineCompressed(InlineCompressedSections {
                compression,
                data_start,
                sections,
            }))
        }
        None => {
            Ok(IDBFormats::InlineUncompressed(InlineUnCompressedSections {
                data_start,
                sections,
            }))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum IDBFormats {
    /// File that contains sections, the header will contain the header offsets,
    /// and each section will be preceded by a section-header containing a size
    /// and a compression (if any), each section can be accessed separately
    /// and can always be read directly from the IDB file.
    Separated(IDAVariants<SeparatedSections<IDA32>, SeparatedSections<IDA64>>),
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
pub trait IDBFormat<K: IDAKind>: Sealed {
    type ID0Location;
    type ID1Location;
    type ID2Location;
    type NamLocation;
    type TilLocation;
    fn id0_location(&self) -> Option<Self::ID0Location>;
    fn read_id0<I: IdbReadKind<K> + IdbBufRead + Seek>(
        &self,
        input: I,
        id0: Self::ID0Location,
    ) -> Result<ID0Section<K>>;
    fn id1_location(&self) -> Option<Self::ID1Location>;
    fn read_id1<I: IdbReadKind<K> + IdbBufRead + Seek>(
        &self,
        input: I,
        id1: Self::ID1Location,
    ) -> Result<ID1Section<K>>;
    fn id2_location(&self) -> Option<Self::ID2Location>;
    fn read_id2<I: IdbReadKind<K> + IdbBufRead + Seek>(
        &self,
        input: I,
        id2: Self::ID2Location,
    ) -> Result<ID2Section<K>>;
    fn nam_location(&self) -> Option<Self::NamLocation>;
    fn read_nam<I: IdbReadKind<K> + IdbBufRead + Seek>(
        &self,
        input: I,
        nam: Self::NamLocation,
    ) -> Result<NamSection<K>>;
    fn til_location(&self) -> Option<Self::TilLocation>;
    fn read_til<I: IdbBufRead + Seek>(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeparatedSections<K: IDAKind> {
    _kind: PhantomData<K>,
    magic: IDBMagic,
    version: Option<IDBSeparatedVersion>,
    id0: Option<SeparatedSection>,
    id1: Option<SeparatedSection>,
    id2: Option<SeparatedSection>,
    nam: Option<SeparatedSection>,
    seg: Option<SeparatedSection>,
    til: Option<SeparatedSection>,
}

impl<K: IDAKind> SeparatedSections<K> {
    pub fn id0_location(&self) -> Option<ID0Offset> {
        self.id0.map(|x| x.offset).map(ID0Offset)
    }

    pub fn id1_location(&self) -> Option<ID1Offset> {
        self.id1.map(|x| x.offset).map(ID1Offset)
    }

    pub fn id2_location(&self) -> Option<ID2Offset> {
        self.id2.map(|x| x.offset).map(ID2Offset)
    }

    pub fn nam_location(&self) -> Option<NamOffset> {
        self.nam.map(|x| x.offset).map(NamOffset)
    }

    pub fn til_location(&self) -> Option<TILOffset> {
        self.til.map(|x| x.offset).map(TILOffset)
    }

    pub fn read_id0<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        id0: ID0Offset,
    ) -> Result<ID0Section<K>> {
        input.seek(SeekFrom::Start(id0.0))?;
        read_section_from_header::<ID0Section<K>, _, _>(
            input,
            self.version,
            self.magic,
        )
    }

    pub fn read_id1<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        id1: ID1Offset,
    ) -> Result<ID1Section<K>> {
        input.seek(SeekFrom::Start(id1.0))?;
        read_section_from_header::<ID1Section<K>, _, _>(
            input,
            self.version,
            self.magic,
        )
    }

    pub fn read_id2<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        id1: ID2Offset,
    ) -> Result<ID2Section<K>> {
        input.seek(SeekFrom::Start(id1.0))?;
        // TODO find the InnerRef and check the magic/version relation here
        read_section_from_header::<ID2Section<K>, _, _>(
            input,
            self.version,
            self.magic,
        )
    }

    pub fn read_nam<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        nam: NamOffset,
    ) -> Result<NamSection<K>> {
        input.seek(SeekFrom::Start(nam.0))?;
        read_section_from_header::<NamSection<K>, _, _>(
            input,
            self.version,
            self.magic,
        )
    }

    pub fn read_til<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        til: TILOffset,
    ) -> Result<TILSection> {
        input.seek(SeekFrom::Start(til.0))?;
        read_section_from_header::<TILSection, _, K>(
            input,
            self.version,
            self.magic,
        )
    }

    pub fn decompress_til<I: IdbBufRead + Seek, O: Write>(
        &self,
        mut input: I,
        output: O,
        til: TILOffset,
    ) -> Result<()> {
        input.seek(SeekFrom::Start(til.0))?;
        let section_header = IDBSectionHeader::<K>::read(&mut input)?;
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

impl<K: IDAKind> Sealed for SeparatedSections<K> {}
impl<K: IDAKind> IDBFormat<K> for SeparatedSections<K> {
    type ID0Location = ID0Offset;
    type ID1Location = ID1Offset;
    type ID2Location = ID2Offset;
    type NamLocation = NamOffset;
    type TilLocation = TILOffset;

    fn id0_location(&self) -> Option<Self::ID0Location> {
        self.id0_location()
    }

    fn read_id0<I: IdbBufRead + Seek>(
        &self,
        input: I,
        id0: Self::ID0Location,
    ) -> Result<ID0Section<K>> {
        self.read_id0(input, id0)
    }

    fn id1_location(&self) -> Option<Self::ID1Location> {
        self.id1_location()
    }

    fn id2_location(&self) -> Option<Self::ID2Location> {
        self.id2_location()
    }

    fn read_id1<I: IdbBufRead + Seek>(
        &self,
        input: I,
        id1: Self::ID1Location,
    ) -> Result<ID1Section<K>> {
        self.read_id1(input, id1)
    }

    fn read_id2<I: IdbBufRead + Seek>(
        &self,
        input: I,
        id2: Self::ID2Location,
    ) -> Result<ID2Section<K>> {
        self.read_id2(input, id2)
    }

    fn nam_location(&self) -> Option<Self::NamLocation> {
        self.nam_location()
    }

    fn read_nam<I: IdbBufRead + Seek>(
        &self,
        input: I,
        nam: Self::NamLocation,
    ) -> Result<NamSection<K>> {
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

impl IDBVersion {
    fn from_raw(value: u16) -> Result<Self> {
        match value {
            1 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V1)),
            // TODO what about 2?
            3 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V3)),
            4 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V4)),
            5 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V5)),
            6 => Ok(IDBVersion::PreV910(IDBSeparatedVersion::V6)),
            910 => Ok(IDBVersion::PostV910(IDBInlineVersion::V910)),
            value => Err(anyhow!("Invalid IDBVersion: {value}")),
        }
    }
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
    // Versions: 5.2
    V1 = 1,
    // TODO Version 2?
    // Versions: 6.1
    V3 = 3,
    // TODO find this version
    V4 = 4,
    V5 = 5,
    // Versions: 6.5 6.6 7.0 7.3 7.6 8.3 9.0
    V6 = 6,
    // NOTE after V6 comes the V910 in IDBInlineVersion
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBInlineVersion {
    // Versions: 9.1
    V910 = 910,
    // NOTE more will be added in the future
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeparatedSection {
    offset: u64,
    checksum: Option<u32>,
}

impl SeparatedSection {
    fn new<K: IDAKind>(
        offset: &[u8],
        checksum: Option<u32>,
    ) -> Result<Option<SeparatedSection>> {
        let offset = K::usize_try_from_le_bytes(offset).unwrap();
        Self::new_inner::<K>(offset, checksum)
    }

    fn new_inner<K: IDAKind>(
        offset: K::Usize,
        checksum: Option<u32>,
    ) -> Result<Option<SeparatedSection>> {
        let offset = offset.into_u64();
        match (offset, checksum) {
            // no offset, zero checksum, this section simply don't exit
            (0, Some(0) | None) => Ok(None),
            // if there is no checksum, no inference can be made
            (_, None) => Ok(Some(Self { offset, checksum })),
            // have a valid offset, there is a section there
            (1.., Some(_)) => Ok(Some(Self { offset, checksum })),
            // don't have the section offset, but have a valid checksum,
            // we can ignore it, but this checksum is invalid
            #[cfg(not(feature = "restrictive"))]
            (0, Some(1..)) => Ok(None),
            #[cfg(feature = "restrictive")]
            (0, Some(1..)) => {
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
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name {
            offset: u64,
            size: NonZeroU64,
        }
        impl Sealed for $name {}
        impl IDBLocation for $name {
            fn idb_offset(&self) -> u64 {
                self.offset
            }
            fn idb_size(&self) -> u64 {
                self.size.get()
            }
        }
    };
}

impl_idb_location!(ID0Location);
impl_idb_location!(ID1Location);
impl_idb_location!(ID2Location);
impl_idb_location!(NamLocation);
impl_idb_location!(TILLocation);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InlineCompressedSections {
    /// compression used on the section data
    compression: IDBSectionCompression,
    data_start: u64,
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
        input.seek(SeekFrom::Start(self.data_start))?;
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
            data_start: 0u8.into(),
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
        self.sections.id0_size.map(|size| ID0Location {
            offset: self.sections.id0_offset_raw(self.data_start),
            size,
        })
    }

    pub fn id1_location(&self) -> Option<ID1Location> {
        self.sections.id1_size.map(|size| ID1Location {
            offset: self.sections.id1_offset_raw(self.data_start),
            size,
        })
    }

    pub fn id2_location(&self) -> Option<ID2Location> {
        self.sections.id2_size.map(|size| ID2Location {
            offset: self.sections.id2_offset_raw(self.data_start),
            size,
        })
    }

    pub fn nam_location(&self) -> Option<NamLocation> {
        self.sections.nam_size.map(|size| NamLocation {
            offset: self.sections.nam_offset_raw(self.data_start),
            size,
        })
    }

    pub fn til_location(&self) -> Option<TILLocation> {
        self.sections.til_size.map(|size| TILLocation {
            offset: self.sections.til_offset_raw(self.data_start),
            size,
        })
    }

    pub fn read_id0<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        location: ID0Location,
    ) -> Result<ID0Section<IDA64>> {
        input.seek(SeekFrom::Start(location.offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        read_section_uncompressed::<ID0Section<IDA64>, _, _>(
            input,
            location.size.get(),
            IDBMagic::IDA2,
        )
    }

    pub fn read_id1<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        location: ID1Location,
    ) -> Result<ID1Section<IDA64>> {
        input.seek(SeekFrom::Start(location.offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        read_section_uncompressed::<ID1Section<IDA64>, _, _>(
            input,
            location.size.get(),
            IDBMagic::IDA2,
        )
    }

    pub fn read_id2<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        location: ID2Location,
    ) -> Result<ID2Section<IDA64>> {
        input.seek(SeekFrom::Start(location.offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        read_section_uncompressed::<ID2Section<IDA64>, _, _>(
            input,
            location.size.get(),
            IDBMagic::IDA2,
        )
    }

    pub fn read_nam<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        location: NamLocation,
    ) -> Result<NamSection<IDA64>> {
        input.seek(SeekFrom::Start(location.offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        read_section_uncompressed::<NamSection<IDA64>, _, _>(
            input,
            location.size.get(),
            IDBMagic::IDA2,
        )
    }

    pub fn read_til<I: IdbBufRead + Seek>(
        &self,
        mut input: I,
        location: TILLocation,
    ) -> Result<TILSection> {
        input.seek(SeekFrom::Start(location.offset))?;
        // TODO find the InnerRef and check the magic/version relation here
        read_section_uncompressed::<TILSection, _, IDA64>(
            input,
            location.size.get(),
            IDBMagic::IDA2,
        )
    }

    pub fn decompress_til<I: IdbBufRead + Seek, O: Write>(
        &self,
        mut input: I,
        output: O,
        location: TILLocation,
    ) -> Result<()> {
        input.seek(SeekFrom::Start(location.offset))?;
        let input = input.take(location.size.get());
        TILSection::decompress(input, output)
    }
}

impl Sealed for InlineUnCompressedSections {}
impl IDBFormat<IDA64> for InlineUnCompressedSections {
    type ID0Location = ID0Location;
    type ID1Location = ID1Location;
    type ID2Location = ID2Location;
    type NamLocation = NamLocation;
    type TilLocation = TILLocation;

    fn id0_location(&self) -> Option<Self::ID0Location> {
        self.id0_location()
    }

    fn read_id0<I: BufRead + Seek>(
        &self,
        input: I,
        id0: Self::ID0Location,
    ) -> Result<ID0Section<IDA64>> {
        self.read_id0(input, id0)
    }

    fn id1_location(&self) -> Option<Self::ID1Location> {
        self.id1_location()
    }

    fn read_id1<I: BufRead + Seek>(
        &self,
        input: I,
        id1: Self::ID1Location,
    ) -> Result<ID1Section<IDA64>> {
        self.read_id1(input, id1)
    }

    fn id2_location(&self) -> Option<Self::ID2Location> {
        self.id2_location()
    }

    fn read_id2<I: BufRead + Seek>(
        &self,
        input: I,
        id1: Self::ID2Location,
    ) -> Result<ID2Section<IDA64>> {
        self.read_id2(input, id1)
    }

    fn nam_location(&self) -> Option<Self::NamLocation> {
        self.nam_location()
    }

    fn read_nam<I: BufRead + Seek>(
        &self,
        input: I,
        nam: Self::NamLocation,
    ) -> Result<NamSection<IDA64>> {
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
    fn id0_offset_raw(&self, start: u64) -> u64 {
        start
    }
    fn id1_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.id0_offset_raw(start);
        if let Some(size) = self.id0_size {
            offset += size.get()
        }
        offset
    }
    fn nam_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.id1_offset_raw(start);
        if let Some(size) = self.id1_size {
            offset += size.get()
        }
        offset
    }
    fn id2_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.nam_offset_raw(start);
        if let Some(size) = self.nam_size {
            offset += size.get()
        }
        offset
    }
    fn til_offset_raw(&self, start: u64) -> u64 {
        let mut offset = self.id2_offset_raw(start);
        if let Some(size) = self.id2_size {
            offset += size.get()
        }
        offset
    }
    fn _seg_offset_raw(&self, start: u64) -> u64 {
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
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(u64);
        impl Sealed for $name {}
        impl IDBOffset for $name {
            fn idb_offset(&self) -> u64 {
                self.0
            }
        }
    };
}

impl_idb_offset!(ID0Offset);
impl_idb_offset!(ID1Offset);
impl_idb_offset!(ID2Offset);
impl_idb_offset!(NamOffset);
impl_idb_offset!(TILOffset);

trait SectionReader<K: IDAKind> {
    type Result;
    fn read_section<I: IdbReadKind<K> + IdbBufRead>(
        reader: &mut I,
        magic: IDBMagic,
    ) -> Result<Self::Result>;
}

// read the header from the disk
fn read_section_from_header<F, I, K>(
    mut input: I,
    version: Option<IDBSeparatedVersion>,
    magic: IDBMagic,
) -> Result<F::Result>
where
    I: IdbBufRead,
    K: IDAKind,
    F: SectionReader<K>,
{
    // NOTE section header size is not related to i64/idb it's base on the
    // version
    match version {
        None
        | Some(
            IDBSeparatedVersion::V1
            | IDBSeparatedVersion::V3
            | IDBSeparatedVersion::V4,
        ) => {
            let section_header = IDBSectionHeader::<IDA32>::read(&mut input)?;
            read_section::<F, _, _>(
                input,
                section_header.compress,
                section_header.len.into(),
                magic,
            )
        }
        Some(IDBSeparatedVersion::V5 | IDBSeparatedVersion::V6) => {
            let section_header = IDBSectionHeader::<IDA64>::read(&mut input)?;
            read_section::<F, _, _>(
                input,
                section_header.compress,
                section_header.len.into(),
                magic,
            )
        }
    }
}

fn read_section<F, I, K>(
    input: I,
    compress: Option<IDBSectionCompression>,
    len: u64,
    magic: IDBMagic,
) -> Result<F::Result>
where
    I: IdbBufRead,
    K: IDAKind,
    F: SectionReader<K>,
{
    match compress {
        None => read_section_uncompressed::<F, I, K>(input, len, magic),
        Some(IDBSectionCompression::Zlib) => {
            // TODO seems its normal to have a few extra bytes at the end of the sector, maybe
            // because of the compressions stuff, anyway verify that
            let input = std::io::Read::take(input, len.into_u64());
            let mut flate_reader =
                BufReader::new(flate2::read::ZlibDecoder::new(input));
            let result = F::read_section(&mut flate_reader, magic)?;
            let input_inner = flate_reader.into_inner().into_inner();
            let limit = input_inner.limit();
            ensure!(
                limit <= 16,
                "Compressed Zlib Sector have more data then expected, left {limit} bytes",
            );
            Ok(result)
        }
        Some(IDBSectionCompression::Zstd) => {
            let input = std::io::Read::take(input, len.into_u64());
            let mut zstd_reader = BufReader::new(zstd::Decoder::new(input)?);
            let result = F::read_section(&mut zstd_reader, magic)?;
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

fn read_section_uncompressed<F, I, K>(
    input: I,
    len: u64,
    magic: IDBMagic,
) -> Result<F::Result>
where
    I: IdbBufRead,
    K: IDAKind,
    F: SectionReader<K>,
{
    let mut input = std::io::Read::take(input, len.into_u64());
    let result = F::read_section(&mut input, magic)?;
    ensure!(
        input.limit() == 0,
        "Sector have more data then expected, left {} bytes",
        input.limit()
    );
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IDBMagic {
    // Versions-32bits: 4.1
    IDA0,
    // Versions-32bits: 5.2 6.1 6.5 6.6 6.8 7.0 7.3 7.6 8.3
    IDA1,
    // Versions-64bits: 5.2 6.1 6.5 6.6 6.8 7.0 7.3 7.6 8.3 9.0 9.1
    IDA2,
}

impl IDBMagic {
    fn is_64(&self) -> bool {
        match self {
            IDBMagic::IDA0 | IDBMagic::IDA1 => false,
            IDBMagic::IDA2 => true,
        }
    }

    fn from_raw(value: [u8; 4]) -> Result<Self> {
        match &value {
            b"IDA0" => Ok(IDBMagic::IDA0),
            b"IDA1" => Ok(IDBMagic::IDA1),
            b"IDA2" => Ok(IDBMagic::IDA2),
            _value => Err(anyhow!(
                "Invalid IDA Magic {value:?}, expect IDA0 IDA1 or IDA2"
            )),
        }
    }
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

// NOTE V910 ditched the SectionHeader
#[derive(Debug, Clone, Copy)]
struct IDBSectionHeader<K: IDAKind> {
    compress: Option<IDBSectionCompression>,
    len: K::Usize,
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
            _ => Err(anyhow!(
                "Invalid value for IDBSection Compression: {value}"
            )),
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

impl<K: IDAKind> IDBSectionHeader<K> {
    fn read(input: &mut impl IdbReadKind<K>) -> Result<Self> {
        let compress = IDBSectionCompression::from_raw(input.read_u8()?)?;
        let len = input.read_usize()?;
        Ok(IDBSectionHeader { compress, len })
    }
}

#[derive(Clone, Copy, Debug)]
enum VaVersion {
    Va0,
    Va1,
    Va2,
    Va3,
    // Versions: 4.1 5.2 6.1
    Va4,
    // Versions: 6.5 6.6 6.8 7.0 7.3 7.6 8.3 9.0 9.1
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

impl Serialize for IDBString {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self.as_utf8_lossy();
        serializer.collect_str(&value)
    }
}

impl IDBString {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_utf8_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Display for IDBString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_utf8_lossy().fmt(f)
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

#[derive(Clone, Copy)]
pub struct IDBStr<'a>(&'a [u8]);

impl Serialize for IDBStr<'_> {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self.as_utf8_lossy();
        serializer.collect_str(&value)
    }
}

impl<'a> IDBStr<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }

    pub fn as_utf8_lossy(self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.0)
    }

    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    pub fn to_idb_string(self) -> IDBString {
        IDBString::new(self.0.to_vec())
    }
}

impl std::fmt::Display for IDBStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_utf8_lossy().fmt(f)
    }
}

impl std::fmt::Debug for IDBStr<'_> {
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

#[derive(Clone, Copy)]
pub enum IDAVariants<I32, I64> {
    IDA32(I32),
    IDA64(I64),
}

impl<I32, I64> core::fmt::Debug for IDAVariants<I32, I64>
where
    I32: core::fmt::Debug,
    I64: core::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IDAVariants::IDA32(x) => {
                write!(f, "IDA32(")?;
                x.fmt(f)?;
                write!(f, ")")?;
                Ok(())
            }
            IDAVariants::IDA64(x) => {
                write!(f, "IDA64(")?;
                x.fmt(f)?;
                write!(f, ")")?;
                Ok(())
            }
        }
    }
}

pub trait IDAKind:
    core::fmt::Debug + Clone + Copy + Default + Serialize + 'static
{
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
    + Default
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
    + From<bool>
    + From<u8>
    + From<u16>
    + From<u32>
    + TryFrom<u64, Error: std::fmt::Debug>
    + TryFrom<usize, Error: std::fmt::Debug>
    + Into<i128>
    + TryFrom<i128>
    + for<'de> serde::Deserialize<'de>
    + serde::Serialize
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
    + Default
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
    + From<bool>
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
    ($bytes:literal, $utype:ty, $itype:ty, $name:ident, $unapack_fun:ident) => {
        #[derive(Debug, Clone, Copy, Serialize)]
        pub struct $name;
        impl Default for $name {
            fn default() -> Self {
                Self
            }
        }
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

/// representation of arbitrary memory Address
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Address<K: IDAKind>(K::Usize);

impl<K: IDAKind> PartialOrd for Address<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: IDAKind> Ord for Address<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.into_raw().cmp(&other.into_raw())
    }
}

impl<K: IDAKind> PartialEq for Address<K> {
    fn eq(&self, other: &Self) -> bool {
        self.into_raw().eq(&other.into_raw())
    }
}

impl<K: IDAKind> Eq for Address<K> {}

impl<K: IDAKind> std::hash::Hash for Address<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<K: IDAKind> Address<K> {
    pub fn from_raw(value: K::Usize) -> Self {
        Self(value)
    }

    pub fn into_raw(self) -> K::Usize {
        self.0
    }
}

impl<K: IDAKind> std::fmt::Display for Address<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<K: IDAKind> std::fmt::UpperHex for Address<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl<K: IDAKind> std::fmt::LowerHex for Address<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl<K: IDAKind> core::ops::Add for Address<K> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Address::from_raw(self.into_raw() + rhs.into_raw())
    }
}

impl<K: IDAKind> core::ops::Sub for Address<K> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Address::from_raw(self.into_raw() - rhs.into_raw())
    }
}

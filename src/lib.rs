pub mod id0;
pub mod id1;
pub mod nam;
pub mod til;

use std::fmt::Debug;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::num::NonZeroU64;

use id0::ID0Section;
use serde::Deserialize;

use crate::id1::ID1Section;
use crate::nam::NamSection;
use crate::til::section::TILSection;
use anyhow::{anyhow, ensure, Result};

#[derive(Debug, Clone, Copy)]
pub struct IDBParser<I: BufRead + Seek> {
    input: I,
    header: IDBHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID0Offset(NonZeroU64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ID1Offset(NonZeroU64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamOffset(NonZeroU64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TILOffset(NonZeroU64);

impl<I: BufRead + Seek> IDBParser<I> {
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
        read_section(&mut self.input, &self.header, id0.0.get(), ID0Section::read)
    }

    pub fn read_id1_section(&mut self, id1: ID1Offset) -> Result<ID1Section> {
        read_section(&mut self.input, &self.header, id1.0.get(), ID1Section::read)
    }

    pub fn read_nam_section(&mut self, nam: NamOffset) -> Result<NamSection> {
        read_section(&mut self.input, &self.header, nam.0.get(), NamSection::read)
    }

    pub fn read_til_section(&mut self, til: TILOffset) -> Result<TILSection> {
        read_section(
            &mut self.input,
            &self.header,
            til.0.get(),
            |input, _, compress| TILSection::read(input, compress),
        )
    }

    #[allow(dead_code)]
    pub(crate) fn decompress_section(
        &mut self,
        offset: u64,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        self.input.seek(SeekFrom::Start(offset))?;
        let section_header = IDBSectionHeader::read(&self.header, &mut self.input)?;
        // makes sure the reader doesn't go out-of-bounds
        let mut input = Read::take(&mut self.input, section_header.len);
        match section_header.compress {
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                let _ = std::io::copy(&mut input, output)?;
            }
            IDBSectionCompression::None => {
                let _ = std::io::copy(&mut input, output)?;
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn decompress_til_section(
        &mut self,
        til: TILOffset,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        self.input.seek(SeekFrom::Start(til.0.get()))?;
        let section_header = IDBSectionHeader::read(&self.header, &mut self.input)?;
        // makes sure the reader doesn't go out-of-bounds
        let mut input = Read::take(&mut self.input, section_header.len);
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
    I: BufRead + Seek,
    F: FnMut(&mut std::io::Take<&'a mut I>, &IDBHeader, IDBSectionCompression) -> Result<T>,
{
    input.seek(SeekFrom::Start(offset))?;
    let section_header = IDBSectionHeader::read(header, &mut *input)?;
    // makes sure the reader doesn't go out-of-bounds
    let mut input = Read::take(input, section_header.len);
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
enum IDBSectionCompression {
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
    pub fn read<I: BufRead + Seek>(input: &mut I) -> Result<Self> {
        let header_raw: IDBHeaderRaw = bincode::deserialize_from(&mut *input)?;
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

    fn read_v1<I: Read + Seek>(
        header_raw: &IDBHeaderRaw,
        magic: IDBMagic,
        input: I,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V1Raw {
            id2_offset: u32,
            checksums: [u32; 3],
            unk30_zeroed: u32,
            unk33_checksum: u32,
            unk38_zeroed: [u8; 6],
        }

        let v1_raw: V1Raw = bincode::deserialize_from(input)?;
        ensure!(v1_raw.unk30_zeroed == 0, "unk30 not zeroed");
        ensure!(v1_raw.id2_offset == 0, "id2 in V1 is not zeroed");
        ensure!(v1_raw.unk38_zeroed == [0; 6], "unk38 is not zeroed");

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

    fn read_v4<I: Read + Seek>(
        header_raw: &IDBHeaderRaw,
        magic: IDBMagic,
        input: I,
    ) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V4Raw {
            id2_offset: u32,
            checksums: [u32; 3],
            unk30_zeroed: u32,
            unk33_checksum: u32,
            unk38_zeroed: [u8; 8],
            unk40_v5c: u32,
            unk44_zeroed: [u8; 8],
            _unk4c: [u8; 16],
            unk5c_zeroed: [[u8; 16]; 8],
        }

        let v4_raw: V4Raw = bincode::deserialize_from(input)?;

        ensure!(v4_raw.unk30_zeroed == 0, "unk30 not zeroed");
        ensure!(v4_raw.id2_offset == 0, "id2 in V4 is not zeroed");
        ensure!(v4_raw.unk38_zeroed == [0; 8], "unk38 is not zeroed");
        ensure!(v4_raw.unk40_v5c == 0x5c, "unk40 is not 0x5C");
        ensure!(v4_raw.unk44_zeroed == [0; 8], "unk44 is not zeroed");
        ensure!(v4_raw.unk5c_zeroed == [[0; 16]; 8], "unk5c is not zeroed");

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

    fn read_v5(header_raw: &IDBHeaderRaw, magic: IDBMagic, input: impl Read) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V5Raw {
            nam_offset: u64,
            seg_offset_zeroed: u64,
            til_offset: u64,
            initial_checksums: [u32; 3],
            unk4_zeroed: u32,
            unk_checksum: u32,
            id2_offset_zeroed: u64,
            final_checksum: u32,
            unk0_v7c: u32,
            unk1_zeroed: [u8; 16],
            _unk2: [u8; 16],
            unk3_zeroed: [[u8; 16]; 8],
        }
        let v5_raw: V5Raw = bincode::deserialize_from(input)?;
        let id0_offset =
            u64::from_le(u64::from(header_raw.offsets[1]) << 32 | u64::from(header_raw.offsets[0]));
        let id1_offset =
            u64::from_le(u64::from(header_raw.offsets[3]) << 32 | u64::from(header_raw.offsets[2]));

        // TODO Final checksum is always zero on v5?

        ensure!(v5_raw.unk4_zeroed == 0, "unk4 not zeroed");
        ensure!(v5_raw.id2_offset_zeroed == 0, "id2 in V5 is not zeroed");
        ensure!(v5_raw.seg_offset_zeroed == 0, "seg in V5 is not zeroed");
        ensure!(v5_raw.unk0_v7c == 0x7C, "unk0 not 0x7C");
        ensure!(v5_raw.unk1_zeroed == [0; 16], "unk1 is not zeroed");
        ensure!(v5_raw.unk3_zeroed == [[0; 16]; 8], "unk3 is not zeroed");

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

    fn read_v6(header_raw: &IDBHeaderRaw, magic: IDBMagic, input: impl Read) -> Result<Self> {
        #[derive(Debug, Deserialize)]
        struct V6Raw {
            nam_offset: u64,
            seg_offset_zeroed: u64,
            til_offset: u64,
            initial_checksums: [u32; 3],
            unk4_zeroed: [u8; 4],
            unk5_checksum: u32,
            id2_offset: u64,
            final_checksum: u32,
            unk0_v7c: u32,
            unk1_zeroed: [u8; 16],
            _unk2: [u8; 16],
            unk3_zeroed: [[u8; 16]; 8],
        }
        let v6_raw: V6Raw = bincode::deserialize_from(input)?;
        let id0_offset =
            u64::from_le(u64::from(header_raw.offsets[1]) << 32 | u64::from(header_raw.offsets[0]));
        let id1_offset =
            u64::from_le(u64::from(header_raw.offsets[3]) << 32 | u64::from(header_raw.offsets[2]));

        ensure!(v6_raw.unk4_zeroed == [0; 4], "unk4 not zeroed");
        ensure!(v6_raw.seg_offset_zeroed == 0, "seg in V6 is not zeroed");
        ensure!(v6_raw.unk0_v7c == 0x7C, "unk0 not 0x7C");
        ensure!(v6_raw.unk1_zeroed == [0; 16], "unk1 is not zeroed");
        ensure!(v6_raw.unk3_zeroed == [[0; 16]; 8], "unk3 is not zeroed");

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
    pub fn read<I: BufRead>(header: &IDBHeader, input: I) -> Result<Self> {
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
    fn read<I: Read>(input: &mut I) -> Result<Self> {
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
fn read_bytes_len_u16<I: Read>(mut input: I) -> Result<Vec<u8>> {
    let mut len = [0, 0];
    input.read_exact(&mut len)?;
    let mut bytes = vec![0u8; u16::from_le_bytes(len).into()];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_bytes_len_u8<I: Read>(mut input: I) -> Result<Vec<u8>> {
    let mut len = [0];
    input.read_exact(&mut len)?;
    let mut bytes = vec![0u8; len[0].into()];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_string_len_u8<I: Read>(input: I) -> Result<String> {
    let bytes = read_bytes_len_u8(input)?;
    Ok(String::from_utf8(bytes)?)
}

#[allow(dead_code)]
fn write_string_len_u8<O: std::io::Write>(mut output: O, value: &str) -> Result<()> {
    output.write_all(&[u8::try_from(value.len()).unwrap()])?;
    Ok(output.write_all(value.as_bytes())?)
}

fn read_c_string_raw<I: BufRead>(mut input: I) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![];
    input.read_until(b'\x00', &mut buf)?;
    // last char need to be \x00 or we found a EoF
    if buf.pop() != Some(b'\x00') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Unexpected EoF on CStr",
        ));
    }
    Ok(buf)
}

fn read_c_string<I: BufRead>(input: &mut I) -> std::io::Result<String> {
    let buf = read_c_string_raw(input)?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn read_c_string_vec<I: BufRead>(input: &mut I) -> std::io::Result<Vec<String>> {
    let buf = read_c_string_raw(input)?;
    if buf.is_empty() {
        return Ok(vec![]);
    }

    let mut result = vec![];
    // NOTE never 0 because this came from a CStr
    let mut len = buf[0] - 1;
    // NOTE zero len (buf[0] == 1) string is allowed
    let mut current = &buf[1..];
    loop {
        if usize::from(len) > current.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid len on Vec of CStr",
            ));
        }
        let (value, rest) = current.split_at(len.into());
        result.push(String::from_utf8_lossy(value).to_string());
        if rest.is_empty() {
            break;
        }
        len = rest[0] - 1;
        current = &rest[1..];
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::til::section::TILSection;
    use crate::*;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::BufReader;
    use std::path::{Path, PathBuf};

    #[test]
    fn parse_id0_til() {
        let function = [
            0x0c, // Function Type
            0xaf, 0x81, 0x42, 0x01, 0x53, // TODO
            0x01, // void ret
            0x03, //n args
            0x3d, 0x08, 0x48, 0x4d, 0x4f, 0x44, 0x55, 0x4c, 0x45, 0x3d, 0x06, 0x44, 0x57, 0x4f,
            0x52, 0x44, 0x00,
        ];
        let _til = til::Type::new_from_id0(&function).unwrap();
    }

    #[test]
    fn parse_idb_param() {
        let param = b"IDA\xbc\x02\x06metapc#\x8a\x03\x03\x02\x00\x00\x00\x00\xff_\xff\xff\xf7\x03\x00\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x0d\x00\x0d \x0d\x10\xff\xff\x00\x00\x00\xc0\x80\x00\x00\x00\x02\x02\x01\x0f\x0f\x06\xce\xa3\xbeg\xc6@\x00\x07\x00\x07\x10(FP\x87t\x09\x03\x00\x01\x13\x0a\x00\x00\x01a\x00\x07\x00\x13\x04\x04\x04\x00\x02\x04\x08\x00\x00\x00";
        let _parsed = id0::IDBParam::read(param, false).unwrap();
    }

    #[test]
    fn parse_idbs() {
        let files = find_all("resources/idbs".as_ref(), &["idb".as_ref(), "i64".as_ref()]).unwrap();
        for filename in files {
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
            let _: Vec<_> = id0.loader_name().unwrap().map(Result::unwrap).collect();
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
            let _ = id0.dirtree_names().unwrap();
            if let Some(til) = til {
                let _dirtree_tinfos = id0.dirtree_tinfos(&til).unwrap();
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
    }

    #[test]
    fn parse_tils() {
        let files = find_all("resources/tils".as_ref(), &["til".as_ref()]).unwrap();
        let _results = files
            .into_iter()
            .map(|file| {
                println!("{}", file.to_str().unwrap());
                // makes sure it don't read out-of-bounds
                let mut input = BufReader::new(File::open(file)?);
                // TODO make a SmartReader
                match TILSection::read(&mut input, IDBSectionCompression::None) {
                    Ok(_til) => {
                        let current = input.seek(SeekFrom::Current(0))?;
                        let end = input.seek(SeekFrom::End(0))?;
                        ensure!(
                            current == end,
                            "unable to consume the entire TIL file, {current} != {end}"
                        );
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            })
            .collect::<Result<(), _>>()
            .unwrap();
    }

    fn find_all(path: &Path, exts: &[&OsStr]) -> Result<Vec<PathBuf>> {
        fn inner_find_all(path: &Path, exts: &[&OsStr], buf: &mut Vec<PathBuf>) -> Result<()> {
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

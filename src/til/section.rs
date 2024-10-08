use crate::ida_reader::{IdaGenericBufUnpack, IdaGenericUnpack};
use crate::til::{flag, TILMacro, TILTypeInfo};
use crate::IDBSectionCompression;
use anyhow::ensure;
use serde::{Deserialize, Serialize};
use std::io::{BufReader, Read, Write};
use std::num::NonZeroU8;

// TODO migrate this to flags
pub const TIL_SECTION_MAGIC: &[u8; 6] = b"IDATIL";

#[derive(Debug, Clone)]
pub struct TILSection {
    pub format: u32,
    /// short file name (without path and extension)
    pub title: Vec<u8>,
    /// human readable til description
    pub description: Vec<u8>,
    pub id: u8,
    /// information about the target compiler
    pub cm: u8,
    pub def_align: u8,
    pub symbols: Vec<TILTypeInfo>,
    // TODO create a struct for ordinal aliases
    pub type_ordinal_numbers: Option<Vec<u32>>,
    pub types: Vec<TILTypeInfo>,
    pub size_i: NonZeroU8,
    pub size_b: NonZeroU8,
    pub sizes: Option<TILSizes>,
    pub size_long_double: Option<NonZeroU8>,
    pub macros: Option<Vec<TILMacro>>,
    pub is_universal: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TILSizes {
    pub size_short: NonZeroU8,
    pub size_long: NonZeroU8,
    pub size_long_long: NonZeroU8,
}

#[derive(Debug, Clone)]
pub struct TILSectionHeader {
    pub format: u32,
    pub flags: TILSectionFlag,
    pub title: Vec<u8>,
    pub description: Vec<u8>,
    pub id: u8,
    pub cm: u8,
    pub size_enum: u8,
    pub size_i: NonZeroU8,
    pub size_b: NonZeroU8,
    pub def_align: u8,
    pub size_s_l_ll: Option<TILSizes>,
    pub size_long_double: Option<NonZeroU8>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct TILSectionHeader1 {
    pub signature: [u8; 6],
    pub format: u32,
    pub flags: TILSectionFlag,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct TILSectionHeader2 {
    pub id: u8,
    pub cm: u8,
    pub size_i: u8,
    pub size_b: u8,
    pub size_enum: u8,
    pub def_align: u8,
}

impl TILSection {
    pub fn parse(mut input: impl IdaGenericBufUnpack) -> anyhow::Result<Self> {
        Self::read_inner(&mut input)
    }

    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        compress: IDBSectionCompression,
    ) -> anyhow::Result<Self> {
        match compress {
            IDBSectionCompression::None => Self::read_inner(input),
            IDBSectionCompression::Zlib => {
                let mut input = BufReader::new(flate2::read::ZlibDecoder::new(input));
                Self::read_inner(&mut input)
            }
        }
    }

    fn read_inner(input: &mut impl IdaGenericBufUnpack) -> anyhow::Result<Self> {
        let header = Self::read_header(&mut *input)?;
        let symbols = Self::read_bucket(&mut *input, &header)?;
        let type_ordinal_numbers = header
            .flags
            .has_ordinal()
            .then(|| Self::read_ordinals(&mut *input, &header))
            .transpose()?;
        let types = Self::read_bucket(&mut *input, &header)?;
        let macros = header
            .flags
            .has_macro_table()
            .then(|| Self::read_macros(&mut *input, &header))
            .transpose()?;

        // TODO verify that is always false?
        let _mod = header.flags.is_mod();
        let _uni = header.flags.is_universal();
        let _ord = header.flags.has_ordinal();
        let _ali = header.flags.has_type_aliases();
        let _stm = header.flags.has_extra_stream();

        Ok(TILSection {
            format: header.format,
            title: header.title,
            description: header.description,
            id: header.id,
            cm: header.cm,
            def_align: header.def_align,
            size_long_double: header.size_long_double,
            is_universal: header.flags.is_universal(),
            size_b: header.size_b,
            size_i: header.size_i,
            sizes: header.size_s_l_ll,
            symbols,
            type_ordinal_numbers,
            types,
            macros,
        })
    }

    fn read_ordinals(
        input: &mut impl IdaGenericUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Vec<u32>> {
        let ord_total = bincode::deserialize_from::<_, u32>(&mut *input)?;
        let mut ordinals = vec![ord_total];
        if !header.flags.has_type_aliases() {
            return Ok(ordinals);
        }

        loop {
            let value = bincode::deserialize_from::<_, u32>(&mut *input)?;
            if value == u32::MAX {
                break;
            }

            ordinals.push(value)
        }
        Ok(ordinals)
    }

    fn read_header(input: &mut impl IdaGenericUnpack) -> anyhow::Result<TILSectionHeader> {
        let header1: TILSectionHeader1 = bincode::deserialize_from(&mut *input)?;
        ensure!(
            header1.signature == *TIL_SECTION_MAGIC,
            "Invalid TIL Signature"
        );

        let title = input.read_bytes_len_u8()?;
        let description = input.read_bytes_len_u8()?;

        let header2: TILSectionHeader2 = bincode::deserialize_from(&mut *input)?;
        let size_s_l_ll = header1
            .flags
            .have_size_short_long_longlong()
            .then(|| bincode::deserialize_from(&mut *input))
            .transpose()?
            .map(|(s, l, ll): (u8, u8, u8)| -> anyhow::Result<_> {
                Ok(TILSizes {
                    size_short: s.try_into()?,
                    size_long: l.try_into()?,
                    size_long_long: ll.try_into()?,
                })
            })
            .transpose()?;
        let size_long_double = header1
            .flags
            .has_size_long_double()
            .then(|| bincode::deserialize_from::<_, u8>(&mut *input))
            .transpose()?
            .map(|size| size.try_into())
            .transpose()?;
        Ok(TILSectionHeader {
            format: header1.format,
            flags: header1.flags,
            title,
            description,
            id: header2.id,
            size_enum: header2.size_enum,
            size_i: header2.size_i.try_into()?,
            size_b: header2.size_b.try_into()?,
            cm: header2.cm,
            def_align: header2.def_align,
            size_s_l_ll,
            size_long_double,
        })
    }

    pub fn decompress(
        input: &mut impl IdaGenericUnpack,
        output: &mut impl Write,
        compress: IDBSectionCompression,
    ) -> anyhow::Result<()> {
        match compress {
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                Self::decompress_inner(&mut input, output)
            }
            IDBSectionCompression::None => Self::decompress_inner(input, output),
        }
    }

    fn decompress_inner(
        input: &mut impl IdaGenericUnpack,
        output: &mut impl Write,
    ) -> anyhow::Result<()> {
        let mut header = Self::read_header(&mut *input)?;
        let og_flags = header.flags;
        // disable the zip flag
        header.flags.set_zip(false);
        let header1 = TILSectionHeader1 {
            signature: *TIL_SECTION_MAGIC,
            format: header.format,
            flags: header.flags,
        };
        let header2 = TILSectionHeader2 {
            id: header.id,
            cm: header.cm,
            size_i: header.size_i.get(),
            size_b: header.size_b.get(),
            size_enum: header.size_enum,
            def_align: header.def_align,
        };
        bincode::serialize_into(&mut *output, &header1)?;
        crate::write_string_len_u8(&mut *output, &header.title)?;
        crate::write_string_len_u8(&mut *output, &header.description)?;
        bincode::serialize_into(&mut *output, &header2)?;
        header
            .size_s_l_ll
            .map(|value| {
                bincode::serialize_into(
                    &mut *output,
                    &(
                        value.size_short.get(),
                        value.size_long.get(),
                        value.size_long_long.get(),
                    ),
                )
            })
            .transpose()?;
        header
            .size_long_double
            .map(|value| bincode::serialize_into(&mut *output, &value))
            .transpose()?;

        // if not zipped, just copy the rest of the data, there is no possible zip
        // block inside a bucket
        if !og_flags.is_zip() {
            std::io::copy(&mut *input, output)?;
            return Ok(());
        }

        // symbols
        Self::decompress_bucket(&mut *input, &mut *output)?;
        let _type_ordinal_numbers: Option<u32> = header
            .flags
            .has_ordinal()
            .then(|| -> anyhow::Result<u32> {
                let result: u32 = bincode::deserialize_from(&mut *input)?;
                bincode::serialize_into(&mut *output, &result)?;
                Ok(result)
            })
            .transpose()?;
        // types
        Self::decompress_bucket(&mut *input, &mut *output)?;
        // macros
        header
            .flags
            .has_macro_table()
            .then(|| Self::decompress_bucket(&mut *input, &mut *output))
            .transpose()?;

        Ok(())
    }
}

// TODO remove deserialize and implement a verification if the value is correct
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct TILSectionFlag(pub(crate) u32);
impl TILSectionFlag {
    pub fn is_zip(&self) -> bool {
        self.0 & flag::TIL_ZIP != 0
    }
    pub fn set_zip(&mut self, value: bool) {
        if value {
            self.0 |= flag::TIL_ZIP
        } else {
            self.0 &= !flag::TIL_ZIP
        }
    }
    pub fn has_macro_table(&self) -> bool {
        self.0 & flag::TIL_MAC != 0
    }
    /// extended sizeof info (short, long, longlong)
    pub fn have_size_short_long_longlong(&self) -> bool {
        self.0 & flag::TIL_ESI != 0
    }
    /// universal til for any compiler
    pub fn is_universal(&self) -> bool {
        self.0 & flag::TIL_UNI != 0
    }
    /// type ordinal numbers are present
    pub fn has_ordinal(&self) -> bool {
        self.0 & flag::TIL_ORD != 0
    }
    /// type aliases are present
    pub fn has_type_aliases(&self) -> bool {
        self.0 & flag::TIL_ALI != 0
    }
    /// til has been modified, should be saved
    pub fn is_mod(&self) -> bool {
        self.0 & flag::TIL_MOD != 0
    }
    /// til has extra streams
    pub fn has_extra_stream(&self) -> bool {
        self.0 & flag::TIL_STM != 0
    }
    /// sizeof(long double)
    pub fn has_size_long_double(&self) -> bool {
        self.0 & flag::TIL_SLD != 0
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct TILBucketRaw {
    ndefs: u32,
    len: u32,
}

impl TILSection {
    fn read_bucket_header(input: &mut impl IdaGenericUnpack) -> anyhow::Result<(u32, u32)> {
        let ndefs = bincode::deserialize_from(&mut *input)?;
        let len = bincode::deserialize_from(&mut *input)?;
        Ok((ndefs, len))
    }

    fn read_bucket_zip_header(
        input: &mut impl IdaGenericUnpack,
    ) -> anyhow::Result<(u32, u32, u32)> {
        let (ndefs, len) = Self::read_bucket_header(&mut *input)?;
        let compressed_len = bincode::deserialize_from(&mut *input)?;
        Ok((ndefs, len, compressed_len))
    }

    fn read_bucket(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Vec<TILTypeInfo>> {
        if header.flags.is_zip() {
            Self::read_bucket_zip(&mut *input, header)
        } else {
            Self::read_bucket_normal(&mut *input, header)
        }
    }

    fn read_bucket_normal(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Vec<TILTypeInfo>> {
        let (ndefs, len) = Self::read_bucket_header(&mut *input)?;
        let mut input = input.take(len.into());
        let type_info = (0..ndefs)
            .map(|_| TILTypeInfo::read(&mut input, header))
            .collect::<anyhow::Result<_, _>>()?;
        ensure!(
            input.limit() == 0,
            "TypeBucket total data is smaller then expected"
        );
        Ok(type_info)
    }

    fn read_bucket_zip(
        input: &mut impl IdaGenericUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Vec<TILTypeInfo>> {
        let (ndefs, len, compressed_len) = Self::read_bucket_zip_header(&mut *input)?;
        // make sure the decompressor don't read out-of-bounds
        let mut compressed_input = input.take(compressed_len.into());
        let inflate = BufReader::new(flate2::read::ZlibDecoder::new(&mut compressed_input));
        // make sure only the defined size is decompressed
        let mut decompressed_input = inflate.take(len.into());
        let type_info = (0..ndefs.try_into().unwrap())
            .map(|_| TILTypeInfo::read(&mut decompressed_input, header))
            .collect::<anyhow::Result<Vec<_>, _>>()?;
        // make sure the input was fully consumed
        ensure!(
            decompressed_input.limit() == 0,
            "TypeBucket data is smaller then expected"
        );
        ensure!(
            compressed_input.limit() == 0,
            "TypeBucket compressed data is smaller then expected"
        );
        Ok(type_info)
    }

    fn read_macros(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> anyhow::Result<Vec<TILMacro>> {
        if header.flags.is_zip() {
            Self::read_macros_zip(&mut *input)
        } else {
            Self::read_macros_normal(&mut *input)
        }
    }

    fn read_macros_normal(input: &mut impl IdaGenericBufUnpack) -> anyhow::Result<Vec<TILMacro>> {
        let (ndefs, len) = Self::read_bucket_header(&mut *input)?;
        let mut input = input.take(len.into());
        let type_info = (0..ndefs)
            .map(|_| TILMacro::read(&mut input))
            .collect::<anyhow::Result<_, _>>()?;
        ensure!(
            input.limit() == 0,
            "TypeBucket macro total data is smaller then expected"
        );
        Ok(type_info)
    }

    fn read_macros_zip(input: &mut impl IdaGenericUnpack) -> anyhow::Result<Vec<TILMacro>> {
        let (ndefs, len, compressed_len) = Self::read_bucket_zip_header(&mut *input)?;
        // make sure the decompressor don't read out-of-bounds
        let mut compressed_input = input.take(compressed_len.into());
        let inflate = BufReader::new(flate2::read::ZlibDecoder::new(&mut compressed_input));
        // make sure only the defined size is decompressed
        let mut decompressed_input = inflate.take(len.into());
        let type_info = (0..ndefs.try_into().unwrap())
            .map(|_| TILMacro::read(&mut decompressed_input))
            .collect::<anyhow::Result<Vec<_>, _>>()?;
        // make sure the input was fully consumed
        ensure!(
            decompressed_input.limit() == 0,
            "TypeBucket macros data is smaller then expected"
        );
        ensure!(
            compressed_input.limit() == 0,
            "TypeBucket macros compressed data is smaller then expected"
        );
        Ok(type_info)
    }

    #[allow(dead_code)]
    fn decompress_bucket(
        input: &mut impl IdaGenericUnpack,
        output: &mut impl std::io::Write,
    ) -> anyhow::Result<()> {
        let (ndefs, len, compressed_len) = Self::read_bucket_zip_header(&mut *input)?;
        bincode::serialize_into(&mut *output, &TILBucketRaw { len, ndefs })?;
        // write the decompressed data
        let mut compressed_input = input.take(compressed_len.into());
        let inflate = flate2::read::ZlibDecoder::new(&mut compressed_input);
        let mut decompressed_input = inflate.take(len.into());
        std::io::copy(&mut decompressed_input, output)?;
        ensure!(
            decompressed_input.limit() == 0,
            "TypeBucket data is smaller then expected"
        );
        ensure!(
            compressed_input.limit() == 0,
            "TypeBucket compressed data is smaller then expected"
        );
        Ok(())
    }
}

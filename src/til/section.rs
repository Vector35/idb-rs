use crate::id0::Id0TilOrd;
use crate::ida_reader::{IdaGenericBufUnpack, IdaGenericUnpack};
use crate::til::{flag, TILMacro, TILTypeInfo};
use crate::IDBSectionCompression;
use anyhow::{anyhow, ensure, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufReader, Read, Write};
use std::num::NonZeroU8;

// TODO migrate this to flags
pub const TIL_SECTION_MAGIC: &[u8; 6] = b"IDATIL";

#[derive(Debug, Clone)]
pub struct TILSection {
    pub format: u32,
    // TODO is title and description inverted?
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
    pub type_ordinal_alias: Option<Vec<(u32, u32)>>,
    pub types: Vec<TILTypeInfo>,
    pub size_i: NonZeroU8,
    pub size_b: NonZeroU8,
    pub size_short: NonZeroU8,
    pub size_long: NonZeroU8,
    pub size_long_long: NonZeroU8,
    pub size_long_double: Option<NonZeroU8>,
    pub macros: Option<Vec<TILMacro>>,
    pub is_universal: bool,
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
    pub size_short: NonZeroU8,
    pub size_long: NonZeroU8,
    pub size_long_long: NonZeroU8,
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
    pub fn parse(mut input: impl IdaGenericBufUnpack) -> Result<Self> {
        Self::read_inner(&mut input)
    }

    pub(crate) fn read(
        input: &mut impl IdaGenericBufUnpack,
        compress: IDBSectionCompression,
    ) -> Result<Self> {
        match compress {
            IDBSectionCompression::None => Self::read_inner(input),
            IDBSectionCompression::Zlib => {
                let mut input = BufReader::new(flate2::read::ZlibDecoder::new(input));
                Self::read_inner(&mut input)
            }
        }
    }

    fn read_inner(input: &mut impl IdaGenericBufUnpack) -> Result<Self> {
        let header = Self::read_header(&mut *input)?;
        let symbols = Self::read_bucket(&mut *input, &header, None, None)?;

        // TODO create an ordinal -> type mapping, to make sure the ordinals are not duplicated
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e292
        let (next_ordinal, type_ordinal_alias) =
            Self::read_next_ordinal_and_alias(&mut *input, &header)?;
        let types = Self::read_bucket(
            &mut *input,
            &header,
            next_ordinal,
            type_ordinal_alias.as_deref(),
        )?;
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
            size_short: header.size_short,
            size_long: header.size_long,
            size_long_long: header.size_long_long,
            symbols,
            type_ordinal_alias,
            types,
            macros,
        })
    }

    #[allow(clippy::type_complexity)]
    fn read_next_ordinal_and_alias(
        input: &mut impl IdaGenericUnpack,
        header: &TILSectionHeader,
    ) -> Result<(Option<u32>, Option<Vec<(u32, u32)>>)> {
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e292
        if !header.flags.has_ordinal() {
            return Ok((None, None));
        }
        let next_ord = input.read_u32()?;

        match (header.flags.has_type_aliases(), next_ord) {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e2a8
            (false, _) | (_, 0) => return Ok((Some(next_ord), None)),
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e29c
            (true, 1..) => {}
        };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e2b1
        // TODO verify that no alias cycle exists
        // TODO create and Map for Ord -> Type
        // TODO what is that? Note !0x3Fu8 = 0xC0u8
        let calc_ord = (next_ord + 0x3f) & 0xffff_ffc0;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e2b6
        ensure!(next_ord <= calc_ord);

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e29c
        let mut ordinals = vec![];
        // read the alias
        loop {
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e374
            let src_ordinal = input.read_u32()?;
            if src_ordinal == u32::MAX {
                break;
            }
            ensure!(
                src_ordinal < next_ord,
                "Too many ordinal-numbers, missing -1"
            );

            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e339
            let dst_ordinal = input.read_u32()?;
            ensure!(
                dst_ordinal < next_ord,
                "destination for ordinal-number is invalid"
            );
            ordinals.push((src_ordinal, dst_ordinal))
        }
        Ok((Some(next_ord), Some(ordinals)))
    }

    fn read_header(input: &mut impl IdaGenericUnpack) -> Result<TILSectionHeader> {
        // TODO this break a few files
        let signature: [u8; 6] = bincode::deserialize_from(&mut *input)?;
        ensure!(signature == *TIL_SECTION_MAGIC, "Invalid TIL Signature");
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x431eb5
        let (format, flags) = match input.read_u32()? {
            format @ 0x13.. => return Err(anyhow!("Invalid TIL format {format}")),
            // read the flag after the format
            format @ 0x10..=0x12 => {
                let flags = TILSectionFlag(input.read_u32()?);
                (format, flags)
            }
            // format and flag are the same
            value @ ..=0xf => (value, TILSectionFlag(value)),
        };
        let header1 = TILSectionHeader1 {
            signature,
            format,
            flags,
        };

        let title = input.read_bytes_len_u8()?;
        let mut description = input.read_bytes_len_u8()?;

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x431f64
        // remove the "_arm" from the description
        const MACOS_ARM_EXCEPTION: &[u8] = b"macosx_arm";
        if let Some(pos) = description
            .windows(MACOS_ARM_EXCEPTION.len())
            .position(|window| window == MACOS_ARM_EXCEPTION)
        {
            description = description[..pos + 6]
                .iter()
                .chain(&description[pos + MACOS_ARM_EXCEPTION.len()..])
                .copied()
                .collect::<Vec<_>>();
        }

        let header2: TILSectionHeader2 = bincode::deserialize_from(&mut *input)?;

        // TODO header2.cm default to 0x13
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42ef86

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x431ffe
        let (size_short, size_long, size_long_long) =
            if header1.flags.have_size_short_long_longlong() {
                let ss = input.read_u8()?;
                let ls = input.read_u8()?;
                let lls = input.read_u8()?;
                let ss = NonZeroU8::new(ss).ok_or_else(|| anyhow!("Invalid short size"))?;
                let ls = NonZeroU8::new(ls).ok_or_else(|| anyhow!("Invalid long size"))?;
                let lls = NonZeroU8::new(lls).ok_or_else(|| anyhow!("Invalid long long size"))?;
                (ss, ls, lls)
            } else {
                (
                    2.try_into().unwrap(),
                    4.try_into().unwrap(),
                    8.try_into().unwrap(),
                )
            };

        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x432014
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
            size_short,
            size_long,
            size_long_long,
            size_long_double,
        })
    }

    pub fn decompress(
        input: &mut impl IdaGenericUnpack,
        output: &mut impl Write,
        compress: IDBSectionCompression,
    ) -> Result<()> {
        match compress {
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                Self::decompress_inner(&mut input, output)
            }
            IDBSectionCompression::None => Self::decompress_inner(input, output),
        }
    }

    fn decompress_inner(input: &mut impl IdaGenericUnpack, output: &mut impl Write) -> Result<()> {
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
        if header.flags.have_size_short_long_longlong() {
            bincode::serialize_into(
                &mut *output,
                &(
                    header.size_short.get(),
                    header.size_long.get(),
                    header.size_long_long.get(),
                ),
            )?;
        }

        if header.flags.has_size_long_double() {
            bincode::serialize_into(&mut *output, &header.size_long_double.unwrap().get())?;
        }

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
            .then(|| -> Result<u32> {
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

    pub fn get_ord(&self, id0_ord: Id0TilOrd) -> Option<&TILTypeInfo> {
        // first search the ordinal alias
        if let Some(ordinals) = &self.type_ordinal_alias {
            // it's unclear what is the first value
            if let Some((_src, dst)) = ordinals
                .iter()
                .find(|(src, _dst)| u64::from(*src) == id0_ord.ord)
            {
                return self.get_ord(Id0TilOrd { ord: (*dst).into() });
            }
        }
        // if not and alias, search for the type directly
        self.types.iter().find(|ty| ty.ordinal == id0_ord.ord)
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
    fn read_bucket_header(input: &mut impl IdaGenericUnpack) -> Result<(u32, u32)> {
        let ndefs = bincode::deserialize_from(&mut *input)?;
        // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e3e0
        //ensure!(ndefs < 0x55555555);
        let len = bincode::deserialize_from(&mut *input)?;
        Ok((ndefs, len))
    }

    fn read_bucket_zip_header(input: &mut impl IdaGenericUnpack) -> Result<(u32, u32, u32)> {
        let (ndefs, len) = Self::read_bucket_header(&mut *input)?;
        let compressed_len = bincode::deserialize_from(&mut *input)?;
        Ok((ndefs, len, compressed_len))
    }

    fn read_bucket(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        next_ordinal: Option<u32>,
        ordinal_alias: Option<&[(u32, u32)]>,
    ) -> Result<Vec<TILTypeInfo>> {
        if header.flags.is_zip() {
            Self::read_bucket_zip(&mut *input, header, next_ordinal, ordinal_alias)
        } else {
            Self::read_bucket_normal(&mut *input, header, next_ordinal, ordinal_alias)
        }
    }

    fn read_bucket_normal(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        next_ordinal: Option<u32>,
        ordinal_alias: Option<&[(u32, u32)]>,
    ) -> Result<Vec<TILTypeInfo>> {
        let (ndefs, len) = Self::read_bucket_header(&mut *input)?;
        Self::read_bucket_inner(&mut *input, header, ndefs, len, next_ordinal, ordinal_alias)
    }

    fn read_bucket_zip(
        input: &mut impl IdaGenericUnpack,
        header: &TILSectionHeader,
        next_ordinal: Option<u32>,
        ordinal_alias: Option<&[(u32, u32)]>,
    ) -> Result<Vec<TILTypeInfo>> {
        let (ndefs, len, compressed_len) = Self::read_bucket_zip_header(&mut *input)?;
        // make sure the decompressor don't read out-of-bounds
        let mut compressed_input = input.take(compressed_len.into());
        let mut inflate = BufReader::new(flate2::read::ZlibDecoder::new(&mut compressed_input));
        // make sure only the defined size is decompressed
        let type_info = Self::read_bucket_inner(
            &mut inflate,
            header,
            ndefs,
            len,
            next_ordinal,
            ordinal_alias,
        )?;
        ensure!(
            compressed_input.limit() == 0,
            "TypeBucket compressed data is smaller then expected"
        );
        Ok(type_info)
    }

    fn read_bucket_inner(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
        ndefs: u32,
        len: u32,
        next_ord: Option<u32>,
        ordinal_alias: Option<&[(u32, u32)]>,
    ) -> Result<Vec<TILTypeInfo>> {
        if let Some(next_ord) = next_ord {
            let alias: u32 = ordinal_alias
                .map(|x| x.len())
                .unwrap_or(0)
                .try_into()
                .unwrap();
            // InnerRef fb47f2c2-3c08-4d40-b7ab-3c7736dce31d 0x42e3e0
            ensure!(ndefs + alias + 1 <= next_ord);
        }
        let mut input = input.take(len.into());
        let type_info = (0..ndefs)
            .map(|_| TILTypeInfo::read(&mut input, header))
            .collect::<Result<_>>()?;
        ensure!(
            input.limit() == 0,
            "TypeBucket total data is smaller then expected"
        );
        Ok(type_info)
    }

    fn read_macros(
        input: &mut impl IdaGenericBufUnpack,
        header: &TILSectionHeader,
    ) -> Result<Vec<TILMacro>> {
        if header.flags.is_zip() {
            Self::read_macros_zip(&mut *input)
        } else {
            Self::read_macros_normal(&mut *input)
        }
    }

    fn read_macros_normal(input: &mut impl IdaGenericBufUnpack) -> Result<Vec<TILMacro>> {
        let (ndefs, len) = Self::read_bucket_header(&mut *input)?;
        let mut input = input.take(len.into());
        let type_info = (0..ndefs)
            .map(|_| TILMacro::read(&mut input))
            .collect::<Result<_, _>>()?;
        ensure!(
            input.limit() == 0,
            "TypeBucket macro total data is smaller then expected"
        );
        Ok(type_info)
    }

    fn read_macros_zip(input: &mut impl IdaGenericUnpack) -> Result<Vec<TILMacro>> {
        let (ndefs, len, compressed_len) = Self::read_bucket_zip_header(&mut *input)?;
        // make sure the decompressor don't read out-of-bounds
        let mut compressed_input = input.take(compressed_len.into());
        let inflate = BufReader::new(flate2::read::ZlibDecoder::new(&mut compressed_input));
        // make sure only the defined size is decompressed
        let mut decompressed_input = inflate.take(len.into());
        let type_info = (0..ndefs.try_into().unwrap())
            .map(|_| TILMacro::read(&mut decompressed_input))
            .collect::<Result<Vec<_>, _>>()?;
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
    ) -> Result<()> {
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

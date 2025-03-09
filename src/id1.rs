use anyhow::{anyhow, ensure, Result};

pub mod flag;

use std::ops::{Div, Range, Rem};

use crate::ida_reader::{IdbRead, IdbReadKind};
use crate::{IDAKind, IDBSectionCompression, VaVersion};

#[derive(Clone, Debug)]
pub struct ID1Section {
    pub seglist: Vec<SegInfo>,
}

impl ID1Section {
    pub(crate) fn read<K: IDAKind>(
        input: &mut impl IdbRead,
        compress: IDBSectionCompression,
    ) -> Result<Self> {
        match compress {
            IDBSectionCompression::None => Self::read_inner::<K>(input),
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                Self::read_inner::<K>(&mut input)
            }
        }
    }

    fn read_inner<K: IDAKind>(input: &mut impl IdbRead) -> Result<Self> {
        // TODO pages are always 0x2000?
        const PAGE_SIZE: usize = 0x2000;
        let mut buf = vec![0; PAGE_SIZE];
        input.read_exact(&mut buf[..])?;
        let mut header_page = &buf[..];
        let version = VaVersion::read(&mut header_page)?;
        let (npages, seglist_raw) = match version {
            VaVersion::Va0
            | VaVersion::Va1
            | VaVersion::Va2
            | VaVersion::Va3
            | VaVersion::Va4 => {
                let nsegments = header_page.read_u16()?;
                let npages = header_page.read_u16()?;
                ensure!(
                    npages > 0,
                    "Invalid number of pages, net at least one for the header"
                );
                // TODO section_size / npages == 0x2000

                // TODO the reference code uses the magic version, should it use
                // the version itself instead?
                let seglist: Vec<SegInfoVaNRaw<K>> = (0..nsegments)
                    .map(|_| {
                        let start =
                            IdbReadKind::<K>::read_word(&mut header_page)?;
                        let end =
                            IdbReadKind::<K>::read_word(&mut header_page)?;
                        ensure!(start <= end);
                        let offset =
                            IdbReadKind::<K>::read_word(&mut header_page)?;
                        Ok(SegInfoVaNRaw {
                            address: start..end,
                            offset,
                        })
                    })
                    .collect::<Result<_>>()?;
                (u32::from(npages), SegInfoRaw::VaN(seglist))
            }
            VaVersion::VaX => {
                let unknown_always3: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                ensure!(unknown_always3 == 3);
                let nsegments: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                let unknown_always2048: u32 =
                    bincode::deserialize_from(&mut header_page)?;
                ensure!(unknown_always2048 == 2048);
                let npages: u32 = bincode::deserialize_from(&mut header_page)?;

                let seglist = (0..nsegments)
                    // TODO the reference code uses the magic version, should it use
                    // the version itself instead?
                    .map(|_| {
                        let start =
                            IdbReadKind::<K>::read_word(&mut header_page)?;
                        let end =
                            IdbReadKind::<K>::read_word(&mut header_page)?;
                        ensure!(start <= end);
                        Ok(start..end)
                    })
                    .collect::<Result<_>>()?;
                (npages, SegInfoRaw::VaX(seglist))
            }
        };
        // make sure the unused values a all zero
        ensure!(header_page.iter().all(|b| *b == 0));

        // sort segments by address
        let mut overlay_check = match &seglist_raw {
            SegInfoRaw::VaN(segs) => {
                segs.iter().map(|s| s.address.clone()).collect()
            }
            SegInfoRaw::VaX(segs) => segs.clone(),
        };
        overlay_check.sort_unstable_by_key(|s| s.start);

        // make sure segments don't overlap
        let overlap = overlay_check.windows(2).any(|segs| {
            let [seg1, seg2] = segs else { unreachable!() };
            seg1.end >= seg2.start
        });
        ensure!(!overlap);

        // make sure the data fits the available pages
        let required_size: K::Usize = overlay_check
            .iter()
            .map(|s| (s.end - s.start) * K::Usize::from(4u8))
            .sum();
        let round_up = required_size.rem(K::Usize::try_from(PAGE_SIZE).unwrap())
            != K::Usize::from(0u8);
        let required_pages = required_size
            .div(K::Usize::try_from(PAGE_SIZE).unwrap())
            + K::Usize::from(round_up as u8);
        // TODO if the extra data at the end of the section is identified, review replacing <= with ==
        // -1 because the first page is always the header
        ensure!(required_pages <= K::Usize::from(npages - 1));

        // populated the seglist data using the pages
        let seglist = match seglist_raw {
            SegInfoRaw::VaN(mut segs) => {
                // sort it by disk offset, so we can read one after the other
                segs.sort_unstable_by_key(|s| s.offset);
                let mut current_offset = K::Usize::try_from(PAGE_SIZE).unwrap();
                segs.into_iter()
                    .map(|seg| {
                        // skip any gaps
                        match seg.offset.cmp(&current_offset) {
                            std::cmp::Ordering::Less => {
                                return Err(anyhow!("invalid offset"))
                            }
                            std::cmp::Ordering::Greater => {
                                // TODO can be any deleted sector contains randon data?
                                // skip intermidiate bytes, also ensuring they are all zeros
                                ensure_all_bytes_are_zero(
                                    std::io::Read::take(
                                        &mut *input,
                                        (seg.offset - current_offset).into(),
                                    ),
                                    &mut buf,
                                )?;
                                current_offset = seg.offset;
                            }
                            std::cmp::Ordering::Equal => {}
                        }
                        let len = seg.address.end - seg.address.start;
                        let data = read_data::<K>(&mut *input, len)?;
                        current_offset += len * K::Usize::from(4u8);
                        Ok(SegInfo {
                            offset: (seg.address.start).into(),
                            data,
                        })
                    })
                    .collect::<Result<_>>()?
            }
            SegInfoRaw::VaX(segs) => {
                // the data for the segments are stored sequentialy in disk
                segs.into_iter()
                    .map(|address| {
                        let data = read_data::<K>(
                            &mut *input,
                            address.end - address.start,
                        )?;
                        Ok(SegInfo {
                            offset: (address.start).into(),
                            data,
                        })
                    })
                    .collect::<Result<_>>()?
            }
        };

        //// ensure the rest of the data (page alignment) is just zeros
        //ensure_all_bytes_are_zero(input, &mut buf)?;
        // TODO sometimes there some extra data with unknown meaning, maybe it's just a
        // deleted segment
        ignore_bytes(input, &mut buf)?;

        Ok(Self { seglist })
    }

    pub fn byte_by_address(&self, address: u64) -> Option<ByteInfoRaw> {
        for seg in &self.seglist {
            let addr_range =
                seg.offset..seg.offset + u64::try_from(seg.data.len()).unwrap();
            if addr_range.contains(&address) {
                return Some(ByteInfoRaw(
                    seg.data[usize::try_from(address - seg.offset).unwrap()],
                ));
            }
        }
        None
    }

    pub fn all_bytes(
        &self,
    ) -> impl Iterator<Item = (u64, ByteInfoRaw)> + use<'_> {
        self.seglist.iter().flat_map(|seg| {
            seg.data.iter().enumerate().map(|(i, b)| {
                (seg.offset + u64::try_from(i).unwrap(), ByteInfoRaw(*b))
            })
        })
    }
}

#[derive(Clone, Debug)]
pub struct SegInfo {
    pub offset: u64,
    // data and flags
    data: Vec<u32>,
}

#[derive(Clone, Copy, Debug)]
pub struct ByteInfoRaw(u32);

impl ByteInfoRaw {
    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn byte_raw(&self) -> u8 {
        (self.0 & flag::byte::MS_VAL) as u8
    }

    pub fn flags_raw(&self) -> u32 {
        self.0 & !flag::byte::MS_VAL
    }

    pub fn decode(&self) -> Result<ByteInfo> {
        ByteInfo::from_raw(*self)
    }

    pub fn byte_value(&self) -> Option<u8> {
        (self.0 & flag::byte::FF_IVL != 0)
            .then(|| (self.0 & flag::byte::MS_VAL) as u8)
    }

    pub fn byte_type(&self) -> ByteRawType {
        use flag::flags::byte_type::*;
        match self.0 & MS_CLS {
            FF_DATA => ByteRawType::Data,
            FF_CODE => ByteRawType::Code,
            FF_TAIL => ByteRawType::Tail,
            FF_UNK => ByteRawType::Unknown,
            _ => unreachable!(),
        }
    }

    pub fn has_comment(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_COMM != 0
    }
    pub fn has_reference(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_REF != 0
    }
    pub fn has_comment_ext(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_LINE != 0
    }
    pub fn has_name(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_NAME != 0
    }
    pub fn has_dummy_name(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_LABL != 0
    }
    pub fn exec_flow_from_prev_inst(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_FLOW != 0
    }
    pub fn op_invert_sig(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_SIGN != 0
    }
    pub fn op_bitwise_negation(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_BNOT != 0
    }
    pub fn is_unused_set(&self) -> bool {
        self.0 & flag::flags::byte_info::FF_UNUSED != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteInfo {
    pub byte_value: Option<u8>,
    pub has_comment: bool,
    pub has_reference: bool,
    pub has_comment_ext: bool,
    pub has_name: bool,
    pub has_dummy_name: bool,
    pub exec_flow_from_prev_inst: bool,
    pub op_invert_sig: bool,
    pub op_bitwise_negation: bool,
    pub is_unused_set: bool,
    pub byte_type: ByteType,
}

impl ByteInfo {
    fn from_raw(value: ByteInfoRaw) -> Result<Self> {
        let byte_type = ByteType::from_raw(value)?;
        Ok(Self {
            byte_value: value.byte_value(),
            has_comment: value.has_comment(),
            has_reference: value.has_reference(),
            has_comment_ext: value.has_comment_ext(),
            has_name: value.has_name(),
            has_dummy_name: value.has_dummy_name(),
            exec_flow_from_prev_inst: value.exec_flow_from_prev_inst(),
            op_invert_sig: value.op_invert_sig(),
            op_bitwise_negation: value.op_bitwise_negation(),
            is_unused_set: value.is_unused_set(),
            byte_type,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteRawType {
    Code,
    Data,
    Tail,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteType {
    Code(CodeData),
    Data(ByteData),
    Tail,
    Unknown,
}

impl ByteType {
    fn from_raw(value: ByteInfoRaw) -> Result<Self> {
        match value.byte_type() {
            // TODO find the InnerRef for this decoding, this is not correct
            ByteRawType::Code => {
                Ok(ByteType::Code(CodeData::from_raw(value.0.into())?))
            }
            ByteRawType::Data => {
                Ok(ByteType::Data(ByteData::from_raw(value.0)?))
            }
            ByteRawType::Tail => Ok(ByteType::Tail),
            ByteRawType::Unknown => Ok(ByteType::Unknown),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodeData {
    pub operands: [InstOpInfo; 8],
    pub is_func_start: bool,
    pub is_reserved_set: bool,
    pub is_immediate_value: bool,
    pub is_jump_table: bool,
}

impl CodeData {
    fn from_raw(value: u64) -> Result<Self> {
        use flag::flags::code_info::*;
        let is_func_start = value & FF_FUNC as u64 != 0;
        let is_reserved_set = value & FF_RESERVED as u64 != 0;
        let is_immediate_value = value & FF_IMMD as u64 != 0;
        let is_jump_table = value & FF_JUMP as u64 != 0;
        #[cfg(feature = "restrictive")]
        if value
            & (MS_CODE as u64)
            & !((FF_FUNC | FF_RESERVED | FF_IMMD | FF_JUMP) as u64)
            != 0
        {
            return Err(anyhow!("Invalid id1 CodeData flag"));
        }
        let operands = [
            InstOpInfo::from_raw(value.into(), 7)?,
            InstOpInfo::from_raw(value.into(), 6)?,
            InstOpInfo::from_raw(value.into(), 5)?,
            InstOpInfo::from_raw(value.into(), 4)?,
            InstOpInfo::from_raw(value.into(), 3)?,
            InstOpInfo::from_raw(value.into(), 2)?,
            InstOpInfo::from_raw(value.into(), 1)?,
            InstOpInfo::from_raw(value.into(), 0)?,
        ];
        Ok(CodeData {
            is_func_start,
            is_reserved_set,
            is_immediate_value,
            is_jump_table,
            operands,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteData {
    pub data_type: ByteDataType,
    pub print_info: InstOpInfo,
}

impl ByteData {
    fn from_raw(value: u32) -> Result<Self> {
        Ok(Self {
            data_type: ByteDataType::from_raw(value),
            print_info: InstOpInfo::from_raw(value.into(), 0)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteDataType {
    Byte,
    Word,
    Dword,
    Qword,
    Oword,
    Yword,
    Zword,
    Tbyte,
    Float,
    Double,
    Packreal,
    Strlit,
    Struct,
    Align,
    Reserved,
    Custom,
}

impl ByteDataType {
    fn from_raw(value: u32) -> Self {
        use flag::flags::data_info::*;
        match value & DT_TYPE {
            FF_BYTE => ByteDataType::Byte,
            FF_WORD => ByteDataType::Word,
            FF_DWORD => ByteDataType::Dword,
            FF_QWORD => ByteDataType::Qword,
            FF_TBYTE => ByteDataType::Tbyte,
            FF_STRLIT => ByteDataType::Strlit,
            FF_STRUCT => ByteDataType::Struct,
            FF_OWORD => ByteDataType::Oword,
            FF_FLOAT => ByteDataType::Float,
            FF_DOUBLE => ByteDataType::Double,
            FF_PACKREAL => ByteDataType::Packreal,
            FF_ALIGN => ByteDataType::Align,
            FF_RESERVED => ByteDataType::Reserved,
            FF_CUSTOM => ByteDataType::Custom,
            FF_YWORD => ByteDataType::Yword,
            FF_ZWORD => ByteDataType::Zword,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InstOpInfo {
    /// Void (unknown)
    Void,
    /// Hexadecimal number
    Hex,
    /// Decimal number
    Dec,
    /// Char
    Char,
    /// Segment
    Seg,
    /// Offset
    Off,
    /// Binary number
    Bin,
    /// Octal number
    Oct,
    /// Enumeration
    Enum,
    /// Forced operand
    Fop,
    /// Struct offset
    StrOff,
    /// Stack variable
    StackVar,
    /// Floating point number
    Float,
    /// Custom representation
    Custom,
}

impl InstOpInfo {
    fn from_raw(value: u64, n: u32) -> Result<Self> {
        use flag::flags::inst_info::*;
        Ok(
            match ((value >> get_operand_type_shift(n)) as u8) & MS_N_TYPE {
                FF_N_VOID => Self::Void,
                FF_N_NUMH => Self::Hex,
                FF_N_NUMD => Self::Dec,
                FF_N_CHAR => Self::Char,
                FF_N_SEG => Self::Seg,
                FF_N_OFF => Self::Off,
                FF_N_NUMB => Self::Bin,
                FF_N_NUMO => Self::Oct,
                FF_N_ENUM => Self::Enum,
                FF_N_FOP => Self::Fop,
                FF_N_STRO => Self::StrOff,
                FF_N_STK => Self::StackVar,
                FF_N_FLT => Self::Float,
                FF_N_CUST => Self::Custom,
                // TODO reserved values?
                #[cfg(not(feature = "restrictive"))]
                0xE | 0xF => Self::Custom,
                #[cfg(feature = "restrictive")]
                0xE | 0xF => return Err(anyhow!("Invalid ID1 operand value")),
                _ => unreachable!(),
            },
        )
    }
}

#[derive(Clone, Debug)]
enum SegInfoRaw<K: IDAKind> {
    VaN(Vec<SegInfoVaNRaw<K>>),
    VaX(Vec<Range<K::Usize>>),
}

#[derive(Clone, Debug)]
struct SegInfoVaNRaw<K: IDAKind> {
    address: Range<K::Usize>,
    offset: K::Usize,
}

fn ensure_all_bytes_are_zero(
    mut input: impl IdbRead,
    buf: &mut [u8],
) -> Result<()> {
    loop {
        match input.read(buf) {
            // found EoF
            Ok(0) => break,
            // read something
            Ok(n) => ensure!(&buf[..n].iter().all(|b| *b == 0)),
            // ignore interrupts
            Err(ref e)
                if matches!(e.kind(), std::io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(e.into()),
        };
    }
    Ok(())
}

fn ignore_bytes(mut input: impl IdbRead, buf: &mut [u8]) -> Result<()> {
    loop {
        match input.read(buf) {
            // found EoF
            Ok(0) => break,
            // read something
            Ok(_n) => {}
            // ignore interrupts
            Err(ref e)
                if matches!(e.kind(), std::io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(e.into()),
        };
    }
    Ok(())
}

fn read_data<K: IDAKind>(
    mut input: impl IdbRead,
    len: K::Usize,
) -> Result<Vec<u32>> {
    let len = <K::Usize as TryInto<usize>>::try_into(len).unwrap();
    let mut data = vec![0u8; len * 4];
    input.read_exact(&mut data)?;
    Ok(data
        .chunks(4)
        .map(|b| {
            let data = u32::from_le_bytes(b.try_into().unwrap());
            data
        })
        .collect())
}

const fn get_operand_type_shift(n: u32) -> u32 {
    let n_mod = (n > 1) as u32;
    20 + (4 * (n + n_mod))
}

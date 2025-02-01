use anyhow::Result;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use std::num::{NonZeroU32, NonZeroU8};
use std::ops::Range;

use super::*;

#[derive(Clone, Copy, Debug)]
pub struct SegmentStringsIdx<'a>(pub(crate) &'a [u8]);

#[derive(Clone, Debug)]
pub struct Segment {
    pub address: Range<u64>,
    pub name: Option<SegmentNameIdx>,
    // TODO class String
    _class_id: u64,
    /// This field is IDP dependent.
    /// You may keep your information about the segment here
    pub orgbase: u64,
    /// See more at [flags](https://hex-rays.com//products/ida/support/sdkdoc/group___s_f_l__.html)
    pub flags: SegmentFlag,
    /// [Segment alignment codes](https://hex-rays.com//products/ida/support/sdkdoc/group__sa__.html)
    pub align: SegmentAlignment,
    /// [Segment combination codes](https://hex-rays.com//products/ida/support/sdkdoc/group__sc__.html)
    pub comb: SegmentCombination,
    /// [Segment permissions](https://hex-rays.com//products/ida/support/sdkdoc/group___s_e_g_p_e_r_m__.html) (0 means no information)
    pub perm: Option<SegmentPermission>,
    /// Number of bits in the segment addressing.
    pub bitness: SegmentBitness,
    /// Segment type (see [Segment types](https://hex-rays.com//products/ida/support/sdkdoc/group___s_e_g__.html)).
    /// The kernel treats different segment types differently. Segments marked with '*' contain no instructions or data and are not declared as 'segments' in the disassembly.
    pub seg_type: SegmentType,
    /// Segment selector - should be unique.
    /// You can't change this field after creating the segment.
    /// Exception: 16bit OMF files may have several segments with the same selector,
    /// but this is not good (no way to denote a segment exactly) so it should be fixed in
    /// the future.
    pub selector: u64,
    /// Default segment register values.
    /// First element of this array keeps information about value of [processor_t::reg_first_sreg](https://hex-rays.com//products/ida/support/sdkdoc/structprocessor__t.html#a4206e35bf99d211c18d53bd1035eb2e3)
    pub defsr: [u64; 16],
    /// the segment color
    pub color: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentNameIdx(pub(crate) NonZeroU32);

impl Segment {
    pub(crate) fn read(value: &[u8], is_64: bool) -> Result<Self> {
        let mut cursor = IdaUnpacker::new(value, is_64);
        // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x330684
        let startea = cursor.unpack_usize()?;
        let size = cursor.unpack_usize()?;
        let name_id = cursor.unpack_usize()?;
        let name_id = NonZeroU32::new(u32::try_from(name_id).unwrap());
        let name = name_id.map(SegmentNameIdx);
        // TODO AKA [sclass](https://hex-rays.com//products/ida/support/sdkdoc/classsegment__t.html)
        // I don't know what is this value or what it represents
        let _class_id = cursor.unpack_usize()?;
        let orgbase = cursor.unpack_usize()?;
        let flags = SegmentFlag::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Flag value"))?;
        let align = u8::try_from(cursor.unpack_dd()?)
            .ok()
            .and_then(|x| SegmentAlignment::try_from_primitive(x).ok())
            .ok_or_else(|| anyhow!("Invalid Segment Alignment value"))?;
        let comb = SegmentCombination::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Combination value"))?;
        let perm = SegmentPermission::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Permission value"))?;
        let bitness = SegmentBitness::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Bitness value"))?;
        let seg_type = u8::try_from(cursor.unpack_dd()?)
            .ok()
            .and_then(|x| SegmentType::try_from(x).ok())
            .ok_or_else(|| anyhow!("Invalid Segment Type value"))?;
        let selector = cursor.unpack_usize()?;
        let defsr: [_; 16] = (0..16)
            .map(|_| cursor.unpack_usize())
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();
        let color = cursor.unpack_dd()?;

        // TODO maybe new versions include extra information and thid check fails
        ensure!(cursor.inner().is_empty());
        Ok(Segment {
            address: startea..startea + size,
            name,
            _class_id,
            orgbase,
            flags,
            align,
            comb,
            perm,
            bitness,
            seg_type,
            selector,
            defsr,
            color,
        })
    }
}

#[derive(Clone, Copy)]
pub struct SegmentFlag(u8);
impl SegmentFlag {
    fn from_raw(value: u32) -> Option<Self> {
        if value > 0x80 - 1 {
            return None;
        }
        Some(Self(value as u8))
    }

    /// IDP dependent field (IBM PC: if set, ORG directive is not commented out)
    pub fn is_comorg(&self) -> bool {
        self.0 & 0x01 != 0
    }
    /// Orgbase is present? (IDP dependent field)
    pub fn is_orgbase_present(&self) -> bool {
        self.0 & 0x02 != 0
    }
    /// Is the segment hidden?
    pub fn is_hidden(&self) -> bool {
        self.0 & 0x04 != 0
    }
    /// Is the segment created for the debugger?.
    ///
    /// Such segments are temporary and do not have permanent flags.
    pub fn is_debug(&self) -> bool {
        self.0 & 0x08 != 0
    }
    /// Is the segment created by the loader?
    pub fn is_created_by_loader(&self) -> bool {
        self.0 & 0x10 != 0
    }
    /// Hide segment type (do not print it in the listing)
    pub fn is_hide_type(&self) -> bool {
        self.0 & 0x20 != 0
    }
    /// Header segment (do not create offsets to it in the disassembly)
    pub fn is_header(&self) -> bool {
        self.0 & 0x40 != 0
    }
}

impl core::fmt::Debug for SegmentFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SegmentFlag(")?;
        let flags: Vec<&str> = self
            .is_comorg()
            .then_some("Comorg")
            .into_iter()
            .chain(self.is_orgbase_present().then_some("Orgbase"))
            .chain(self.is_hidden().then_some("Hidden"))
            .chain(self.is_debug().then_some("Debug"))
            .chain(self.is_created_by_loader().then_some("LoaderCreated"))
            .chain(self.is_hide_type().then_some("HideType"))
            .chain(self.is_header().then_some("Header"))
            .collect();
        write!(f, "{}", flags.join(","))?;
        write!(f, ")")
    }
}

#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SegmentAlignment {
    /// Absolute segment.
    Abs = 0,
    /// Relocatable, byte aligned.
    RelByte = 1,
    /// Relocatable, word (2-byte) aligned.
    RelWord = 2,
    /// Relocatable, paragraph (16-byte) aligned.
    RelPara = 3,
    /// Relocatable, aligned on 256-byte boundary.
    RelPage = 4,
    /// Relocatable, aligned on a double word (4-byte) boundary.
    RelDble = 5,
    /// This value is used by the PharLap OMF for page (4K) alignment.
    ///
    /// It is not supported by LINK.
    Rel4K = 6,
    /// Segment group.
    Group = 7,
    /// 32 bytes
    Rel32Bytes = 8,
    /// 64 bytes
    Rel64Bytes = 9,
    /// 8 bytes
    RelQword = 10,
    /// 128 bytes
    Rel128Bytes = 11,
    /// 512 bytes
    Rel512Bytes = 12,
    /// 1024 bytes
    Rel1024Bytes = 13,
    /// 2048 bytes
    Rel2048Bytes = 14,
}

#[derive(Clone, Copy, Debug)]
pub enum SegmentCombination {
    /// Private.
    ///
    /// Do not combine with any other program segment.
    Priv,
    /// Segment group.
    Group,
    /// Public.
    ///
    /// Combine by appending at an offset that meets the alignment requirement.
    Pub,
    /// As defined by Microsoft, same as C=2 (public).
    Pub2,
    /// Stack.
    Stack,
    /// Common. Combine by overlay using maximum size.
    ///
    /// Combine as for C=2. This combine type forces byte alignment.
    Common,
    /// As defined by Microsoft, same as C=2 (public).
    Pub3,
}

impl SegmentCombination {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Priv),
            1 => Some(Self::Group),
            2 => Some(Self::Pub),
            4 => Some(Self::Pub2),
            5 => Some(Self::Stack),
            6 => Some(Self::Common),
            7 => Some(Self::Pub3),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SegmentPermission(NonZeroU8);

impl SegmentPermission {
    fn from_raw(value: u32) -> Option<Option<Self>> {
        if value > 7 {
            return None;
        }
        Some(NonZeroU8::new(value as u8).map(Self))
    }

    pub fn can_execute(&self) -> bool {
        self.0.get() & 1 != 0
    }

    pub fn can_write(&self) -> bool {
        self.0.get() & 2 != 0
    }

    pub fn can_read(&self) -> bool {
        self.0.get() & 4 != 0
    }
}

impl core::fmt::Debug for SegmentPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SegmentPermission(")?;
        if self.can_read() {
            write!(f, "R")?;
        }
        if self.can_write() {
            write!(f, "W")?;
        }
        if self.can_execute() {
            write!(f, "X")?;
        }
        write!(f, ")")
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SegmentBitness {
    S16Bits,
    S32Bits,
    S64Bits,
}

impl SegmentBitness {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::S16Bits),
            1 => Some(Self::S32Bits),
            2 => Some(Self::S64Bits),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SegmentType {
    /// unknown type, no assumptions
    Norm = 0,
    /// segment with 'extern' definitions.
    ///
    /// no instructions are allowed
    Xtrn = 1,
    /// code segment
    Code = 2,
    /// data segment
    Data = 3,
    /// java: implementation segment
    Imp = 4,
    /// group of segments
    Grp = 6,
    /// zero-length segment
    Null = 7,
    /// undefined segment type (not used)
    Undf = 8,
    /// uninitialized segment
    Bss = 9,
    /// segment with definitions of absolute symbols
    Abssym = 10,
    /// segment with communal definitions
    Comm = 11,
    /// internal processor memory & sfr (8051)
    Imem = 12,
}

pub struct SegmentIter<'a> {
    pub(crate) id0: &'a ID0Section,
    pub(crate) segments: &'a [ID0Entry],
}

impl<'a> Iterator for SegmentIter<'a> {
    type Item = Result<Segment>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some((current, rest)) = self.segments.split_first() else {
            return None;
        };
        self.segments = rest;
        Some(Segment::read(&current.value, self.id0.is_64))
    }
}

#[derive(Clone, Copy)]
pub struct SegmentStringIter<'a> {
    pub(crate) segments: &'a [ID0Entry],
    pub(crate) segment_strings: SegmentStringsIter<'a>,
}

impl<'a> SegmentStringIter<'a> {
    pub(crate) fn new(segments: &'a [ID0Entry]) -> Self {
        // dummy value
        let segment_strings = SegmentStringsIter {
            start: 0,
            end: 0,
            value: &[],
        };
        Self {
            segments,
            segment_strings,
        }
    }
    fn inner_next(&mut self) -> Result<Option<(SegmentNameIdx, &'a [u8])>> {
        // get the next segment string
        if let Some(value) = self.segment_strings.next() {
            return Some(value).transpose();
        }
        // no strings in this segment, next segment
        let Some((current, rest)) = self.segments.split_first() else {
            return Ok(None);
        };
        self.segments = rest;

        let mut current_value = &current.value[..];
        let start = current_value.unpack_dd()?;
        let end = current_value.unpack_dd()?;
        ensure!(start > 0, "Invalid ID0 Segment String idx start");
        ensure!(start <= end, "Invalid ID0 Segment String idx end");
        self.segment_strings = SegmentStringsIter {
            start,
            end,
            value: current_value,
        };
        self.inner_next()
    }
}

impl<'a> Iterator for SegmentStringIter<'a> {
    type Item = Result<(SegmentNameIdx, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_next().transpose()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SegmentStringsIter<'a> {
    pub(crate) start: u32,
    pub(crate) end: u32,
    pub(crate) value: &'a [u8],
}

impl<'a> SegmentStringsIter<'a> {
    fn inner_next(&mut self) -> Result<Option<(SegmentNameIdx, &'a [u8])>> {
        if self.start == self.end {
            ensure!(
                self.value.is_empty(),
                "Unparsed data in ID0 Segment String: {}",
                self.value.len()
            );
            return Ok(None);
        }
        let len = self.value.unpack_dd()?;
        let (value, rest) = self
            .value
            .split_at_checked(len.try_into().unwrap())
            .ok_or_else(|| anyhow!("Invalid ID0 Segment String len"))?;
        self.value = rest;
        let idx = self.start;
        self.start += 1;
        Ok(Some((SegmentNameIdx(idx.try_into().unwrap()), value)))
    }
}

impl<'a> Iterator for SegmentStringsIter<'a> {
    type Item = Result<(SegmentNameIdx, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_next().transpose()
    }
}

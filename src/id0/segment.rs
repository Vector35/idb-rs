use anyhow::Result;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::Serialize;

use std::marker::PhantomData;
use std::num::NonZeroU8;
use std::ops::Range;

use crate::ida_reader::IdbReadKind;
use crate::Address;

use super::*;

#[derive(Clone, Copy, Debug)]
pub struct SegmentIdx<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> From<SegmentIdx<K>> for NetnodeIdx<K> {
    fn from(value: SegmentIdx<K>) -> Self {
        Self(value.0)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SegmentStringsIdx<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> From<SegmentStringsIdx<K>> for NetnodeIdx<K> {
    fn from(value: SegmentStringsIdx<K>) -> Self {
        Self(value.0)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Segment<K: IDAKind> {
    pub address: Range<Address<K>>,
    pub name: SegmentNameIdx<K>,
    // TODO class String
    pub class_id: SegmentNameIdx<K>,
    /// This field is IDP dependent.
    /// You may keep your information about the segment here
    pub orgbase: K::Usize,
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
    pub selector: K::Usize,
    /// Default segment register values.
    /// First element of this array keeps information about value of [processor_t::reg_first_sreg](https://hex-rays.com//products/ida/support/sdkdoc/structprocessor__t.html#a4206e35bf99d211c18d53bd1035eb2e3)
    pub defsr: [K::Usize; 16],
    /// the segment color
    pub color: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SegmentNameIdx<K: IDAKind>(pub K::Usize);

impl<K: IDAKind> Segment<K> {
    pub(crate) fn read(value: &[u8]) -> Result<Self> {
        let mut cursor = value;
        let result = Self::inner_read(&mut cursor)?;
        ensure!(cursor.is_empty());
        Ok(result)
    }

    pub(crate) fn inner_read(cursor: &mut impl IdbReadKind<K>) -> Result<Self> {
        // InnerRef 5c1b89aa-5277-4c98-98f6-cec08e1946ec 0x330684
        let startea = cursor.unpack_usize()?;
        let size = cursor.unpack_usize()?;
        let name = SegmentNameIdx(cursor.unpack_usize()?);
        // TODO AKA [sclass](https://hex-rays.com//products/ida/support/sdkdoc/classsegment__t.html)
        // I don't know what is this value or what it represents
        let class_id = SegmentNameIdx(cursor.unpack_usize()?);
        let orgbase = cursor.unpack_usize()?;
        let flags = SegmentFlag::from_raw(cursor.unpack_dd()?)
            .ok_or_else(|| anyhow!("Invalid Segment Flag value"))?;
        let align = u8::try_from(cursor.unpack_dd()?)
            .ok()
            .and_then(|x| SegmentAlignment::try_from_primitive(x).ok())
            .ok_or_else(|| anyhow!("Invalid Segment Alignment value"))?;
        let comb_raw = cursor.unpack_dd()?;
        let comb = u8::try_from(comb_raw)
            .ok()
            .and_then(|x| SegmentCombination::try_from_primitive(x).ok())
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

        Ok(Segment {
            address: Address::from_raw(startea)
                ..Address::from_raw(startea + size),
            name,
            class_id,
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

#[derive(Clone, Copy, Serialize)]
pub struct SegmentFlag(u8);
impl SegmentFlag {
    fn from_raw(value: u32) -> Option<Self> {
        if value > 0x80 - 1 {
            return None;
        }
        Some(Self(value as u8))
    }

    pub(crate) fn into_raw(self) -> u8 {
        self.0
    }

    /// IDP dependent field (IBM PC: if set, ORG directive is not commented out)
    pub fn is_comorg(&self) -> bool {
        self.0 & flag::segs::sfl::SFL_COMORG != 0
    }
    /// Orgbase is present? (IDP dependent field)
    pub fn is_orgbase_present(&self) -> bool {
        self.0 & flag::segs::sfl::SFL_OBOK != 0
    }
    /// Is the segment hidden?
    pub fn is_hidden(&self) -> bool {
        self.0 & flag::segs::sfl::SFL_HIDDEN != 0
    }
    /// Is the segment created for the debugger?.
    ///
    /// Such segments are temporary and do not have permanent flags.
    pub fn is_debug(&self) -> bool {
        self.0 & flag::segs::sfl::SFL_DEBUG != 0
    }
    /// Is the segment created by the loader?
    pub fn is_created_by_loader(&self) -> bool {
        self.0 & flag::segs::sfl::SFL_LOADER != 0
    }
    /// Hide segment type (do not print it in the listing)
    pub fn is_hide_type(&self) -> bool {
        self.0 & flag::segs::sfl::SFL_HIDETYPE != 0
    }
    /// Header segment (do not create offsets to it in the disassembly)
    pub fn is_header(&self) -> bool {
        self.0 & flag::segs::sfl::SFL_HEADER != 0
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

#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive, Serialize)]
#[repr(u8)]
pub enum SegmentAlignment {
    /// Absolute segment.
    Abs = flag::segs::sa::SA_ABS,
    /// Relocatable, byte aligned.
    RelByte = flag::segs::sa::SA_REL_BYTE,
    /// Relocatable, word (2-byte) aligned.
    RelWord = flag::segs::sa::SA_REL_WORD,
    /// Relocatable, paragraph (16-byte) aligned.
    RelPara = flag::segs::sa::SA_REL_PARA,
    /// Relocatable, aligned on 256-byte boundary.
    RelPage = flag::segs::sa::SA_REL_PAGE,
    /// Relocatable, aligned on a double word (4-byte) boundary.
    RelDble = flag::segs::sa::SA_REL_DBLE,
    /// This value is used by the PharLap OMF for page (4K) alignment.
    ///
    /// It is not supported by LINK.
    Rel4K = flag::segs::sa::SA_REL4_K,
    /// Segment group.
    Group = flag::segs::sa::SA_GROUP,
    /// 32 bytes
    Rel32Bytes = flag::segs::sa::SA_REL32_BYTES,
    /// 64 bytes
    Rel64Bytes = flag::segs::sa::SA_REL64_BYTES,
    /// 8 bytes
    RelQword = flag::segs::sa::SA_REL_QWORD,
    /// 128 bytes
    Rel128Bytes = flag::segs::sa::SA_REL128_BYTES,
    /// 512 bytes
    Rel512Bytes = flag::segs::sa::SA_REL512_BYTES,
    /// 1024 bytes
    Rel1024Bytes = flag::segs::sa::SA_REL1024_BYTES,
    /// 2048 bytes
    Rel2048Bytes = flag::segs::sa::SA_REL2048_BYTES,
}

#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive, Serialize)]
#[repr(u8)]
pub enum SegmentCombination {
    /// Private.
    ///
    /// Do not combine with any other program segment.
    Priv = super::flag::segs::sc::SC_PRIV,
    /// Segment group.
    Group = super::flag::segs::sc::SC_GROUP,
    /// Public.
    ///
    /// Combine by appending at an offset that meets the alignment requirement.
    Pub = super::flag::segs::sc::SC_PUB,
    /// As defined by Microsoft, same as C=2 (public).
    Pub2 = super::flag::segs::sc::SC_PUB2,
    /// Stack.
    Stack = super::flag::segs::sc::SC_STACK,
    /// Common. Combine by overlay using maximum size.
    ///
    /// Combine as for C=2. This combine type forces byte alignment.
    Common = super::flag::segs::sc::SC_COMMON,
    /// As defined by Microsoft, same as C=2 (public).
    Pub3 = super::flag::segs::sc::SC_PUB3,
}

#[derive(Clone, Copy, Serialize)]
pub struct SegmentPermission(NonZeroU8);

impl SegmentPermission {
    fn from_raw(value: u32) -> Option<Option<Self>> {
        if value > 7 {
            return None;
        }
        Some(NonZeroU8::new(value as u8).map(Self))
    }

    pub(crate) fn into_raw(self) -> u8 {
        self.0.get()
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

#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive, Serialize)]
#[repr(u8)]
pub enum SegmentBitness {
    S16Bits = 0,
    S32Bits = 1,
    S64Bits = 2,
}

impl SegmentBitness {
    fn from_raw(value: u32) -> Option<Self> {
        Self::try_from_primitive(value.try_into().ok()?).ok()
    }
}

// Has segment a special type?. (#SEG_XTRN, #SEG_GRP, #SEG_ABSSYM, #SEG_COMM)
// Does the address belong to a segment with a special type?.(#SEG_XTRN, #SEG_GRP, #SEG_ABSSYM, #SEG_COMM)
#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive, Serialize)]
#[repr(u8)]
pub enum SegmentType {
    /// unknown type, no assumptions
    Norm = flag::segs::ty::SEG_NORM,
    /// segment with 'extern' definitions.
    ///
    /// no instructions are allowed
    Xtrn = flag::segs::ty::SEG_XTRN,
    /// code segment
    Code = flag::segs::ty::SEG_CODE,
    /// data segment
    Data = flag::segs::ty::SEG_DATA,
    /// java: implementation segment
    Imp = flag::segs::ty::SEG_IMP,
    /// group of segments
    Grp = flag::segs::ty::SEG_GRP,
    /// zero-length segment
    Null = flag::segs::ty::SEG_NULL,
    /// undefined segment type (not used)
    Undf = flag::segs::ty::SEG_UNDF,
    /// uninitialized segment
    Bss = flag::segs::ty::SEG_BSS,
    /// segment with definitions of absolute symbols
    Abssym = flag::segs::ty::SEG_ABSSYM,
    /// segment with communal definitions
    Comm = flag::segs::ty::SEG_COMM,
    /// internal processor memory & sfr (8051)
    Imem = flag::segs::ty::SEG_IMEM,
}

pub struct SegmentIter<'a, K> {
    pub(crate) _kind: std::marker::PhantomData<K>,
    pub(crate) segments: &'a [ID0Entry],
}

impl<'a, K: IDAKind> Iterator for SegmentIter<'a, K> {
    type Item = Result<Segment<K>>;

    fn next(&mut self) -> Option<Self::Item> {
        let (current, rest) = self.segments.split_first()?;
        self.segments = rest;

        Some(Segment::read(&current.value[..]))
    }
}

#[derive(Clone, Copy)]
pub struct SegmentStringIter<'a, K> {
    pub(crate) segments: &'a [ID0Entry],
    pub(crate) segment_strings: SegmentStringsIter<'a, K>,
}

impl<'a, K: IDAKind> SegmentStringIter<'a, K> {
    pub(crate) fn new(segments: &'a [ID0Entry]) -> Self {
        // dummy value
        let segment_strings = SegmentStringsIter {
            start: 0,
            end: 0,
            value: IDBStr::new(&[]),
            _kind: PhantomData,
        };
        Self {
            segments,
            segment_strings,
        }
    }
    fn inner_next(
        &mut self,
    ) -> Result<Option<(SegmentNameIdx<K>, IDBStr<'a>)>> {
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
            value: IDBStr::new(current_value),
            _kind: PhantomData,
        };
        self.inner_next()
    }
}

impl<'a, K: IDAKind> Iterator for SegmentStringIter<'a, K> {
    type Item = Result<(SegmentNameIdx<K>, IDBStr<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_next().transpose()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SegmentStringsIter<'a, K> {
    pub(crate) start: u32,
    pub(crate) end: u32,
    pub(crate) value: IDBStr<'a>,
    _kind: PhantomData<K>,
}

impl<'a, K: IDAKind> SegmentStringsIter<'a, K> {
    fn inner_next(
        &mut self,
    ) -> Result<Option<(SegmentNameIdx<K>, IDBStr<'a>)>> {
        let mut bytes = self.value.as_bytes();
        if self.start == self.end {
            ensure!(
                bytes.is_empty(),
                "Unparsed data in ID0 Segment String: {}",
                bytes.len()
            );
            return Ok(None);
        }
        let len = bytes.unpack_dd()?;
        let (value, rest) = bytes
            .split_at_checked(len.try_into().unwrap())
            .ok_or_else(|| anyhow!("Invalid ID0 Segment String len"))?;
        self.value = IDBStr::new(rest);
        let idx = self.start;
        self.start += 1;
        Ok(Some((SegmentNameIdx(idx.into()), IDBStr::new(value))))
    }
}

impl<'a, K: IDAKind> Iterator for SegmentStringsIter<'a, K> {
    type Item = Result<(SegmentNameIdx<K>, IDBStr<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_next().transpose()
    }
}

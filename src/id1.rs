use anyhow::{anyhow, ensure, Result};
use flag::flags::inst_info::*;
use num_traits::CheckedAdd;

pub mod flag;
mod sparse;
pub use sparse::SparseFlags;

use std::ops::{Div, Range, Rem};

use crate::id0::flag::netnode::nn_res::*;
use crate::id0::ID0Section;
use crate::ida_reader::{IdbRead, IdbReadKind};
use crate::{Address, IDAKind, SectionReader, VaVersion};

// TODO pages are always 0x2000?
const PAGE_SIZE: usize = 0x2000;

#[derive(Clone, Debug)]
pub struct ID1Section<K: IDAKind> {
    pub seglist: Vec<SegInfo<K>>,
    /// Flags of the ranges without file data, 9.1+ databases only.
    pub sparse: Option<SparseFlags<K>>,
}

impl<K: IDAKind> SectionReader<K> for ID1Section<K> {
    type Result = Self;

    fn read_section<I: IdbReadKind<K>>(
        input: &mut I,
        _magic: crate::IDBMagic,
    ) -> Result<Self> {
        Self::read_inner(input)
    }
}

impl<K: IDAKind> ID1Section<K> {
    fn read_inner(input: &mut impl std::io::Read) -> Result<Self> {
        let mut buf = vec![0; PAGE_SIZE];
        input.read_exact(&mut buf[..])?;
        let mut cursor = &buf[..];
        let (npages, seglist_raw) = Self::read_header(&mut cursor)?;
        // make sure the unused values a all zero
        ensure!(cursor.iter().all(|b| *b == 0));

        // sort segments by address
        let mut overlay_check = match &seglist_raw {
            SegInfoRaw::VaN(segs) | SegInfoRaw::VaXOffsets(segs) => {
                segs.iter().map(|s| s.address.clone()).collect()
            }
            SegInfoRaw::VaX(segs) => segs.clone(),
        };
        overlay_check.sort_unstable_by_key(|s| s.start);

        // make sure segments don't overlap
        let overlap = overlay_check.windows(2).any(|segs| {
            let [seg1, seg2] = segs else { unreachable!() };
            seg1.end > seg2.start
        });
        ensure!(!overlap);

        // make sure the data fits the available pages
        let required_size: K::Usize = overlay_check
            .iter()
            .map(|s| (s.end - s.start) * K::Usize::from(4u8))
            .sum();
        let round_up = required_size
            .rem(K::Usize::try_from(PAGE_SIZE).unwrap())
            != K::Usize::from(0u8);
        let required_pages = required_size
            .div(K::Usize::try_from(PAGE_SIZE).unwrap())
            + K::Usize::from(round_up as u8);
        // TODO if the extra data at the end of the section is identified, review replacing <= with ==
        // -1 because the first page is always the header
        ensure!(required_pages <= K::Usize::from(npages - 1));

        // populated the seglist data using the pages
        let seglist = match seglist_raw {
            SegInfoRaw::VaN(segs) => {
                read_by_offset(&mut *input, segs, &mut buf, true)?
            }
            // kind 4 (IDA 9.5+) leaves stale data of moved ranges in the gaps
            SegInfoRaw::VaXOffsets(segs) => {
                read_by_offset(&mut *input, segs, &mut buf, false)?
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
                            offset: Address::from_raw(address.start),
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

        Ok(Self {
            seglist,
            sparse: None,
        })
    }

    fn read_header(
        input: &mut impl IdbReadKind<K>,
    ) -> Result<(u32, SegInfoRaw<K>)> {
        let version = VaVersion::read(&mut *input)?;
        match version {
            VaVersion::Va0
            | VaVersion::Va1
            | VaVersion::Va2
            | VaVersion::Va3
            | VaVersion::Va4 => {
                let nsegments = input.read_u16()?;
                let npages = input.read_u16()?;
                ensure!(
                    npages > 0,
                    "Invalid number of pages, net at least one for the header"
                );
                // TODO section_size / npages == 0x2000

                // TODO the reference code uses the magic version, should it use
                // the version itself instead?
                let seglist: Vec<SegInfoVaNRaw<K>> = (0..nsegments)
                    .map(|_| {
                        let start = input.read_usize()?;
                        let end = input.read_usize()?;
                        ensure!(start <= end);
                        let offset = input.read_usize()?;
                        Ok(SegInfoVaNRaw {
                            address: start..end,
                            offset,
                        })
                    })
                    .collect::<Result<_>>()?;
                Ok((u32::from(npages), SegInfoRaw::VaN(seglist)))
            }
            VaVersion::VaX => {
                let kind = input.read_u32()?;
                let nsegments = input.read_u32()?;
                let unknown_always2048 = input.read_u32()?;
                ensure!(unknown_always2048 == 2048);
                let npages = input.read_u32()?;

                if kind == 4 {
                    let seglist = (0..nsegments)
                        .map(|_| {
                            let start = input.read_usize()?;
                            let end = input.read_usize()?;
                            ensure!(start <= end);
                            let offset = input.read_usize()?;
                            Ok(SegInfoVaNRaw {
                                address: start..end,
                                offset,
                            })
                        })
                        .collect::<Result<_>>()?;
                    return Ok((npages, SegInfoRaw::VaXOffsets(seglist)));
                }
                ensure!(kind == 3, "Unknown ID1 VA* kind {kind}");
                let seglist = (0..nsegments)
                    // TODO the reference code uses the magic version, should it use
                    // the version itself instead?
                    .map(|_| {
                        let start = input.read_usize()?;
                        let end = input.read_usize()?;
                        ensure!(start <= end);
                        Ok(start..end)
                    })
                    .collect::<Result<_>>()?;
                Ok((npages, SegInfoRaw::VaX(seglist)))
            }
        }
    }

    pub(crate) fn segment_idx_by_address(
        &self,
        address: Address<K>,
    ) -> Result<usize, usize> {
        self.seglist.binary_search_by(|seg| {
            let seg_end = seg.offset
                + Address::from_raw(
                    K::Usize::try_from(seg.data.len()).unwrap(),
                );
            use std::cmp::Ordering::*;
            // this segment is
            match (address.cmp(&seg.offset), address.cmp(&seg_end)) {
                // after the address, get one prior
                (Less, Less) => Greater,
                // contains the addrss, get this one
                (Equal | Greater, Less) => Equal,
                // before the address, get one after
                (Greater, Greater | Equal) => Less,
                // unreachable if range is valid and not empty segments exist
                (Less | Equal, Equal) | (Equal, Greater) | (Less, Greater) => {
                    unreachable!()
                }
            }
        })
    }

    pub fn segment_by_address(
        &self,
        address: Address<K>,
    ) -> Option<&SegInfo<K>> {
        self.segment_idx_by_address(address)
            .ok()
            .map(|idx| &self.seglist[idx])
    }

    pub fn byte_by_address(&self, address: Address<K>) -> Option<ByteInfo> {
        self.segment_by_address(address)
            .map(|seg| {
                let idx: usize = (address.into_raw() - seg.offset.into_raw())
                    .try_into()
                    .unwrap();
                ByteInfo(seg.data[idx])
            })
            .or_else(|| {
                self.sparse
                    .as_ref()?
                    .flags(address.into_raw())
                    .map(ByteInfo)
            })
    }

    /// Contiguous address ranges that have flags, in address order. A range
    /// can be stored partly in ID1 and partly in IDAS.
    pub fn ranges(
        &self,
    ) -> impl Iterator<Item = Range<Address<K>>> + use<'_, K> {
        let mut stored = self.stored_ranges().peekable();
        std::iter::from_fn(move || {
            let mut range = stored.next()?;
            while let Some(next) = stored.next_if(|r| r.start == range.end) {
                range.end = next.end;
            }
            Some(to_address_range(range))
        })
    }

    /// The range from [`Self::ranges`] that contains `address`.
    pub fn range_by_address(
        &self,
        address: Address<K>,
    ) -> Option<Range<Address<K>>> {
        let address = address.into_raw();
        let (_, range) = self.ranges_around(|r| r.end <= address);
        range
            .filter(|r| r.start <= address)
            .map(|r| to_address_range(self.contiguous(r)))
    }

    /// The first range from [`Self::ranges`] that starts after `address`.
    pub fn next_range(&self, address: Address<K>) -> Option<Range<Address<K>>> {
        let address = address.into_raw();
        let (_, range) = self.ranges_around(|r| r.start <= address);
        let mut range = self.contiguous(range?);
        if range.start <= address {
            // continues the range that contains `address`
            let end = range.end;
            let (_, next) = self.ranges_around(|r| r.start < end);
            range = self.contiguous(next?);
        }
        Some(to_address_range(range))
    }

    /// The last range from [`Self::ranges`] that ends before `address`, and
    /// before the range that contains it.
    pub fn prev_range(&self, address: Address<K>) -> Option<Range<Address<K>>> {
        let address = address.into_raw();
        let (range, _) = self.ranges_around(|r| r.end <= address);
        let mut range = self.contiguous(range?);
        if range.end > address {
            // part of the range that contains `address`
            let start = range.start;
            let (prev, _) = self.ranges_around(|r| r.end <= start);
            range = self.contiguous(prev?);
        }
        Some(to_address_range(range))
    }

    /// Extend a stored range with the ranges that touch it. ID1 and IDAS
    /// don't store touching ranges themselves, but a range of one can touch
    /// a range of the other.
    fn contiguous(&self, mut range: Range<K::Usize>) -> Range<K::Usize> {
        loop {
            let start = range.start;
            match self.ranges_around(|r| r.end < start).1 {
                Some(prev) if prev.end == start && prev.start < start => {
                    range.start = prev.start
                }
                _ => break,
            }
        }
        loop {
            let end = range.end;
            match self.ranges_around(|r| r.start < end).1 {
                Some(next) if next.start == end && next.end > end => {
                    range.end = next.end
                }
                _ => break,
            }
        }
        range
    }

    /// The last range for which `before` holds and the first range for which
    /// it does not. `before` must hold for a prefix of the ranges in address
    /// order.
    pub(crate) fn ranges_around(
        &self,
        before: impl Fn(&Range<K::Usize>) -> bool,
    ) -> (Option<Range<K::Usize>>, Option<Range<K::Usize>>) {
        let id1 = self.seglist.partition_point(|seg| before(&seg.raw_range()));
        let sparse = self.sparse_ranges();
        let sparse_idx = sparse.partition_point(&before);
        let last = [
            id1.checked_sub(1).map(|i| self.seglist[i].raw_range()),
            sparse_idx.checked_sub(1).map(|i| sparse[i].clone()),
        ]
        .into_iter()
        .flatten()
        .max_by_key(|r| r.start);
        let first = [
            self.seglist.get(id1).map(SegInfo::raw_range),
            sparse.get(sparse_idx).cloned(),
        ]
        .into_iter()
        .flatten()
        .min_by_key(|r| r.start);
        (last, first)
    }

    fn sparse_ranges(&self) -> &[Range<K::Usize>] {
        self.sparse.as_ref().map_or(&[], |sparse| sparse.ranges())
    }

    /// Ranges as stored in ID1 and IDAS, in address order.
    fn stored_ranges(
        &self,
    ) -> impl Iterator<Item = Range<K::Usize>> + use<'_, K> {
        let mut id1 = self.seglist.iter().map(SegInfo::raw_range).peekable();
        let mut sparse = self.sparse_ranges().iter().cloned().peekable();
        std::iter::from_fn(move || match (id1.peek(), sparse.peek()) {
            (Some(a), Some(b)) if b.start < a.start => sparse.next(),
            (Some(_), _) => id1.next(),
            (None, _) => sparse.next(),
        })
    }

    /// Flags of the addresses in `range`, which must be inside one of
    /// [`Self::stored_ranges`].
    fn range_bytes(
        &self,
        range: Range<K::Usize>,
    ) -> Box<dyn DoubleEndedIterator<Item = (Address<K>, ByteInfo)> + '_> {
        match self.segment_by_address(Address::from_raw(range.start)) {
            Some(seg) => {
                let base = seg.offset.into_raw();
                let idx =
                    |a: K::Usize| -> usize { (a - base).try_into().unwrap() };
                Box::new(
                    seg.data[idx(range.start)..idx(range.end)]
                        .iter()
                        .enumerate()
                        .map(move |(i, b)| {
                            let addr =
                                range.start + K::Usize::try_from(i).unwrap();
                            (Address::from_raw(addr), ByteInfo(*b))
                        }),
                )
            }
            None => Box::new(
                self.sparse
                    .iter()
                    .flat_map(move |sparse| sparse.range_flags(range.clone()))
                    .map(|(a, flags)| (Address::from_raw(a), ByteInfo(flags))),
            ),
        }
    }

    pub fn all_bytes(
        &self,
    ) -> impl Iterator<Item = (Address<K>, ByteInfo)> + use<'_, K> {
        self.stored_ranges().flat_map(|r| self.range_bytes(r))
    }

    pub fn all_bytes_no_tails(
        &self,
    ) -> impl Iterator<Item = (Address<K>, ByteInfo, usize)> + use<'_, K> {
        self.stored_ranges().flat_map(|r| {
            let mut bytes = self.range_bytes(r).peekable();
            std::iter::from_fn(move || loop {
                let (address, byte) = bytes.next()?;
                if byte.byte_type().is_tail() {
                    continue;
                }
                let mut size = 1;
                while bytes.next_if(|(_, b)| b.byte_type().is_tail()).is_some()
                {
                    size += 1;
                }
                return Some((address, byte, size));
            })
        })
    }

    // if the address is inside some multi-byte thing, type like a struct or
    // instruction, get the address where it starts
    pub fn prev_not_tail(
        &self,
        ea: Address<K>,
    ) -> Option<(Address<K>, ByteInfo)> {
        // TODO can data span multiple ranges? If so this is incorrect
        let ea = ea.into_raw();
        // the range that contains the address, or the one before it
        let (range, _) = self.ranges_around(|r| r.start <= ea);
        let range = range?;
        let end = if ea < range.end {
            ea + K::Usize::from(1u8)
        } else {
            range.end
        };
        self.range_bytes(range.start..end)
            .rev()
            .find(|(_addr, byte)| !byte.byte_type().is_tail())
    }

    // get the address of the next non tail thing after `ea`
    pub fn next_not_tail(
        &self,
        ea: Address<K>,
    ) -> Option<(Address<K>, ByteInfo)> {
        let start = ea.into_raw().checked_add(&K::Usize::from(1u8))?;
        self.stored_ranges()
            .filter(|r| r.end > start)
            .flat_map(|r| self.range_bytes(r.start.max(start)..r.end))
            .find(|(_addr, byte)| !byte.byte_type().is_tail())
    }
}

#[derive(Clone, Debug)]
pub struct SegInfo<K: IDAKind> {
    pub offset: Address<K>,
    // data and flags
    data: Vec<u32>,
}

impl<K: IDAKind> SegInfo<K> {
    fn raw_range(&self) -> Range<K::Usize> {
        let start = self.offset.into_raw();
        start..start + K::Usize::try_from(self.data.len()).unwrap()
    }

    /// len of the segment in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn get(&self, idx: usize) -> Option<ByteInfo> {
        self.data.get(idx).copied().map(ByteInfo)
    }

    pub fn all_bytes(
        &self,
    ) -> impl DoubleEndedIterator<Item = (Address<K>, ByteInfo)>
           + ExactSizeIterator
           + use<'_, K> {
        self.data.iter().enumerate().map(|(current_offset, byte)| {
            let addr = self.offset
                + Address::from_raw((current_offset).try_into().unwrap());
            let byte_info = ByteInfo(*byte);
            (addr, byte_info)
        })
    }
}

// ByteInfo Information
// ALL:
// 0x0000_00ff 0b00000000_00000000__00000000_11111111 -> byte data if any
// 0x0000_0100 0b00000000_00000000__00000001_00000000 -> byte have data
// 0x0000_0600 0b00000000_00000000__00000110_00000000 -> type of byte
// 0x0007_f800 0b00000000_00000111__11111000_00000000 -> byte info
// 0x0008_0000 0b00000000_00001000__00000000_00000000 -> unused bit
//
// DATA:
// 0xf000_0000 0b11110000_00000000__00000000_00000000 -> data type
// 0x00f0_0000 0b00000000_11110000__00000000_00000000 -> operand 0
//
// CODE:
// 0x00f0_0000 0b00000000_11110000__00000000_00000000 -> operand 0
// 0x0f00_0000 0b00001111_00000000__00000000_00000000 -> operand 1
// 0xf000_0000 0b11110000_00000000__00000000_00000000 -> code info
//
// CODE with extended info, aka id0 entry:
// 0x0000_000f__0000_0000 -> operand 2
// 0x0000_00f0__0000_0000 -> operand 3
// 0x0000_0f00__0000_0000 -> operand 4
// 0x0000_f000__0000_0000 -> operand 5
// 0x000f_0000__0000_0000 -> operand 6
// 0x00f0_0000__0000_0000 -> operand 7
// 0xff00_0000__0000_0000 -> TODO ???
//
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteInfo(u32);

impl ByteInfo {
    pub(crate) fn from_raw(value: u32) -> Self {
        Self(value)
    }

    pub fn as_raw(&self) -> u32 {
        self.0
    }

    pub fn has_data(&self) -> bool {
        self.0 & flag::byte::FF_IVL != 0
    }

    pub fn data(&self) -> Option<u8> {
        self.has_data()
            .then_some((self.0 & flag::byte::MS_VAL) as u8)
    }

    pub fn byte_type(self) -> ByteType {
        ByteType::from_raw(self)
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

    pub fn operand0(&self) -> Result<Option<ByteOp>> {
        ByteOp::from_raw((self.0 >> 20) as u8 & MS_N_TYPE)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteCode(ByteInfo);
impl core::ops::Deref for ByteCode {
    type Target = ByteInfo;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ByteCode {
    pub fn operand1(&self) -> Result<Option<ByteOp>> {
        ByteOp::from_raw((self.0 .0 >> 24) as u8 & MS_N_TYPE)
    }

    pub fn is_func_start(&self) -> bool {
        self.0 .0 & flag::flags::code_info::FF_FUNC != 0
    }
    pub fn has_func_reserved_set(&self) -> bool {
        self.0 .0 & flag::flags::code_info::FF_RESERVED != 0
    }
    pub fn has_immediate_value(&self) -> bool {
        self.0 .0 & flag::flags::code_info::FF_IMMD != 0
    }
    pub fn has_jump_table(&self) -> bool {
        self.0 .0 & flag::flags::code_info::FF_JUMP != 0
    }

    pub fn extend<K: IDAKind>(
        self,
        id0: &ID0Section<K>,
        ea: K::Usize,
    ) -> Result<ByteExtended<Self>> {
        let root_info_idx = id0.root_node()?;
        let root_info = id0.ida_info(root_info_idx)?;
        let node_idx = root_info.netdelta();
        let node = node_idx.ea2node(Address::from_raw(ea));
        let value = id0
            .sup_value(node, K::Usize::from(0x25u8), ARRAY_ALT_TAG)
            .map(|entry| {
                entry
                    .try_into()
                    .map_err(|_| anyhow!("Invalid extended id1 value"))
                    .map(u32::from_le_bytes)
            })
            .transpose()?;
        Ok(ByteExtended {
            byte: self,
            extended: value.unwrap_or(0),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteExtended<B> {
    byte: B,
    extended: u32,
}

impl<B> core::ops::Deref for ByteExtended<B> {
    type Target = B;
    fn deref(&self) -> &Self::Target {
        &self.byte
    }
}

impl<B> ByteExtended<B> {
    fn op_tail(&self, n: u8) -> Result<Option<ByteOp>> {
        ByteOp::from_raw((self.extended >> (n * 4)) as u8 & MS_N_TYPE)
    }

    pub fn operand2(&self) -> Result<Option<ByteOp>> {
        self.op_tail(0)
    }

    pub fn operand3(&self) -> Result<Option<ByteOp>> {
        self.op_tail(1)
    }

    pub fn operand4(&self) -> Result<Option<ByteOp>> {
        self.op_tail(2)
    }

    pub fn operand5(&self) -> Result<Option<ByteOp>> {
        self.op_tail(3)
    }

    pub fn operand6(&self) -> Result<Option<ByteOp>> {
        self.op_tail(4)
    }

    pub fn operand7(&self) -> Result<Option<ByteOp>> {
        self.op_tail(5)
    }
}

impl ByteExtended<ByteCode> {
    pub fn operand_n(&self, n: u8) -> Result<Option<ByteOp>> {
        match n {
            0 => self.operand0(),
            1 => self.operand1(),
            2 => self.operand2(),
            3 => self.operand3(),
            4 => self.operand4(),
            5 => self.operand5(),
            6 => self.operand6(),
            7 => self.operand7(),
            _ => Err(anyhow!("Invalid operand number")),
        }
    }

    pub fn is_invsign(&self, n: u8) -> Result<bool> {
        if !self.op_invert_sig() {
            return Ok(false);
        }

        match n {
            0 => Ok(self.operand7()? == Some(ByteOp::Hex)),
            1..8 => Ok(self.operand7()? == Some(ByteOp::Dec)),
            0xf => {
                Ok(matches!(self.operand7()?, Some(ByteOp::Hex | ByteOp::Dec)))
            }
            #[cfg(feature = "restrictive")]
            8..0xf | 0x10.. => panic!(),
            #[cfg(not(feature = "restrictive"))]
            8..0xf | 0x10.. => Ok(true),
        }
    }

    pub fn is_bnot(&self, n: u8) -> Result<bool> {
        if !self.op_bitwise_negation() {
            return Ok(false);
        }
        match n {
            0 => Ok(self.operand4()? == Some(ByteOp::Hex)),
            1..8 => Ok(self.operand4()? == Some(ByteOp::Dec)),
            0xf => {
                Ok(matches!(self.operand4()?, Some(ByteOp::Hex | ByteOp::Dec)))
            }
            #[cfg(feature = "restrictive")]
            8..0xf | 0x10.. => panic!(),
            #[cfg(not(feature = "restrictive"))]
            8..0xf | 0x10.. => Ok(true),
        }
    }

    pub fn forced_operand<'a, K: IDAKind>(
        &self,
        id0: &'a ID0Section<K>,
        ea: K::Usize,
        n: u8,
    ) -> Result<Option<&'a [u8]>> {
        if self.operand_n(n)? != Some(ByteOp::ForceOp) {
            return Ok(None);
        }
        get_forced_operand(id0, ea, n)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteData(ByteInfo);
impl core::ops::Deref for ByteData {
    type Target = ByteInfo;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl ByteData {
    pub fn data_type(&self) -> ByteDataType {
        ByteDataType::from_raw(self.0 .0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteTail(ByteInfo);
impl core::ops::Deref for ByteTail {
    type Target = ByteInfo;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait ID1Byte {
    fn byte_info(&self) -> &ByteInfo;
}

impl ID1Byte for ByteData {
    fn byte_info(&self) -> &ByteInfo {
        self
    }
}

impl ID1Byte for ByteExtended<ByteCode> {
    fn byte_info(&self) -> &ByteInfo {
        self
    }
}

fn get_default_radix() -> u32 {
    // TODO
    16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteType {
    Code(ByteCode),
    Data(ByteData),
    Tail(ByteTail),
    Unknown,
}

impl ByteType {
    pub(crate) fn from_raw(value: ByteInfo) -> ByteType {
        use flag::flags::byte_type::*;
        match value.0 & MS_CLS {
            FF_DATA => ByteType::Data(ByteData(value)),
            FF_CODE => ByteType::Code(ByteCode(value)),
            FF_TAIL => ByteType::Tail(ByteTail(value)),
            FF_UNK => ByteType::Unknown,
            _ => unreachable!(),
        }
    }

    pub fn is_code(&self) -> bool {
        matches!(self, Self::Code(_))
    }
    pub fn is_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }
    pub fn is_tail(&self) -> bool {
        matches!(self, Self::Tail(_))
    }
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
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
pub enum ByteOp {
    /// 0x01 Hexadecimal number
    Hex,
    /// 0x02 Decimal number
    Dec,
    /// 0x03 Char
    Char,
    /// 0x04 Segment
    Seg,
    /// 0x05 Offset
    Offset,
    /// 0x06 Binary number
    Bin,
    /// 0x07 Octal number
    Oct,
    /// 0x08 Enumeration
    Enum,
    /// 0x09 Forced operand
    ForceOp,
    /// 0x0a Struct offset
    StructOffset,
    /// 0x0b Stack variable
    StackVariable,
    /// 0x0c Floating point number
    Float,
    /// 0x0d Custom representation
    Custom,
}

impl ByteOp {
    fn from_raw(value: u8) -> Result<Option<Self>> {
        use flag::flags::inst_info::*;
        Ok(Some(match value {
            FF_N_VOID => return Ok(None),
            FF_N_NUMH => Self::Hex,
            FF_N_NUMD => Self::Dec,
            FF_N_CHAR => Self::Char,
            FF_N_SEG => Self::Seg,
            FF_N_OFF => Self::Offset,
            FF_N_NUMB => Self::Bin,
            FF_N_NUMO => Self::Oct,
            FF_N_ENUM => Self::Enum,
            FF_N_FOP => Self::ForceOp,
            FF_N_STRO => Self::StructOffset,
            FF_N_STK => Self::StackVariable,
            FF_N_FLT => Self::Float,
            FF_N_CUST => Self::Custom,
            // TODO reserved values?
            #[cfg(not(feature = "restrictive"))]
            0xE | 0xF => Self::Custom,
            #[cfg(feature = "restrictive")]
            0xE | 0xF => return Err(anyhow!("Invalid ID1 operand value")),
            _ => unreachable!(),
        }))
    }

    pub fn get_radix(&self) -> u32 {
        match self {
            Self::Hex => 16,
            Self::Dec => 10,
            Self::Oct => 8,
            Self::Bin => 2,
            _ => get_default_radix(),
        }
    }
}

fn get_forced_operand<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: K::Usize,
    n: u8,
) -> Result<Option<&[u8]>> {
    let alt_value = <K::Usize as From<u8>>::from(match n {
        0 => 0x02,
        1 => 0x03,
        2 => 0x07,
        3 => 0x12,
        4 => 0x13,
        5 => 0x14,
        6 => 0x1f,
        7 => 0x20,
        #[cfg(not(feature = "restrictive"))]
        _ => return Ok(None),
        #[cfg(feature = "restrictive")]
        _ => unreachable!(),
    });
    let root_info_idx = id0.root_node()?;
    let root_info = id0.ida_info(root_info_idx)?;
    let base = root_info.netdelta();
    let node = base.ea2node(Address::from_raw(ea));

    let entries = id0.sup_value(node, alt_value, ARRAY_SUP_TAG);
    Ok(entries)
}

#[derive(Clone, Debug)]
enum SegInfoRaw<K: IDAKind> {
    VaN(Vec<SegInfoVaNRaw<K>>),
    VaX(Vec<Range<K::Usize>>),
    /// `VA*` kind 4 (IDA 9.5): every range carries its byte offset in the
    /// section. Ranges are not stored in address order, and the space between
    /// them can hold stale data from ranges IDA moved.
    VaXOffsets(Vec<SegInfoVaNRaw<K>>),
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

fn to_address_range<K: IDAKind>(range: Range<K::Usize>) -> Range<Address<K>> {
    Address::from_raw(range.start)..Address::from_raw(range.end)
}

/// Read ranges that are stored at their own offset in the section and return
/// them in address order. If `zero_gaps`, the bytes between ranges must be
/// zero.
fn read_by_offset<K: IDAKind>(
    mut input: impl IdbRead,
    mut segs: Vec<SegInfoVaNRaw<K>>,
    buf: &mut [u8],
    zero_gaps: bool,
) -> Result<Vec<SegInfo<K>>> {
    segs.sort_unstable_by_key(|s| s.offset);
    let mut current_offset = K::Usize::try_from(PAGE_SIZE).unwrap();
    let mut seglist = segs
        .into_iter()
        .map(|seg| {
            ensure!(seg.offset >= current_offset, "Invalid ID1 range offset");
            let gap = std::io::Read::take(
                &mut input,
                (seg.offset - current_offset).into(),
            );
            if zero_gaps {
                ensure_all_bytes_are_zero(gap, buf)?;
            } else {
                ignore_bytes(gap, buf)?;
            }
            let len = seg.address.end - seg.address.start;
            let data = read_data::<K>(&mut input, len)?;
            current_offset = seg.offset + len * K::Usize::from(4u8);
            Ok(SegInfo {
                offset: Address::from_raw(seg.address.start),
                data,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    seglist.sort_unstable_by_key(|s| s.offset);
    Ok(seglist)
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
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect())
}

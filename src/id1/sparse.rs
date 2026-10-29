//! Flags of address ranges that have no bytes in ID1.
//!
//! Since IDA 9.1 the sixth section of an inline IDB (`IDAS`) stores the flags
//! of ranges without file data (`.bss`, `extern`, alignment padding) as sparse
//! records instead of 4 bytes per address in ID1. Layout, all numbers in IDA's
//! packed encoding (`dd` = `unpack_dd`, `dq` = `unpack_dq`):
//!
//! ```text
//! "IDAS" u32(0x5555A51D) dd(version = 0)
//! dd(n) n * (dq(start delta), dq(size))   ranges stored here instead of ID1
//! dd(m) m * (dq(start delta), dq(size))   sub-ranges whose bytes have a value (0)
//! records: dq(address delta) dd(flags) dq(item size), until the address is BADADDR
//! ```
//!
//! Range starts are deltas from the end of the previous range; record
//! addresses are deltas from the previous record. A record sets the flags of
//! its address; the following `item size - 1` bytes are tails unless a later
//! record names them.

use std::ops::Range;

use anyhow::{anyhow, ensure, Result};

use super::flag::byte::FF_IVL;
use super::flag::flags::byte_type::FF_TAIL;
use crate::ida_reader::IdbRead;
use crate::IDAKind;

const MAGIC: &[u8; 8] = b"IDAS\x1d\xa5\x55\x55";

#[derive(Clone, Debug, Default)]
pub struct SparseFlags<K: IDAKind> {
    ranges: Vec<Range<K::Usize>>,
    valued: Vec<Range<K::Usize>>,
    records: Vec<Record<K>>,
}

#[derive(Clone, Copy, Debug)]
struct Record<K: IDAKind> {
    address: K::Usize,
    flags: u32,
    /// End of the item that covers the bytes after this record: its own if
    /// it has a size, otherwise the one of the nearest sized record before it.
    item_end: K::Usize,
}

impl<K: IDAKind> SparseFlags<K> {
    pub(crate) fn read(mut input: &[u8]) -> Result<Self> {
        ensure!(
            input.len() >= 8 && &input[..8] == MAGIC,
            "Invalid IDAS magic"
        );
        input = &input[8..];
        let version = input.unpack_dd()?;
        ensure!(version == 0, "Unknown IDAS version {version}");
        let ranges = read_ranges::<K>(&mut input)?;
        let valued = read_ranges::<K>(&mut input)?;
        let mut raw = Vec::new();
        let mut address = 0u64;
        loop {
            address = address.wrapping_add(input.unpack_dq()?);
            if address == u64::MAX {
                break;
            }
            let flags = input.unpack_dd()?;
            let size = input.unpack_dq()?;
            raw.push((address, flags, size));
        }
        ensure!(
            input.is_empty(),
            "IDAS has {} bytes after the records",
            input.len()
        );
        raw.sort_unstable_by_key(|r| r.0);
        let mut item_end = 0;
        let records = raw
            .into_iter()
            .map(|(address, flags, size)| {
                if size > 0 {
                    item_end = address.saturating_add(size);
                }
                Ok(Record {
                    address: to_usize::<K>(address)?,
                    flags,
                    item_end: to_usize::<K>(item_end)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            ranges,
            valued,
            records,
        })
    }

    /// Ranges whose flags are stored here instead of in ID1, in address
    /// order.
    pub fn ranges(&self) -> &[Range<K::Usize>] {
        &self.ranges
    }

    /// Raw flags of `address`, or `None` outside [`Self::ranges`].
    pub fn flags(&self, address: K::Usize) -> Option<u32> {
        contains(&self.ranges, address).then(|| self.flags_unchecked(address))
    }

    /// Raw flags of every address in `range`, which must be inside
    /// [`Self::ranges`].
    pub(crate) fn range_flags(
        &self,
        range: Range<K::Usize>,
    ) -> impl DoubleEndedIterator<Item = (K::Usize, u32)> + use<'_, K> {
        let len: u64 = (range.end - range.start).into();
        (0..len).map(move |i| {
            let address = range.start + K::Usize::try_from(i).unwrap();
            (address, self.flags_unchecked(address))
        })
    }

    fn flags_unchecked(&self, address: K::Usize) -> u32 {
        let idx = self.records.partition_point(|r| r.address <= address);
        let flags = match idx.checked_sub(1).map(|i| self.records[i]) {
            Some(record) if record.address == address => record.flags,
            Some(record) if address < record.item_end => FF_TAIL,
            _ => 0,
        };
        if contains(&self.valued, address) {
            flags | FF_IVL
        } else {
            flags
        }
    }
}

/// `ranges` must be sorted and not overlap.
fn contains<T: Ord + Copy>(ranges: &[Range<T>], value: T) -> bool {
    let idx = ranges.partition_point(|r| r.end <= value);
    ranges.get(idx).is_some_and(|r| r.start <= value)
}

fn to_usize<K: IDAKind>(value: u64) -> Result<K::Usize> {
    K::Usize::try_from(value)
        .map_err(|_| anyhow!("IDAS value {value:#x} out of range"))
}

fn read_ranges<K: IDAKind>(input: &mut &[u8]) -> Result<Vec<Range<K::Usize>>> {
    let count = input.unpack_dd()?;
    let mut end = 0u64;
    (0..count)
        .map(|_| {
            let start = end
                .checked_add(input.unpack_dq()?)
                .ok_or_else(|| anyhow!("IDAS range start overflows"))?;
            end = start
                .checked_add(input.unpack_dq()?)
                .ok_or_else(|| anyhow!("IDAS range end overflows"))?;
            Ok(to_usize::<K>(start)?..to_usize::<K>(end)?)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::SparseFlags;
    use crate::IDA64;

    #[test]
    fn range_overflow_is_an_error() {
        let mut data = b"IDAS\x1d\xa5\x55\x55".to_vec();
        // version 0, one range: start delta u64::MAX, size 1
        data.extend([0x00, 0x01]);
        data.extend([0xFF; 10]);
        data.extend([0x01, 0x00]);
        assert!(SparseFlags::<IDA64>::read(&data).is_err());
    }
}

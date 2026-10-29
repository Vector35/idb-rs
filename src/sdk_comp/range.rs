use std::ops::Range;

use num_traits::{CheckedAdd, CheckedSub};

use crate::id1::ID1Section;
use crate::id2::{ID2Entry, ID2Section};
use crate::IDAKind;

use super::pro::ea_t;

pub enum range_kind_t {
    RANGE_KIND_UNKNOWN,
    RANGE_KIND_FUNC,
    RANGE_KIND_SEGMENT,
    RANGE_KIND_HIDDEN_RANGE,
}

// The functions below operate on the contiguous ranges with flags, stored in
// ID1 and, since IDA 9.1, in IDAS.

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874c10
pub fn rangeset_t_find_range<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<Range<ea_t<K>>> {
    id1.range_by_address(address)
}
pub fn rangeset_t_find_range_id2<K: IDAKind>(
    id2: &ID2Section<K>,
    address: ea_t<K>,
) -> Option<&ID2Entry<K>> {
    id2.entry_by_address(address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874da0
pub fn rangeset_t_next_range<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    id1.next_range(address).map(|range| range.start)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874e20
pub fn rangeset_t_prev_range<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    id1.prev_range(address).map(|range| range.start)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874d00
pub fn rangeset_t_prev_addr<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    let address = address.into_raw();
    let prev = address.checked_sub(&1u8.into())?;
    // the address before, or the last address of the previous range
    let (range, _) = id1.ranges_around(|r| r.start <= prev);
    range.map(|r| ea_t::from_raw(r.end.min(address) - 1u8.into()))
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874da0
pub fn rangeset_t_next_addr<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    let next = address.into_raw().checked_add(&1u8.into())?;
    // the address after, or the first address of the next range
    let (_, range) = id1.ranges_around(|r| r.end <= next);
    range.map(|r| ea_t::from_raw(r.start.max(next)))
}

pub fn next_range<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    rangeset_t_next_range(id1, address)
}

pub fn prev_range<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    rangeset_t_prev_range(id1, address)
}

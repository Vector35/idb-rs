use num_traits::CheckedSub;

use crate::id1::{ID1Section, SegInfo};
use crate::IDAKind;

use super::pro::ea_t;

pub enum range_kind_t {
    RANGE_KIND_UNKNOWN,
    RANGE_KIND_FUNC,
    RANGE_KIND_SEGMENT,
    RANGE_KIND_HIDDEN_RANGE,
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874c10
pub fn rangeset_t_find_range<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<&SegInfo<K>> {
    id1.segment_by_address(address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874da0
pub fn rangeset_t_next_range<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    match id1.segment_idx_by_address(address) {
        // the address is inside this segment, get the next one
        Ok(segment_idx) => id1
            .seglist
            .get(segment_idx + 1)
            .map(|seg| ea_t::try_from(seg.offset).unwrap()),
        // no segment own this address, the next_segment is right one
        Err(next_segment_idx) => id1
            .seglist
            .get(next_segment_idx)
            .map(|seg| ea_t::try_from(seg.offset).unwrap()),
    }
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874e20
pub fn rangeset_t_prev_range<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    match id1.segment_idx_by_address(address) {
        // the address is inside this segment
        Ok(segment_idx) => id1
            .seglist
            .get(segment_idx + 1)
            .map(|seg| ea_t::try_from(seg.offset).unwrap()),
        // no segment own this address, the next_segment is right one
        Err(next_segment_idx) => id1
            .seglist
            .get(next_segment_idx)
            .map(|seg| ea_t::try_from(seg.offset).unwrap()),
    }
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874d00
pub fn rangeset_t_prev_addr<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    use std::cmp::Ordering::*;
    // get the segment that contains the address and what part of the segment
    let seg_cmp = id1
        .segment_idx_by_address(address)
        .map(|seg_idx| (address.cmp(&id1.seglist[seg_idx].offset), seg_idx));
    match seg_cmp {
        // can't be before the segment start, if so it would be Err
        Ok((Less, _)) => unreachable!(),
        // if in the middle of the segment, so just "addr - 1"
        Ok((Greater, _)) => address
            .into_raw()
            .checked_sub(&1u8.into())
            .map(ea_t::from_raw),
        // first addr of this segment or no segment own this address,
        // the last adddress of the prev segment is the prev address
        Ok((Equal, seg_idx)) | Err(seg_idx) => seg_idx
            .checked_sub(1u8.into())
            .and_then(|idx| id1.seglist.get(idx))
            .map(|seg| {
                let segment_len: K::Usize = seg.len().try_into().unwrap();
                ea_t::from_raw(
                    (seg.offset.into_raw() + segment_len) - 1u8.into(),
                )
            }),
    }
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874da0
pub fn rangeset_t_next_addr<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    use std::cmp::Ordering::*;
    match id1.segment_idx_by_address(address) {
        // the address is inside this segment
        Ok(segment_idx) => {
            let segment = &id1.seglist[segment_idx];
            let segment_len: K::Usize = segment.len().try_into().unwrap();
            let segment_last_addr =
                (segment.offset.into_raw() + segment_len) - 1u8.into();
            match address.into_raw().cmp(&segment_last_addr) {
                // is not the last address, so just next addr + 1
                Less => Some(address + ea_t::from_raw(1u8.into())),
                // last address of this segment, the next segment have the addr
                Equal => id1
                    .seglist
                    .get(segment_idx + 1)
                    .map(|seg| ea_t::try_from(seg.offset).unwrap()),
                Greater => unreachable!(),
            }
        }
        // no segment own this address, the next segment is the next address
        Err(next_segment_idx) => id1
            .seglist
            .get(next_segment_idx)
            .map(|seg| ea_t::try_from(seg.offset).unwrap()),
    }
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

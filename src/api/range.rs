use crate::id1::{ID1Section, SegInfo};
use crate::IDAKind;

use super::pro::ea_t;

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874c10
pub(crate) fn rangeset_t_find_range<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<&SegInfo> {
    id1.segment_by_address(address.as_u64())
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874da0
pub(crate) fn rangeset_t_next_range<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    let address = address.as_u64();
    match id1.segment_idx_by_address(address) {
        // the address is inside this segment, get the next one
        Ok(segment_idx) => id1
            .seglist
            .get(segment_idx + 1)
            .map(|seg| ea_t::try_from_u64(seg.offset).unwrap()),
        // no segment own this address, the next_segment is right one
        Err(next_segment_idx) => id1
            .seglist
            .get(next_segment_idx)
            .map(|seg| ea_t::try_from_u64(seg.offset).unwrap()),
    }
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874e20
pub(crate) fn rangeset_t_prev_range<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    let address = address.as_u64();
    match id1.segment_idx_by_address(address) {
        // the address is inside this segment
        Ok(segment_idx) => id1
            .seglist
            .get(segment_idx + 1)
            .map(|seg| ea_t::try_from_u64(seg.offset).unwrap()),
        // no segment own this address, the next_segment is right one
        Err(next_segment_idx) => id1
            .seglist
            .get(next_segment_idx)
            .map(|seg| ea_t::try_from_u64(seg.offset).unwrap()),
    }
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874d00
pub(crate) fn rangeset_t_prev_addr<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    use std::cmp::Ordering::*;
    let address = address.as_u64();
    match id1.segment_idx_by_address(address) {
        Ok(segment_idx) => {
            let segment = &id1.seglist[segment_idx];
            match address.cmp(&segment.offset) {
                // is not the first address, so just next addr - 1
                Greater => ea_t::try_from_u64(address - 1).ok(),
                // first addr of this segment, the prev segment have the addr
                Equal => segment_idx
                    .checked_sub(1)
                    .and_then(|idx| id1.seglist.get(idx))
                    .map(|seg| {
                        let segment_len = u64::try_from(seg.len()).unwrap();
                        ea_t::try_from_u64((seg.offset + segment_len) - 1)
                            .unwrap()
                    }),
                Less => unreachable!(),
            }
        }
        // no segment own this address, the prev segment is the next address
        Err(next_segment_idx) => {
            let segment = next_segment_idx
                .checked_sub(1)
                .and_then(|idx| id1.seglist.get(idx))?;
            let segment_len = u64::try_from(segment.len()).unwrap();
            Some(
                ea_t::try_from_u64((segment.offset + segment_len) - 1).unwrap(),
            )
        }
    }
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x874da0
pub(crate) fn rangeset_t_next_addr<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    use std::cmp::Ordering::*;
    let address = address.as_u64();
    match id1.segment_idx_by_address(address) {
        // the address is inside this segment
        Ok(segment_idx) => {
            let segment = &id1.seglist[segment_idx];
            let segment_len = u64::try_from(segment.len()).unwrap();
            let segment_last_addr = (segment.offset + segment_len) - 1;
            match address.cmp(&segment_last_addr) {
                // is not the last address, so just next addr + 1
                Less => ea_t::try_from_u64(address + 1).ok(),
                // last address of this segment, the next segment have the addr
                Equal => id1
                    .seglist
                    .get(segment_idx + 1)
                    .map(|seg| ea_t::try_from_u64(seg.offset).unwrap()),
                Greater => unreachable!(),
            }
        }
        // no segment own this address, the next segment is the next address
        Err(next_segment_idx) => id1
            .seglist
            .get(next_segment_idx)
            .map(|seg| ea_t::try_from_u64(seg.offset).unwrap()),
    }
}

pub fn next_range<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    rangeset_t_next_range(id1, address)
}

pub fn prev_range<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    rangeset_t_prev_range(id1, address)
}

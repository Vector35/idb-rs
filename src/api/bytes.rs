use crate::id1::ID1Section;
use crate::IDAKind;

use super::pro::{asize_t, ea_t};

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4de950
pub fn next_addr<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::api::range::rangeset_t_next_addr(id1, address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4dea10
pub fn prev_addr<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::api::range::rangeset_t_prev_addr(id1, address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4deb80
pub fn next_chunk<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::api::range::rangeset_t_next_range(id1, address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4dec10
pub fn prev_chunk<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::api::range::rangeset_t_prev_range(id1, address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4decf0
pub fn chunk_start<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::api::range::rangeset_t_find_range(id1, address)
        .map(|seg| ea_t::try_from_u64(seg.offset).unwrap())
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4dede0
pub fn chunk_size<K: IDAKind>(
    id1: &ID1Section,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::api::range::rangeset_t_find_range(id1, address)
        .map(|seg| ea_t::try_from_u64(seg.len().try_into().unwrap()).unwrap())
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x665b50
pub fn find_free_chunk<K: IDAKind>(
    id1: &ID1Section,
    start: ea_t<K>,
    size: asize_t<K>,
    alignment: asize_t<K>,
) -> Option<ea_t<K>> {
    let start = start.as_u64();
    let size = size.as_u64();
    let alignment = alignment.as_u64();
    if alignment & (alignment + 1) != 0 {
        return None;
    }
    fn fit_between(
        mut start: u64,
        end: u64,
        size: u64,
        alignment: u64,
    ) -> Option<u64> {
        if start & alignment != 0 {
            start = (start & !alignment) + (alignment + 1);
        }
        end.checked_sub(start)
            .filter(|block_size| *block_size >= size)
    }
    let start_idx = match id1.segment_idx_by_address(start) {
        Ok(idx) => idx,
        Err(next_idx) => {
            let segment = &id1.seglist[next_idx];
            if let Some(ea) =
                fit_between(start, segment.offset, size, alignment)
            {
                // space between start and first block have this size
                return Some(ea_t::try_from_u64(ea).unwrap());
            }
            next_idx
        }
    };
    for segs in id1.seglist[start_idx..].windows(2) {
        let [seg1, seg2] = segs else {
            unreachable!();
        };
        if let Some(ea) = fit_between(
            seg1.offset + u64::try_from(seg1.len()).unwrap(),
            seg2.offset,
            size,
            alignment,
        ) {
            return Some(ea_t::try_from_u64(ea).unwrap());
        }
    }
    None
}

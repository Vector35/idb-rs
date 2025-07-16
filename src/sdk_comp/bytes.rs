use num_traits::CheckedSub;

use crate::addr_info::AddressInfo;
use crate::id0::ID0Section;
use crate::id1::{ByteInfo, ID1Section};
use crate::id2::ID2Section;
use crate::{Address, IDAKind, IDBStr};

use std::ops::Range;

use super::pro::{asize_t, bgcolor_t, ea_t};

#[derive(Clone, Debug)]
pub struct hidden_range_t<'a, K: IDAKind> {
    pub range: Range<K::Usize>,
    pub description: &'a [u8],
    pub header: &'a [u8],
    pub footer: &'a [u8],
    pub visible: bool,
    pub color: bgcolor_t,
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4de950
pub fn next_addr<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::sdk_comp::range::rangeset_t_next_addr(id1, address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4dea10
pub fn prev_addr<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::sdk_comp::range::rangeset_t_prev_addr(id1, address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4deb80
pub fn next_chunk<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::sdk_comp::range::rangeset_t_next_range(id1, address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4dec10
pub fn prev_chunk<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::sdk_comp::range::rangeset_t_prev_range(id1, address)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4decf0
pub fn chunk_start<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::sdk_comp::range::rangeset_t_find_range(id1, address)
        .map(|seg| seg.offset)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4dede0
pub fn chunk_size<K: IDAKind>(
    id1: &ID1Section<K>,
    address: ea_t<K>,
) -> Option<ea_t<K>> {
    crate::sdk_comp::range::rangeset_t_find_range(id1, address)
        .map(|seg| ea_t::from_raw(seg.len().try_into().unwrap()))
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4e2230
pub fn prev_not_tail<K: IDAKind>(
    id1: &ID1Section<K>,
    ea: ea_t<K>,
) -> Option<ea_t<K>> {
    id1.prev_not_tail(ea).map(|(addr, _byte_info)| addr)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x665b50
pub fn find_free_chunk<K: IDAKind>(
    id1: &ID1Section<K>,
    start: ea_t<K>,
    size: asize_t<K>,
    alignment: asize_t<K>,
) -> Option<ea_t<K>> {
    if alignment & (alignment + 1u8.into()) != 0u8.into() {
        return None;
    }
    fn fit_between<K: IDAKind>(
        mut start: K::Usize,
        end: K::Usize,
        size: K::Usize,
        alignment: K::Usize,
    ) -> Option<K::Usize> {
        if start & alignment != 0u8.into() {
            start = (start & !alignment) + (alignment + 1u8.into());
        }
        end.checked_sub(&start)
            .filter(|block_size| *block_size >= size)
    }
    let start_idx = match id1.segment_idx_by_address(start) {
        Ok(idx) => idx,
        Err(next_idx) => {
            let segment = &id1.seglist[next_idx];
            if let Some(ea) = fit_between::<K>(
                start.into_raw(),
                segment.offset.into_raw(),
                size,
                alignment,
            ) {
                // space between start and first block have this size
                return Some(ea_t::from_raw(ea));
            }
            next_idx
        }
    };
    for segs in id1.seglist[start_idx..].windows(2) {
        let [seg1, seg2] = segs else {
            unreachable!();
        };
        if let Some(ea) = fit_between::<K>(
            seg1.offset.into_raw() + K::Usize::try_from(seg1.len()).unwrap(),
            seg2.offset.into_raw(),
            size,
            alignment,
        ) {
            return Some(ea_t::from_raw(ea));
        }
    }
    None
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4e0f10
pub fn get_flags_ex<K: IDAKind>(
    id1: &ID1Section<K>,
    ea: ea_t<K>,
    _how: u32,
) -> Option<ByteInfo> {
    id1.byte_by_address(ea)
}

pub fn get_flags<K: IDAKind>(
    id1: &ID1Section<K>,
    ea: ea_t<K>,
) -> Option<ByteInfo> {
    get_flags_ex(id1, ea, 0)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4e2b60
pub fn get_cmt<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    id1: &ID1Section<K>,
    id2: Option<&ID2Section<K>>,
    ea: ea_t<K>,
    repeatable: bool,
) -> Option<IDBStr<'a>> {
    let root_info_idx = id0.root_node().ok()?;
    let root_info = id0.ida_info(root_info_idx).ok()?;
    let image_base = root_info.netdelta();
    let addresss = Address::from_raw(ea.0);
    let addr_info = AddressInfo::new(id0, id1, id2, image_base, addresss)?;
    if repeatable {
        addr_info.comment_repeatable()
    } else {
        addr_info.comment()
    }
}

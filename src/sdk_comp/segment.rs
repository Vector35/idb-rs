use anyhow::Result;

use std::ops::Range;

use crate::id0::{ID0Section, Segment};
use crate::IDAKind;

use super::pro::{bgcolor_t, ea_t, sel_t, uval_t};

#[derive(Debug, Clone)]
pub struct segment_t<K: IDAKind> {
    pub range: Range<K::Usize>,
    pub name: uval_t<K>,
    pub sclass: uval_t<K>,
    pub orgbase: uval_t<K>,
    pub align: u8,
    pub comb: u8,
    pub perm: u8,
    pub bitness: u8,
    pub flags: u16,
    pub sel: sel_t<K>,
    pub defsr: [sel_t<K>; 16usize],
    pub type_: u8,
    pub color: bgcolor_t,
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x5de220
pub(crate) fn getseg_inner<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<Segment<K>>> {
    let Some(seg_idx) = id0.segments_idx()? else {
        return Ok(None);
    };
    for seg in id0.segments(seg_idx) {
        let seg = seg?;
        if seg.address.contains(&ea.as_raw()) {
            return Ok(Some(seg));
        }
    }
    Ok(None)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x5e2b80
pub fn getseg<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<segment_t<K>>> {
    getseg_inner(id0, ea).map(|seg| {
        seg.map(|seg| segment_t {
            range: seg.address,
            name: uval_t::from_raw(seg.name.0),
            sclass: uval_t::from_raw(seg.class_id.0),
            orgbase: uval_t::from_raw(seg.orgbase),
            align: seg.align.into(),
            comb: seg.comb.into(),
            perm: seg.perm.map(|perm| perm.into_raw()).unwrap_or(0),
            bitness: seg.bitness.into(),
            flags: seg.flags.into_raw().into(),
            sel: sel_t::from_raw(seg.selector),
            defsr: seg.defsr.map(|def| sel_t::from_raw(def)),
            type_: seg.seg_type.into(),
            color: seg.color,
        })
    })
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x5e41e0
pub fn segtype<K: IDAKind>(id0: &ID0Section<K>, ea: ea_t<K>) -> Result<u8> {
    getseg_inner(id0, ea)
        .map(|seg| seg.map(|seg| seg.seg_type.into()).unwrap_or(8))
}

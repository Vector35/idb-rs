use anyhow::Result;

use std::ops::Range;

use crate::id0::{
    ID0Section, Segment, SegmentBitness, SegmentNameIdx, SegmentType,
};
use crate::IDAKind;

use super::pro::{bgcolor_t, ea_t, sel_t, uval_t};

#[derive(Debug, Clone)]
pub struct segment_t<K: IDAKind> {
    pub address: Range<ea_t<K>>,
    pub name: SegmentNameIdx<K>,
    pub sclass: SegmentNameIdx<K>,
    pub orgbase: uval_t<K>,
    pub align: u8,
    pub comb: u8,
    pub perm: u8,
    pub bitness: SegmentBitness,
    pub flags: u16,
    pub sel: sel_t<K>,
    pub defsr: [sel_t<K>; 16usize],
    pub type_: SegmentType,
    pub color: bgcolor_t,
}

impl<K: IDAKind> From<Segment<K>> for segment_t<K> {
    fn from(seg: Segment<K>) -> Self {
        Self {
            address: seg.address,
            name: seg.name,
            sclass: seg.class_id,
            orgbase: seg.orgbase,
            align: seg.align.into(),
            comb: seg.comb.into(),
            perm: seg.perm.map(|perm| perm.into_raw()).unwrap_or(0),
            bitness: seg.bitness.into(),
            flags: seg.flags.into_raw().into(),
            sel: seg.selector,
            defsr: seg.defsr,
            type_: seg.seg_type.into(),
            color: seg.color,
        }
    }
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x5de220
pub(crate) fn getseg_inner<K: IDAKind>(
    id0: &ID0Section<K>,
    mut selector: impl FnMut(&Segment<K>) -> bool,
) -> Result<Option<Segment<K>>> {
    let Some(seg_idx) = id0.segments_idx()? else {
        return Ok(None);
    };
    for seg in id0.segments(seg_idx) {
        let seg = seg?;
        if selector(&seg) {
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
    getseg_inner(id0, |seg| seg.address.contains(&ea))
        .map(|seg| seg.map(|seg| seg.into()))
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x5e41e0
pub fn segtype<K: IDAKind>(id0: &ID0Section<K>, ea: ea_t<K>) -> Result<u8> {
    getseg_inner(id0, |seg| seg.address.contains(&ea))
        .map(|seg| seg.map(|seg| seg.seg_type.into()).unwrap_or(8))
}

pub fn get_segm_qty<K: IDAKind>(id0: &ID0Section<K>) -> Result<usize> {
    let Some(seg_idx) = id0.segments_idx()? else {
        return Ok(0);
    };
    Ok(id0.segments(seg_idx).count())
}

pub fn get_next_seg<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<segment_t<K>>> {
    getseg_inner(id0, |seg| seg.address.start > ea)
        .map(|seg| seg.map(|seg| seg.into()))
}

pub fn get_prev_seg<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<segment_t<K>>> {
    getseg_inner(id0, |seg| seg.address.end < ea)
        .map(|seg| seg.map(|seg| seg.into()))
}

pub fn get_first_seg<K: IDAKind>(
    id0: &ID0Section<K>,
) -> Result<Option<segment_t<K>>> {
    getseg_inner(id0, |_seg| true).map(|seg| seg.map(|seg| seg.into()))
}

pub fn get_last_seg<K: IDAKind>(
    id0: &ID0Section<K>,
) -> Result<Option<segment_t<K>>> {
    let Some(seg_idx) = id0.segments_idx()? else {
        return Ok(None);
    };
    id0.segments(seg_idx)
        .last()
        .map(|seg| seg.map(|seg| seg.into()))
        .transpose()
}

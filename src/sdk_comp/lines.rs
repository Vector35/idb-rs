use std::ops::Range;

use crate::{id0::ID0Section, IDAKind};

use super::pro::ea_t;

use anyhow::Result;

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4e4c60
pub fn get_sourcefile<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<(&[u8], Range<K::Usize>)>> {
    let seg = super::segment::getseg_inner(id0, ea)?;
    if let Some(seg) = seg {
        let name = seg
            .name
            .map(|name| id0.segment_name(name))
            .transpose()?
            .unwrap_or(&[]);
        Ok(Some((name, seg.address)))
    } else {
        Ok(None)
    }
}

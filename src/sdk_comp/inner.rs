use anyhow::Result;

use crate::id0::ID0Section;
use crate::sdk_comp::segment::segment_t;
use crate::{IDAKind, IDBStr, IDBString};

// TODO implement based on the InnerRef
pub fn get_segm_name<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    s: &segment_t<K>,
    flags: i32,
) -> Result<IDBString> {
    if flags != 0 {
        todo!();
    }
    if let Some(name) = id0.segment_name(s.name)? {
        return Ok(name.to_idb_string());
    }

    Ok(IDBString::new(format!("seg{:03}", s.name.0).into_bytes()))
}

// TODO implement based on the InnerRef
pub fn get_segm_class<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    s: &segment_t<K>,
) -> Result<Option<IDBStr<'a>>> {
    if let Some(class_name) = id0.segment_name(s.sclass)? {
        return Ok(Some(class_name));
    }

    id0.segment_name(s.name)
}

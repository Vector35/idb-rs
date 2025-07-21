use anyhow::Result;

use crate::id0::ID0Section;
use crate::sdk_comp::segment::segment_t;
use crate::{IDAKind, IDBStr};

// TODO implement based on the InnerRef
pub fn get_segm_name<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    s: &segment_t<K>,
    flags: i32,
) -> Result<Option<IDBStr<'a>>> {
    if flags != 0 {
        todo!();
    }
    id0.segment_name(s.name)
}

// TODO implement based on the InnerRef
pub fn get_segm_class<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    s: &segment_t<K>,
) -> Result<Option<IDBStr<'a>>> {
    id0.segment_name(s.sclass)
}

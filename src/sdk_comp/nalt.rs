use crate::id0::ID0Section;
use crate::IDAKind;

use super::pro::{ea_t, nodeidx_t};

pub type type_t = u8;

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4df3e0
pub fn ea2node<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Option<nodeidx_t<K>> {
    let root_info_idx = id0.root_node().ok()?;
    let root_info = id0.ida_info(root_info_idx).ok()?;
    let base = root_info.netdelta();
    Some(base.ea2node(ea))
}

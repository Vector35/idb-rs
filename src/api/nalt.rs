use crate::id0::ID0Section;
use crate::IDAKind;

use super::pro::{ea_t, nodeidx_t};

pub type type_t = u8;

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4df3e0
pub fn ea2node<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Option<nodeidx_t<K>> {
    let root_info = id0.root_node().ok()?;
    let base = id0.image_base(root_info).ok()?;
    Some(nodeidx_t::from_raw(ea.as_raw() + base.0))
}

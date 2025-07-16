use crate::id0::NetnodeIdx;
use crate::{Address, IDAKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ida_isize_t<K: IDAKind>(K::Isize);
impl<K: IDAKind> ida_isize_t<K> {
    #[allow(dead_code)]
    pub(crate) fn from_raw(value: K::Isize) -> Self {
        Self(value)
    }

    #[allow(dead_code)]
    pub(crate) fn as_raw(&self) -> K::Isize {
        self.0
    }
}

pub type ea_t<K> = Address<K>;
#[allow(type_alias_bounds)]
pub type asize_t<K: IDAKind> = K::Usize;
pub type nodeidx_t<K> = NetnodeIdx<K>;
#[allow(type_alias_bounds)]
pub type sel_t<K: IDAKind> = K::Usize;
#[allow(type_alias_bounds)]
pub type adiff_t<K: IDAKind> = K::Isize;
pub type uval_t<K> = asize_t<K>;
pub type sval_t<K> = adiff_t<K>;
pub type tid_t<K> = nodeidx_t<K>;

pub type bgcolor_t = u32;
pub const DEFCOLOR: bgcolor_t = u32::MAX;

use crate::IDAKind;

/// Address is represented as u32/u64 on 32/64bits
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ida_usize_t<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> ida_usize_t<K> {
    pub(crate) fn from_raw(value: K::Usize) -> Self {
        Self(value)
    }

    pub(crate) fn as_raw(&self) -> K::Usize {
        self.0
    }

    pub(crate) fn try_from_u64(
        value: u64,
    ) -> Result<Self, <K::Usize as TryFrom<u64>>::Error> {
        value.try_into().map(Self)
    }

    pub fn as_u64(self) -> u64 {
        self.0.into()
    }
}

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

pub type ea_t<K> = ida_usize_t<K>;
pub type asize_t<K> = ida_usize_t<K>;
pub type nodeidx_t<K> = ida_usize_t<K>;
pub type sel_t<K> = ida_usize_t<K>;
pub type adiff_t<K> = ida_isize_t<K>;
pub type uval_t<K> = asize_t<K>;
pub type sval_t<K> = adiff_t<K>;

pub type bgcolor_t = u32;
pub const DEFCOLOR: bgcolor_t = u32::MAX;

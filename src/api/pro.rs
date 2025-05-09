use crate::IDAKind;

/// Address is represented as u32/u64 on 32/64bits
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ida_usize_t<K: IDAKind>(K::Usize);
impl<K: IDAKind> ida_usize_t<K> {
    pub(crate) fn try_from_u64(
        value: u64,
    ) -> Result<Self, <K::Usize as TryFrom<u64>>::Error> {
        value.try_into().map(Self)
    }

    pub fn as_u64(self) -> u64 {
        self.0.into()
    }
}

#[allow(non_camel_case_types)]
pub type ea_t<K> = ida_usize_t<K>;
#[allow(non_camel_case_types)]
pub type asize_t<K> = ida_usize_t<K>;

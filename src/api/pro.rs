use crate::IDAKind;

/// Address is represented as u32/u64 on 32/64bits
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ea_t<K: IDAKind>(K::Usize);
impl<K: IDAKind> ea_t<K> {
    pub(crate) fn from_u32(value: u32) -> Self {
        Self(value.into())
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

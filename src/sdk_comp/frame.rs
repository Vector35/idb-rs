use std::ops::Range;

use crate::IDAKind;

use super::pro::{ea_t, sval_t};

#[derive(Debug, Clone, Copy)]
pub struct stkpnt_t<K: IDAKind> {
    pub ea: ea_t<K>,
    // cumulative difference from [BP-frsize]
    pub spd: sval_t<K>,
}

#[derive(Debug, Clone)]
pub struct regvar_t<'a, K: IDAKind> {
    pub _base: Range<K::Usize>,
    pub canon: &'a [u8],
    pub user: &'a [u8],
    pub cmt: &'a [u8],
}

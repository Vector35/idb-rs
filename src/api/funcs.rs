use std::ops::Range;

use crate::{id0::ID0Section, IDAKind};

use super::{
    frame::{regvar_t, stkpnt_t},
    nalt::type_t,
    pro::{asize_t, bgcolor_t, ea_t, uval_t},
};

#[derive(Clone, Debug)]
pub struct func_t<'a, K: IDAKind> {
    pub _base: Range<K::Usize>,
    pub flags: u64,
    pub func_t_type: func_t_type<'a, K>,
}
#[derive(Clone, Debug)]
pub enum func_t_type<'a, K: IDAKind> {
    T1(func_t_1<'a, K>),
    T2(func_t_2<K>),
}

#[derive(Clone, Debug)]
pub struct func_t_1<'a, K: IDAKind> {
    pub frame: uval_t<K>,
    pub frsize: asize_t<K>,
    pub frregs: u16,
    pub argsize: asize_t<K>,
    pub fpd: asize_t<K>,
    pub color: bgcolor_t,
    pub points: Vec<stkpnt_t<K>>,
    pub regvars: Vec<regvar_t<'a, K>>,
    // TODO: llabels: Vec<llabel_t>,
    pub regargs: Vec<regarg_t<'a>>,
    pub tails: Vec<Range<K::Usize>>,
}

#[derive(Debug, Clone)]
pub struct func_t_2<K: IDAKind> {
    pub owner: ea_t<K>,
    pub referers: Vec<ea_t<K>>,
}

#[derive(Clone, Debug)]
pub struct regarg_t<'a> {
    pub reg: usize,
    pub type_: type_t,
    pub name: &'a [u8],
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x68e860
pub fn get_fchunk<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    ea: ea_t<K>,
) -> func_t<'a, K> {
    todo!();
}

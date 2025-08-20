use std::ops::Range;

use crate::id0::function::{IDBFunction, IDBFunctionTail, IDBFunctionType};
use crate::id0::Netdelta;
use crate::{id0::ID0Section, IDAKind};
use crate::{Address, IDBString};

use super::frame::{regvar_t, stkpnt_t};
use super::nalt::type_t;
use super::pro::{asize_t, bgcolor_t, ea_t, uval_t};
use super::DataFetch;

use anyhow::{anyhow, Result};

pub type func_t<K> = IDBFunction<K>;
pub type func_t_type<K> = IDBFunctionType<K>;

#[allow(dead_code)]
pub struct llabel_t(*mut ());

pub struct func_t_1<'a, K: IDAKind> {
    pub frame: uval_t<K>,
    pub frsize: asize_t<K>,
    pub frregs: u16,
    pub argsize: asize_t<K>,
    pub fpd: asize_t<K>,
    pub color: bgcolor_t,
    pub points: DataFetch<stkpnt_t<K>>,
    pub regvars: DataFetch<regvar_t<'a, K>>,
    pub llabels: DataFetch<llabel_t>,
    pub regargs: DataFetch<regarg_t<'a>>,
    pub tails: DataFetch<Range<K::Usize>>,
}

#[derive(Debug, Clone)]
pub struct func_t_2<K: IDAKind> {
    pub owner: ea_t<K>,
    pub referers: ea_t<K>,
}

#[derive(Clone, Debug)]
pub struct regarg_t<'a> {
    pub reg: usize,
    pub type_: type_t,
    pub name: &'a [u8],
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x68e860
pub fn get_fchunk<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<func_t<K>>> {
    let Some(idx) = id0.funcs_idx()? else {
        return Ok(None);
    };
    // TODO create a method that get the fchunk by address
    for chunk in id0.fchunks(idx) {
        let chunk = chunk?;
        if chunk.address.contains(&Address::from_raw(ea.0)) {
            return Ok(Some(chunk));
        }
    }
    Ok(None)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x6903e0
pub fn get_func<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<func_t<K>>> {
    let Some(func) = get_fchunk(id0, ea)? else {
        return Ok(None);
    };
    if let func_t_type::Tail(IDBFunctionTail { owner, .. }) = &func.extra {
        get_fchunk(id0, *owner)
    } else {
        Ok(Some(func))
    }
}

pub fn getn_func<K: IDAKind>(
    id0: &ID0Section<K>,
    n: usize,
) -> Result<Option<func_t<K>>> {
    // TODO how the old versions work?
    let ords = id0
        .funcords_idx()?
        .ok_or_else(|| anyhow!("Missing funcords entry"))?;
    let Some(addr) = id0.funcords(ords)?.nth(n) else {
        return Ok(None);
    };
    get_func(id0, addr?)
}

pub fn get_func_num<K: IDAKind>(
    id0: &ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<usize>> {
    // TODO how the old versions work?
    let ords = id0
        .funcords_idx()?
        .ok_or_else(|| anyhow!("Missing funcords entry"))?;
    for (i, fun_addr) in id0.funcords(ords)?.enumerate() {
        if fun_addr? == ea {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

pub fn get_func_qty<K: IDAKind>(id0: &ID0Section<K>) -> Result<usize> {
    // TODO how the old versions work?
    let ords = id0
        .funcords_idx()?
        .ok_or_else(|| anyhow!("Missing funcords entry"))?;
    Ok(id0.funcords(ords)?.count())
}

pub fn get_func_cmt<K: IDAKind>(
    id0: &ID0Section<K>,
    netdelta: Netdelta<K>,
    addr: Address<K>,
    repeatable: bool,
) -> Result<Option<IDBString>> {
    let func_idx = id0
        .funcs_idx()?
        .ok_or_else(|| anyhow!("Missing funcs entry"))?;
    if repeatable {
        id0.func_repeatable_cmt(func_idx, netdelta, addr)
    } else {
        id0.func_cmt(func_idx, netdelta, addr)
    }
}

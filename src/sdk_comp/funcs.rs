use std::ops::Range;

use crate::id0::function::{
    IDBFunctionNonTail, IDBFunctionTail, IDBFunctionType,
};
use crate::Address;
use crate::{id0::ID0Section, IDAKind};

use super::frame::{regvar_t, stkpnt_t};
use super::nalt::type_t;
use super::pro::{asize_t, bgcolor_t, ea_t, ida_usize_t, uval_t};
use super::DataFetch;

use anyhow::Result;

pub struct func_t<'a, K: IDAKind> {
    pub range: Range<K::Usize>,
    pub flags: u64,
    pub func_t_type: func_t_type<'a, K>,
}

pub enum func_t_type<'a, K: IDAKind> {
    T1(func_t_1<'a, K>),
    T2(func_t_2<K>),
}

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
pub fn get_fchunk<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<func_t<'a, K>>> {
    let Some(idx) = id0.funcs_idx()? else {
        return Ok(None);
    };
    for chunk in id0.fchunks(idx) {
        let chunk = chunk?;
        if chunk.address.contains(&Address::from_raw(ea.0)) {
            return Ok(Some(func_t {
                range: chunk.address.start.into_raw()
                    ..chunk.address.end.into_raw(),
                flags: chunk.flags.into_raw(),
                func_t_type: match chunk.extra {
                    IDBFunctionType::Tail(IDBFunctionTail {
                        owner,
                        _unknown4,
                        _unknown5,
                    }) => func_t_type::T2(func_t_2 {
                        owner: ea_t::from_raw(owner),
                        // TODO check this
                        referers: ea_t::from_raw(K::Usize::from(
                            _unknown5.unwrap_or(_unknown4.into()),
                        )),
                    }),
                    IDBFunctionType::NonTail(IDBFunctionNonTail {
                        frame,
                        frsize,
                        frregs,
                        argsize,
                        pntqty,
                        llabelqty,
                        _unknown1,
                        regargqty,
                        color,
                        tailqty,
                        fpd,
                    }) => func_t_type::T1(func_t_1 {
                        frame: ida_usize_t::from_raw(frame),
                        frsize: asize_t::from_raw(frsize),
                        frregs,
                        argsize: ida_usize_t::from_raw(argsize),
                        fpd: asize_t::from_raw(fpd),
                        color: color.unwrap_or(u32::MAX),
                        points: DataFetch::Qty(pntqty),
                        llabels: DataFetch::Qty(llabelqty),
                        // TODO check this
                        regvars: DataFetch::Qty(_unknown1),
                        regargs: DataFetch::Qty(regargqty),
                        tails: DataFetch::Qty(tailqty),
                    }),
                },
            }));
        }
    }
    Ok(None)
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x6903e0
pub fn get_func<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    ea: ea_t<K>,
) -> Result<Option<func_t<'a, K>>> {
    let Some(func) = get_fchunk(id0, ea)? else {
        return Ok(None);
    };
    if let func_t_type::T2(func_t_2 { owner, referers: _ }) = &func.func_t_type
    {
        get_fchunk(id0, *owner)
    } else {
        Ok(Some(func))
    }
}

use crate::id0::{
    entry_iter::*, get_hash_from_key, get_netnode_from_key, get_sup_from_key,
    is_key_netnode,
};
use crate::id0::{flag, ID0Section, NetnodeIdx};
use crate::IDAKind;

use super::pro::nodeidx_t;

#[derive(Clone, Copy, Debug)]
pub struct netnode<K: IDAKind>(nodeidx_t<K>);

const fn check_tag(tag: u32) -> u8 {
    if tag >= 0x7F {
        unimplemented!();
    }
    tag as u8
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800440
pub fn netnode_check<K: IDAKind>(
    id0: &ID0Section<K>,
    name: &str,
) -> Option<netnode<K>> {
    id0.netnode_idx_by_name(name)
        .ok()?
        .map(|i| netnode(nodeidx_t::from_raw(i.0)))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800ae0
pub fn netnode_start<K: IDAKind>(id0: &ID0Section<K>) -> Option<netnode<K>> {
    id0.entries
        .iter()
        .find(|entry| is_key_netnode(&entry.key))
        .and_then(|entry| {
            get_netnode_from_key::<K>(&entry.key)
                .map(nodeidx_t::from_raw)
                .map(netnode)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800b00
pub fn netnode_end<K: IDAKind>(id0: &ID0Section<K>) -> Option<netnode<K>> {
    id0.entries
        .iter()
        .rev()
        .find(|entry| is_key_netnode(&entry.key))
        .and_then(|entry| {
            get_netnode_from_key::<K>(&entry.key)
                .map(nodeidx_t::from_raw)
                .map(netnode)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800b20
pub fn netnode_next<K: IDAKind>(
    id0: &ID0Section<K>,
    node: netnode<K>,
) -> Option<netnode<K>> {
    let node_idx = id0.netnode_next_idx(NetnodeIdx(node.0 .0))?;
    let key = &id0.entries[node_idx].key;
    if !is_key_netnode(key) {
        return None;
    }

    get_netnode_from_key::<K>(key)
        .map(nodeidx_t::from_raw)
        .map(netnode)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800b40
pub fn netnode_prev<K: IDAKind>(
    id0: &ID0Section<K>,
    node: netnode<K>,
) -> Option<netnode<K>> {
    let node_idx = id0.netnode_prev_idx(NetnodeIdx(node.0 .0))?;
    id0.entries
        .get(node_idx)
        .map(|entry| &entry.key[..])
        .filter(|key| is_key_netnode(key))
        .and_then(|key| {
            get_netnode_from_key::<K>(key)
                .map(nodeidx_t::from_raw)
                .map(netnode)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8004f0
pub fn netnode_get_name<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
) -> Option<&[u8]> {
    id0.netnode_name(NetnodeIdx(num.0))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800580
pub fn netnode_valobj<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
) -> Option<&[u8]> {
    id0.netnode_value(NetnodeIdx(num.0))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8005f0
pub fn netnode_valstr<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
) -> Option<&[u8]> {
    netnode_valobj(id0, num)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8005d0
pub fn netnode_qvalstr<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
) -> Option<&[u8]> {
    netnode_valstr(id0, num)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7f7240
pub fn netnode_charval<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<u8> {
    id0.char_value(NetnodeIdx(num.0), alt.0, check_tag(tag))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffd20
pub fn netnode_supval<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    id0.sup_value(NetnodeIdx(num.0), alt.0, check_tag(tag))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffdc0
pub fn netnode_supstr<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    netnode_supval(id0, num, alt, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffe50
pub fn netnode_qsupstr<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    netnode_supstr(id0, num, alt, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffed0
pub fn netnode_lower_bound<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    cur: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    let tag = check_tag(tag);
    EntryTagContinuousSubkeys::<'_, K>::new(id0, NetnodeIdx(num.0), tag, cur.0)
        .last()
        .and_then(move |entry| {
            get_sup_from_key::<K>(&entry.key).map(nodeidx_t::from_raw)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7fff50
pub fn netnode_supfirst<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    id0.netnode_tag_first_idx(NetnodeIdx(num.0), check_tag(tag))
        .map(|idx| &id0.entries[idx].key)
        .and_then(|key| get_sup_from_key::<K>(key).map(nodeidx_t::from_raw))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7fffc0
pub fn netnode_supnext<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    cur: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    let tag = check_tag(tag);
    id0.netnode_tag_alt_next_idx(NetnodeIdx(num.0), cur.0, tag)
        .map(|idx| &id0.entries[idx].key)
        .and_then(|key| get_sup_from_key::<K>(key).map(nodeidx_t::from_raw))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800020
pub fn netnode_suplast<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    let tag = check_tag(tag);
    id0.netnode_tag_last_idx(NetnodeIdx(num.0), tag)
        .map(|idx| &id0.entries[idx].key)
        .and_then(|key| get_sup_from_key::<K>(key).map(nodeidx_t::from_raw))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800090
pub fn netnode_supprev<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    cur: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    id0.netnode_tag_alt_prev_idx(NetnodeIdx(num.0), cur.0, check_tag(tag))
        .map(|idx| &id0.entries[idx].key)
        .and_then(|key| get_sup_from_key::<K>(key).map(nodeidx_t::from_raw))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffd60
pub fn netnode_supval_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    netnode_supval(id0, num, alt, tag | flag::netnode::NETMAP_X8)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffdf0
pub fn netnode_supstr_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    netnode_supstr(id0, num, alt, tag | flag::netnode::NETMAP_X8)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffe80
pub fn netnode_qsupstr_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    netnode_qsupstr(id0, num, alt, tag | flag::netnode::NETMAP_X8)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7fff00
pub fn netnode_lower_bound_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    netnode_lower_bound(id0, num, alt, tag | flag::netnode::NETMAP_X8)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7fff70
pub fn netnode_supfirst_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    netnode_supfirst(id0, num, tag | flag::netnode::NETMAP_X8)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffff0
pub fn netnode_supnext_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: u8,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    netnode_supnext(
        id0,
        num,
        nodeidx_t::from_raw(alt.into()),
        tag | flag::netnode::NETMAP_X8,
    )
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800040
pub fn netnode_suplast_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    netnode_suplast(id0, num, tag | flag::netnode::NETMAP_X8)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8000c0
pub fn netnode_supprev_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: u8,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    netnode_supprev(
        id0,
        num,
        nodeidx_t::from_raw(alt.into()),
        tag | flag::netnode::NETMAP_X8,
    )
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffb40
pub fn netnode_charval_idx8<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: u8,
    tag: u32,
) -> Option<u8> {
    netnode_charval(
        id0,
        num,
        nodeidx_t::from_raw(alt.into()),
        tag | flag::netnode::NETMAP_X8,
    )
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800770
pub fn netnode_hashval<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    idx: &[u8],
    tag: u32,
) -> Option<&'a [u8]> {
    id0.hash_value(NetnodeIdx(num.0), idx, check_tag(tag))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800800
pub fn netnode_hashstr<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    idx: &[u8],
    tag: u32,
) -> Option<&'a [u8]> {
    netnode_hashval(id0, num, idx, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8007d0
pub fn netnode_qhashstr<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    idx: &[u8],
    tag: u32,
) -> Option<&'a [u8]> {
    netnode_hashstr(id0, num, idx, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800850
pub fn netnode_hashval_long<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    idx: &[u8],
    tag: u32,
) -> Option<nodeidx_t<K>> {
    netnode_hashval(id0, num, idx, tag)
        .and_then(K::usize_try_from_le_bytes)
        .map(nodeidx_t::from_raw)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800970
pub fn netnode_hashfirst<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    id0.netnode_tag_first_idx(NetnodeIdx(num.0), check_tag(tag))
        .and_then(|i| get_hash_from_key::<K>(&id0.entries[i].key))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800940
pub fn netnode_qhashfirst<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    netnode_hashfirst(id0, num, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8009f0
pub fn netnode_hashnext<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    idx: &[u8],
    tag: u32,
) -> Option<&'a [u8]> {
    id0.netnode_tag_hash_next_idx(NetnodeIdx(num.0), idx, check_tag(tag))
        .and_then(|i| get_hash_from_key::<K>(&id0.entries[i].key))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8009c0
pub fn netnode_qhashnext<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    idx: &[u8],
    tag: u32,
) -> Option<&'a [u8]> {
    netnode_hashnext(id0, num, idx, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800a50
pub fn netnode_hashlast<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    id0.netnode_tag_last_idx(NetnodeIdx(num.0), check_tag(tag))
        .and_then(|i| get_hash_from_key::<K>(&id0.entries[i].key))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800a20
pub fn netnode_qhashlast<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    netnode_hashlast(id0, num, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800ab0
pub fn netnode_hashprev<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    idx: &[u8],
    tag: u32,
) -> Option<&'a [u8]> {
    id0.netnode_tag_hash_prev_idx(NetnodeIdx(num.0), idx, check_tag(tag))
        .and_then(|i| get_hash_from_key::<K>(&id0.entries[i].key))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800a80
pub fn netnode_qhashprev<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    idx: &[u8],
    tag: u32,
) -> Option<&'a [u8]> {
    netnode_hashprev(id0, num, idx, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800210
pub fn netnode_blobsize<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    start: nodeidx_t<K>,
    tag: u32,
) -> usize {
    id0.blob(NetnodeIdx(num.0), start.0, check_tag(tag)).count()
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800240
pub fn netnode_getblob<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    start: nodeidx_t<K>,
    tag: u32,
) -> Vec<u8> {
    id0.blob(NetnodeIdx(num.0), start.0, check_tag(tag))
        .collect()
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8002a0
pub fn netnode_qgetblob<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    start: nodeidx_t<K>,
    tag: u32,
) -> Vec<u8> {
    netnode_getblob(id0, num, start, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffaa0
pub fn netnode_exist<K: IDAKind>(id0: &ID0Section<K>, n: netnode<K>) -> bool {
    id0.netnode_idx(NetnodeIdx(n.0 .0)).is_some()
}

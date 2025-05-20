use std::borrow::Cow;

use num_traits::ToBytes;

use crate::id0::flag::netnode::nn_res::*;
use crate::id0::{flag, ID0Entry, ID0Section};
use crate::{IDAKind, IDAUsize};

use super::pro::nodeidx_t;

#[derive(Clone, Copy, Debug)]
pub struct netnode<K: IDAKind>(nodeidx_t<K>);

fn check_tag(tag: u32) -> u8 {
    if tag & flag::netnode::NETMAP_IDX != 0
        || tag & flag::netnode::NETMAP_VAL != 0
    {
        unimplemented!("dynamic ea2node is unavailable, call ea2node manually");
    }
    if tag & flag::netnode::NETMAP_STR != 0 {
        unimplemented!();
    }
    if tag & flag::netnode::NETMAP_X8 != 0
        || tag & flag::netnode::NETMAP_V8 != 0
    {
        unimplemented!();
    }
    if tag & flag::netnode::NETMAP_VAL_NDX != 0 {
        unimplemented!();
    }
    tag as u8
}

fn key_from_num<K: IDAKind>(num: nodeidx_t<K>) -> Vec<u8> {
    b".".iter()
        .chain(num.as_raw().to_be_bytes().as_ref())
        .copied()
        .collect()
}

fn key_from_num_tag<K: IDAKind>(num: nodeidx_t<K>, tag: u8) -> Vec<u8> {
    b".".iter()
        .chain(num.as_raw().to_be_bytes().as_ref())
        .chain([tag].iter())
        .copied()
        .collect()
}

fn key_from_num_tag_sup<K: IDAKind>(
    num: nodeidx_t<K>,
    tag: u8,
    cur: nodeidx_t<K>,
) -> Vec<u8> {
    b".".iter()
        .chain(num.as_raw().to_be_bytes().as_ref())
        .chain([tag].iter())
        .chain(cur.as_raw().to_be_bytes().as_ref())
        .copied()
        .collect()
}

fn key_from_num_tag_hash<K: IDAKind>(
    num: nodeidx_t<K>,
    tag: u8,
    cur: &[u8],
) -> Vec<u8> {
    b".".iter()
        .chain(num.as_raw().to_be_bytes().as_ref())
        .chain([tag].iter())
        .chain(cur)
        .copied()
        .collect()
}

fn subkey_with_tag<K: IDAKind>(key: &[u8]) -> &[u8] {
    // 1 for the '.', K::Usize::BYTES for the num and the other 1 for the tag
    &key[..1 + usize::from(K::Usize::BYTES) + 1]
}

fn subidx_from_other_entry<K: IDAKind>(
    other_entry: &ID0Entry,
    subkey: &[u8],
) -> Option<nodeidx_t<K>> {
    other_entry
        .key
        .starts_with(subkey)
        .then(|| {
            <K::Usize as IDAUsize>::from_be_bytes(
                &other_entry.key[subkey.len()..],
            )
            .map(nodeidx_t::from_raw)
        })
        .flatten()
}

fn iter_all_subkeys<'a, 'b, K: IDAKind>(
    id0: &'a ID0Section<K>,
    start_idx: usize,
    subkey: &'b [u8],
) -> impl Iterator<Item = &'a ID0Entry> + use<'a, 'b, K> {
    id0.entries[start_idx..].iter().scan((), |(), entry| {
        entry.key.starts_with(subkey).then_some(entry)
    })
}

fn iter_continous_subkeys<'a, 'b, K: IDAKind>(
    id0: &'a ID0Section<K>,
    start_idx: usize,
    subkey: &'b [u8],
    start: nodeidx_t<K>,
) -> impl Iterator<Item = &'a ID0Entry> + use<'a, 'b, K> {
    let subkeylen = subkey.len();
    iter_all_subkeys(id0, start_idx, subkey).scan(
        start.as_raw(),
        move |current_subidx, entry| {
            if &entry.key[subkeylen..] != current_subidx.to_be_bytes().as_ref()
            {
                return None;
            }
            *current_subidx += 1u8.into();
            Some(entry)
        },
    )
}

// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800440
pub fn netnode_check<K: IDAKind>(
    id0: &ID0Section<K>,
    name: &str,
) -> Option<netnode<K>> {
    id0.get(format!("N{name}")).and_then(|entry| {
        <K::Usize as IDAUsize>::from_le_bytes(&entry.value)
            .map(|value| netnode(nodeidx_t::from_raw(value)))
    })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800ae0
pub fn netnode_start<K: IDAKind>(id0: &ID0Section<K>) -> Option<netnode<K>> {
    id0.entries
        .iter()
        .find(|entry| entry.key.starts_with(b"."))
        .and_then(|entry| {
            K::Usize::from_be_bytes(
                &entry.key[1..1 + usize::from(K::Usize::BYTES)],
            )
            .map(nodeidx_t::from_raw)
            .map(netnode)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800b00
pub fn netnode_end<K: IDAKind>(id0: &ID0Section<K>) -> Option<netnode<K>> {
    id0.entries
        .iter()
        .rev()
        .find(|entry| entry.key.starts_with(b"."))
        .and_then(|entry| {
            K::Usize::from_be_bytes(
                &entry.key[1..1 + usize::from(K::Usize::BYTES)],
            )
            .map(nodeidx_t::from_raw)
            .map(netnode)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800b20
pub fn netnode_next<K: IDAKind>(
    id0: &ID0Section<K>,
    node: netnode<K>,
) -> Option<netnode<K>> {
    let subkey = key_from_num(node.0);
    let node_idx = id0.binary_search_any_of(&subkey).ok()?;
    id0.entries[node_idx..]
        .iter()
        .map(|entry| &entry.key[..])
        .take_while(|key| key.starts_with(b"."))
        .find(|key| !key.starts_with(&subkey))
        .and_then(|key| {
            K::Usize::from_be_bytes(&key[1..1 + usize::from(K::Usize::BYTES)])
                .map(nodeidx_t::from_raw)
                .map(netnode)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800b40
pub fn netnode_prev<K: IDAKind>(
    id0: &ID0Section<K>,
    node: netnode<K>,
) -> Option<netnode<K>> {
    let subkey = key_from_num(node.0);
    let node_idx = id0.binary_search_any_of(&subkey).ok()?;
    id0.entries[..node_idx]
        .iter()
        .rev()
        .map(|entry| &entry.key[..])
        .take_while(|key| key.starts_with(b"."))
        .find(|key| !key.starts_with(&subkey))
        .and_then(|key| {
            K::Usize::from_be_bytes(&key[1..1 + usize::from(K::Usize::BYTES)])
                .map(nodeidx_t::from_raw)
                .map(netnode)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8004f0
pub fn netnode_get_name<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
) -> Option<&[u8]> {
    let key = key_from_num_tag(num, NAME_TAG);
    id0.get(&key).map(|entry| &entry.value[..])
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800580
pub fn netnode_valobj<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
) -> Option<&[u8]> {
    let key = key_from_num_tag(num, VALUE_TAG);
    id0.get(&key).map(|entry| &entry.value[..])
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
    let key = key_from_num_tag_sup(num, check_tag(tag), alt);
    id0.get(&key)
        .and_then(|entry| (entry.value.len() == 1).then_some(entry.value[0]))
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffd20
pub fn netnode_supval<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    let key = key_from_num_tag_sup(num, check_tag(tag), alt);
    id0.get(&key).map(|entry| &entry.value[..])
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffdc0
pub fn netnode_supstr<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    alt: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    let key = key_from_num_tag_sup(num, check_tag(tag), alt);
    id0.get(&key).map(|entry| &entry.value[..])
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
    let key = key_from_num_tag_sup(num, check_tag(tag), cur);
    let start_idx = id0.binary_search(&key).ok()?;
    let subkey = subkey_with_tag::<K>(&key);
    iter_continous_subkeys(id0, start_idx, subkey, cur)
        .last()
        .and_then(|entry| {
            <K::Usize as IDAUsize>::from_be_bytes(&entry.key[subkey.len()..])
                .map(nodeidx_t::from_raw)
        })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7fff50
pub fn netnode_supfirst<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    let key = key_from_num_tag(num, check_tag(tag));
    id0.range_start(&key).and_then(|entry| {
        let value = &entry.key[key.len()..];
        <K::Usize as IDAUsize>::from_be_bytes(value).map(nodeidx_t::from_raw)
    })
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7fffc0
pub fn netnode_supnext<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    cur: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    let key = key_from_num_tag_sup(num, check_tag(tag), cur);
    let subkey = subkey_with_tag::<K>(&key);
    let idx = id0.binary_search(&key).ok()?;
    // check if the next entry is the next on the sup
    let next = id0.entries.get(idx + 1)?;
    subidx_from_other_entry(next, subkey)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800020
pub fn netnode_suplast<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    let subkey = key_from_num_tag(num, check_tag(tag));
    let end = id0.binary_search_end(&subkey);
    // check if the last entry is part of the key
    let prev = &id0.entries[end.checked_sub(1)?];
    subidx_from_other_entry(prev, &subkey)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800090
pub fn netnode_supprev<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    cur: nodeidx_t<K>,
    tag: u32,
) -> Option<nodeidx_t<K>> {
    let key = key_from_num_tag_sup(num, check_tag(tag), cur);
    let subkey = subkey_with_tag::<K>(&key);
    let idx = id0.binary_search(&key).ok()?;
    // check if the next entry is the next on the sup
    let next = id0.entries.get(idx.checked_sub(1)?)?;
    subidx_from_other_entry(next, subkey)
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
    let key = key_from_num_tag_hash(num, check_tag(tag), idx);
    id0.get(&key).map(|entry| &entry.value[..])
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
        .and_then(K::Usize::from_le_bytes)
        .map(nodeidx_t::from_raw)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800970
pub fn netnode_hashfirst<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    tag: u32,
) -> Option<&[u8]> {
    let key = key_from_num_tag(num, check_tag(tag));
    id0.range_start(&key).map(|entry| &entry.key[key.len()..])
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
    let key = key_from_num_tag_hash(num, check_tag(tag), idx);
    let subkey = subkey_with_tag::<K>(&key);
    let idx = id0.binary_search(&key).ok()?;
    let next = id0.entries.get(idx + 1)?;
    next.key
        .starts_with(subkey)
        .then(|| &next.key[subkey.len()..])
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
    let subkey = key_from_num_tag(num, check_tag(tag));
    let end_idx = id0.binary_search_end(&subkey);
    let last = id0.entries.get(end_idx.checked_sub(1)?)?;
    last.key
        .starts_with(&subkey)
        .then(|| &last.key[subkey.len()..])
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
    let key = key_from_num_tag_hash(num, check_tag(tag), idx);
    let subkey = subkey_with_tag::<K>(&key);
    let idx = id0.binary_search(&key).ok()?;
    let next = id0.entries.get(idx.checked_sub(1)?)?;
    next.key
        .starts_with(subkey)
        .then(|| &next.key[subkey.len()..])
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
) -> Option<usize> {
    let key = key_from_num_tag_sup(num, check_tag(tag), start);
    let subkey = subkey_with_tag::<K>(&key);
    let start_idx = id0.binary_search(&key).ok()?;
    Some(
        iter_continous_subkeys(id0, start_idx, subkey, start)
            .map(|entry| entry.value.len())
            .sum(),
    )
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x800240
pub fn netnode_getblob<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    num: nodeidx_t<K>,
    start: nodeidx_t<K>,
    tag: u32,
) -> Option<Cow<'a, [u8]>> {
    let key = key_from_num_tag_sup(num, check_tag(tag), start);
    let subkey = subkey_with_tag::<K>(&key);
    let start_idx = id0.binary_search(&key).ok()?;
    let values = iter_continous_subkeys(id0, start_idx, subkey, start)
        .fold(None, |mut acc, entry| match acc {
            None => Some(Cow::Borrowed(&entry.value[..])),
            Some(Cow::Borrowed(last_value)) => Some(Cow::Owned(
                last_value.iter().chain(&entry.value).copied().collect(),
            )),
            Some(Cow::Owned(ref mut data_acc)) => {
                data_acc.extend(&entry.value);
                acc
            }
        })
        // iter_continous_subkeys should always return one element, the one that
        // found with binary_search
        .unwrap();
    Some(values)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x8002a0
pub fn netnode_qgetblob<K: IDAKind>(
    id0: &ID0Section<K>,
    num: nodeidx_t<K>,
    start: nodeidx_t<K>,
    tag: u32,
) -> Option<Cow<'_, [u8]>> {
    netnode_getblob(id0, num, start, tag)
}
// InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x7ffaa0
pub fn netnode_exist<K: IDAKind>(id0: &ID0Section<K>, n: netnode<K>) -> bool {
    let key = key_from_num(n.0);
    id0.get(&key).is_some()
}

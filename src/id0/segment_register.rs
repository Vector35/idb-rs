use anyhow::{anyhow, Result};
use num_traits::CheckedAdd;
use serde::Serialize;
use std::ops::Range;

use crate::id0::{ID0Entry, ID0Section, NetnodeIdx};
use crate::ida_reader::{IdbBufRead, IdbReadKind};
use crate::{Address, IDAKind};

#[derive(Copy, Clone, Debug)]
pub struct SrareasIdx<K: IDAKind>(pub(crate) K::Usize);
impl<K: IDAKind> From<SrareasIdx<K>> for NetnodeIdx<K> {
    fn from(value: SrareasIdx<K>) -> Self {
        Self(value.0)
    }
}

#[derive(Debug, Copy, Clone, Serialize)]
pub enum SRegTag {
    Inherit = 1,
    User = 2,
    Auto = 3,
    Autostart = 4,
}

impl SRegTag {
    fn from_raw(tag_raw: u8) -> Result<Self> {
        match tag_raw {
            1 => Ok(SRegTag::Inherit),
            2 => Ok(SRegTag::User),
            3 => Ok(SRegTag::Auto),
            4 => Ok(SRegTag::Autostart),
            _ => Err(anyhow!("Invalid Srarea tag value {tag_raw:X}")),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Srarea<K: IDAKind> {
    pub range: Range<Address<K>>,
    pub value: Option<K::Usize>,
    pub tag: Option<SRegTag>,
}

impl<K: IDAKind> Srarea<K> {
    fn read(entry: &ID0Entry) -> Result<Srarea<K>> {
        let key =
            crate::id0::get_sup_from_key::<K>(&entry.key).ok_or_else(|| {
                anyhow!("Srarea entry with missing valid address key")
            })?;
        let mut cursor = &entry.value[..];
        let value = Self::read_inner(&mut cursor, key)?;
        #[cfg(feature = "restrictive")]
        anyhow::ensure!(
            cursor.is_empty(),
            "Srare entry have more data then expected: {} bytes",
            cursor.len()
        );
        Ok(value)
    }

    fn read_inner<I: IdbReadKind<K> + IdbBufRead>(
        input: &mut I,
        _address_key: K::Usize,
    ) -> Result<Srarea<K>> {
        let start_raw = input.unpack_usize()?;
        // address_key is usually the same as the address start, but not always
        // it seems that is always starts with that value, but in case the
        // segment is moved it may retain the old value
        let offset = input.unpack_usize()?;
        let end_raw = start_raw.checked_add(&offset).ok_or_else(|| {
            anyhow!("Invalid srarea end offset {start_raw:X} offset {offset:X}")
        })?;
        let range = Address::from_raw(start_raw)..Address::from_raw(end_raw);
        // TODO is usize or dq?
        let value_raw = input.unpack_usize()?;
        let value = (value_raw != 0u8.into()).then_some(value_raw - 1u8.into());
        let tag_raw = input.read_u8_or_nothing()?;
        let tag = tag_raw.map(SRegTag::from_raw).transpose()?;
        Ok(Srarea { range, value, tag })
    }
}

pub(crate) fn srareas_idx<K: IDAKind>(
    id0: &ID0Section<K>,
) -> Result<Option<SrareasIdx<K>>> {
    Ok(id0
        .netnode_idx_by_name("$ srareas")?
        .map(|x| SrareasIdx(x.0)))
}

pub(crate) fn srareas<K: IDAKind>(
    id0: &ID0Section<K>,
    idx: SrareasIdx<K>,
    segment_register_idx: u8,
) -> impl Iterator<Item = Result<Srarea<K>>> + use<'_, K> {
    // TODO find the 'a' is the tag from the SDK
    let entries = id0
        .sup_range(idx.into(), b'a' + segment_register_idx)
        .entries;
    entries.iter().map(Srarea::read)
}

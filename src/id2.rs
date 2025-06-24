use std::ops::Range;

use anyhow::{anyhow, ensure, Result};
use num_traits::CheckedAdd;

use crate::id1::ByteInfo;
use crate::ida_reader::IdbReadKind;
use crate::{
    Address, IDAKind, IDAUsize, IDAVariants, SectionReader, IDA32, IDA64,
};

pub type ID2SectionVariants = IDAVariants<ID2Section<IDA32>, ID2Section<IDA64>>;

#[derive(Debug, Clone)]
pub struct ID2Section<K: IDAKind> {
    pub(crate) _ranges1: Vec<Range<K::Usize>>,
    pub(crate) _ranges2: Vec<Range<K::Usize>>,
    pub entries: Vec<ID2Entry<K>>,
}

#[derive(Debug, Clone, Copy)]
pub struct ID2Entry<K: IDAKind> {
    pub address: Address<K>,
    pub byte_info: ByteInfo,
    pub len: K::Usize,
}

impl<K: IDAKind> SectionReader<K> for ID2Section<K> {
    type Result = Self;

    fn read_section<R: IdbReadKind<K>>(input: &mut R) -> Result<Self> {
        Self::read(input)
    }
}

impl<K: IDAKind> ID2Section<K> {
    pub fn read<R: IdbReadKind<K>>(input: &mut R) -> Result<Self> {
        // InnerRef fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4ee39c
        let magic: [u8; 9] = bincode::deserialize_from(&mut *input).unwrap();
        ensure!(magic == *b"IDAS\x1d\xa5UU\x00", "Invalid ID2 Magic");
        let ranges1 = Self::read_ranges(&mut *input)?;
        let ranges2 = Self::read_ranges(&mut *input)?;
        let mut acc: K::Usize = 0u8.into();
        let mut min_addr: K::Usize = 0u8.into();
        let mut entries = vec![];
        loop {
            acc = acc
                .checked_add(&input.unpack_usize()?)
                .ok_or_else(|| anyhow!("Invalid ID2 wrapping address"))?;
            let address = acc;
            if address.is_max() {
                break;
            }
            let byte_info = crate::id1::ByteInfo::from_raw(input.unpack_dd()?);
            let len = input.unpack_usize()?;
            if !byte_info.byte_type().is_tail() {
                if address < min_addr {
                    return Err(anyhow!(
                        "Invalid ID2 Address, overallaping with previous"
                    ));
                }
                if address.checked_add(&len).is_none() {
                    return Err(anyhow!(
                        "Invalid ID2 Address, non-tail entry is too big"
                    ));
                }
            }
            min_addr = address + len;
            entries.push(ID2Entry {
                address: Address::from_raw(address),
                byte_info,
                len,
            })
        }
        Ok(Self {
            _ranges1: ranges1,
            _ranges2: ranges2,
            entries,
        })
    }

    fn read_ranges<R: IdbReadKind<K>>(
        input: &mut R,
    ) -> Result<Vec<Range<K::Usize>>> {
        let n = input.unpack_dd()?;
        let mut acc: K::Usize = 0u8.into();
        (0..n)
            .map(|_| {
                let start_offset = input.unpack_usize()?;
                acc = acc.checked_add(&start_offset).ok_or_else(|| {
                    anyhow!("Invalid ID2 wrapping range start offset")
                })?;
                let start = acc;
                let end_offset = input.unpack_usize()?;
                ensure!(
                    end_offset != K::Usize::from(0u8),
                    "Invalid ID2 empty sparse range"
                );
                acc = acc.checked_add(&end_offset).ok_or_else(|| {
                    anyhow!("Invalid ID2 wrapping range start offset")
                })?;
                // TODO check overlaps
                // TODO check order
                let end = acc;
                Ok(start..end)
            })
            .collect()
    }

    pub fn byte_by_address(&self, address: Address<K>) -> Option<&ID2Entry<K>> {
        self.entries
            .binary_search_by_key(&address, |x| x.address)
            .ok()
            .map(|x| &self.entries[x])
    }

    pub fn all_bytes(&self) -> impl Iterator<Item = &ID2Entry<K>> + use<'_, K> {
        self.entries.iter()
    }

    pub fn all_bytes_no_tails(
        &self,
    ) -> impl Iterator<Item = &ID2Entry<K>> + use<'_, K> {
        self.entries
            .iter()
            .filter(|entry| !entry.byte_info.byte_type().is_tail())
    }

    pub fn prev_not_tail(&self, ea: Address<K>) -> Option<&ID2Entry<K>> {
        let idx = self.entries.binary_search_by_key(&ea, |x| x.address).ok()?;
        self.entries[..idx]
            .iter()
            .rev()
            .find(|x| !x.byte_info.byte_type().is_tail())
    }

    // get the address of the next non tail thing
    pub fn next_not_tail(&self, ea: Address<K>) -> Option<&ID2Entry<K>> {
        let idx = self.entries.binary_search_by_key(&ea, |x| x.address).ok()?;
        self.entries[idx..]
            .iter()
            .find(|x| !x.byte_info.byte_type().is_tail())
    }
}

use std::borrow::Cow;

use anyhow::{anyhow, ensure, Result};
use byteorder::BE;
use num_traits::ToBytes;

use crate::ida_reader::IdbRead;
use crate::{til, IDAKind, IDAUsize};

use super::{
    flag, parse_maybe_cstr, FileRegionIter, FileRegions, ID0CStr, ID0Entry,
    ID0Section,
};

#[derive(Clone, Debug)]
pub enum AddressInfo<'a, K: IDAKind> {
    Comment(Comments<'a>),
    Label(Cow<'a, str>),
    TilType(til::Type),
    DefinedStruct(SubtypeId<K>),
    Other { key: &'a [u8], value: &'a [u8] },
}

#[derive(Clone, Debug)]
pub enum Comments<'a> {
    Comment(&'a [u8]),
    RepeatableComment(&'a [u8]),
    PreComment(&'a [u8]),
    PostComment(&'a [u8]),
}

#[derive(Clone, Copy, Debug)]
pub struct SubtypeId<K: IDAKind>(pub(crate) K::Usize);

impl<'a> Comments<'a> {
    /// The message on the comment, NOTE that IDA don't have a default character encoding
    pub fn message(&self) -> &'a [u8] {
        match self {
            Comments::Comment(x)
            | Comments::RepeatableComment(x)
            | Comments::PreComment(x)
            | Comments::PostComment(x) => x,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SectionAddressInfoByAddressIter<'a, K: IDAKind> {
    id0: &'a ID0Section<K>,
    regions: FileRegionIter<'a, K>,
    current_region: &'a [ID0Entry],
}

impl<'a, K: IDAKind> SectionAddressInfoByAddressIter<'a, K> {
    pub fn new(id0: &'a ID0Section<K>, version: u16) -> Result<Self> {
        let idx = id0.file_regions_idx()?;
        let regions = id0.file_regions(idx, version);
        Ok(Self {
            id0,
            regions,
            // dummy values
            current_region: &[],
        })
    }

    fn advance_region(&mut self) -> Result<Option<()>> {
        // get the next region
        advance_region(&self.id0, &mut self.regions).map(|x| {
            x.map(|x| {
                self.current_region = x;
                ()
            })
        })
    }

    fn next_inner(
        &mut self,
    ) -> Result<Option<(K::Usize, AddressInfoIter<'a, K>)>> {
        // get the next address of the current region, if nothing, next region
        let Some(first) = self.current_region.first() else {
            if self.advance_region()?.is_none() {
                // no more regions, end it
                return Ok(None);
            }
            // NOTE regions can be empty, so check if this new region have
            // elements by calling this function again
            return self.next_inner();
        };

        let mut cursor = &first.key[..];
        // skip the '.'
        ensure!(cursor.read_u8()? == b'.');
        // read the key
        let address = K::Usize::from_bytes_reader::<BE>(&mut cursor)?;

        let end = self
            .current_region
            .iter()
            .position(|e| !e.key.starts_with(address.to_be_bytes().as_ref()))
            .unwrap_or(self.current_region.len());
        let (current_addr, rest) = self.current_region.split_at(end);
        self.current_region = rest;
        Ok(Some((
            address,
            AddressInfoIter::new(current_addr, &self.id0),
        )))
    }
}

impl<'a, K: IDAKind> Iterator for SectionAddressInfoByAddressIter<'a, K> {
    type Item = Result<(K::Usize, AddressInfoIter<'a, K>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_inner().transpose()
    }
}

#[derive(Clone, Copy)]
pub struct SectionAddressInfoIter<'a, K: IDAKind> {
    id0: &'a ID0Section<K>,
    regions: FileRegionIter<'a, K>,
    current_region: AddressInfoIter<'a, K>,
}

impl<'a, K: IDAKind> SectionAddressInfoIter<'a, K> {
    pub fn new(id0: &'a ID0Section<K>, version: u16) -> Result<Self> {
        let idx = id0.file_regions_idx()?;
        let regions = id0.file_regions(idx, version);
        Ok(Self {
            id0,
            regions,
            // dummy value
            current_region: AddressInfoIter::new(&[], id0),
        })
    }

    fn advance_region(&mut self) -> Result<Option<()>> {
        // get the next region
        advance_region(&self.id0, &mut self.regions).map(|x| {
            x.map(|x| {
                self.current_region = AddressInfoIter::new(x, &self.id0);
                ()
            })
        })
    }
}

impl<'a, K: IDAKind> Iterator for SectionAddressInfoIter<'a, K> {
    type Item = Result<(K::Usize, AddressInfo<'a, K>)>;

    fn next(&mut self) -> Option<Self::Item> {
        // next element in the current region, or next region
        let Some(next_addr_info) = self.current_region.next() else {
            match self.advance_region() {
                Ok(Some(_)) => {}
                // no more regions, end it
                Ok(None) => return None,
                Err(e) => return Some(Err(e)),
            };
            // NOTE regions can be empty, so check if this new region have
            // elements by calling this function again
            return self.next();
        };
        Some(next_addr_info)
    }
}

#[derive(Clone, Copy)]
pub struct AddressInfoIter<'a, K: IDAKind> {
    id0: &'a ID0Section<K>,
    entries: &'a [ID0Entry],
}

impl<'a, K: IDAKind> AddressInfoIter<'a, K> {
    pub fn new(entries: &'a [ID0Entry], section: &'a ID0Section<K>) -> Self {
        Self {
            entries,
            id0: section,
        }
    }

    fn next_inner(&mut self) -> Result<Option<(K::Usize, AddressInfo<'a, K>)>> {
        let Some((current, rest)) = self.entries.split_first() else {
            return Ok(None);
        };
        self.entries = rest;
        let mut cursor = &current.key[..];
        // skip the '.'
        ensure!(cursor.read_u8()? == b'.');
        // read the key
        let address = K::Usize::from_bytes_reader::<BE>(&mut cursor)?;
        let (sub_type, subkey) = id_subkey_from_idx::<K>(cursor)
            .ok_or_else(|| anyhow!("Missing SubType"))?;

        // Non UTF-8 comment: "C:\\Documents and Settings\\Administrator\\\xb9\xd9\xc5\xc1 \xc8\xad\xb8\xe9\ls"
        // \xb9\xd9\xc5\xc1 \xc8\xad\xb8\xe9 = "바탕 화면" = "Desktop" in Korean encoded using Extended Unix Code
        #[allow(clippy::wildcard_in_or_patterns)]
        match (sub_type, subkey.map(<K::Usize as Into<u64>>::into)) {
            // Comments
            // NOTE
            // pre comments start at index 1000
            // post comments start at index 2000
            // if you create more then a 1000 pre/post comments ida start acting strange, BUG?
            (flag::netnode::nn_res::ARRAY_SUP_TAG, Some(1000..=1999)) => {
                let comment = parse_maybe_cstr(&current.value[..]).ok_or_else(||
                    anyhow!("Pre-Comment is not valid CStr")
                )?;
                Ok(Some((address, AddressInfo::Comment(Comments::PreComment(comment)))))
            },
            (flag::netnode::nn_res::ARRAY_SUP_TAG, Some(2000..=2999)) => {
                let comment = parse_maybe_cstr(&current.value[..]).ok_or_else(||
                    anyhow!("Post-Comment is not valid CStr")
                )?;
                Ok(Some((address, AddressInfo::Comment(Comments::PostComment(comment)))))
            },
            (flag::netnode::nn_res::ARRAY_SUP_TAG, Some(0x0)) => {
                let comment = parse_maybe_cstr(&current.value[..]).ok_or_else(||
                    anyhow!("Comment is not valid CStr")
                )?;
                Ok(Some((address, AddressInfo::Comment(Comments::Comment(comment)))))
            },
            // Repeatable comment
            (flag::netnode::nn_res::ARRAY_SUP_TAG, Some(0x1)) => {
                let comment = parse_maybe_cstr(&current.value[..]).ok_or_else(||
                    anyhow!("Repeatable Comment is not valid CStr")
                )?;
                Ok(Some((address, AddressInfo::Comment(Comments::RepeatableComment(comment)))))
            },

            // Type at this address
            (flag::netnode::nn_res::ARRAY_SUP_TAG, Some(0x3000)) => {
                // take the field names (optional?) and the continuation (optional!)
                let last = rest.iter().position(|entry| {
                    let Some((_address, sub_type, Some(id))) = id_subkey_from_key::<K>(&entry.key[..]) else {
                        return true;
                    };
                    !matches!((sub_type, <K::Usize as Into<u64>>::into(id)), (b'S', 0x3000u64..=0x3999))
                }).unwrap_or(rest.len());
                self.entries = &rest[last..];
                // TODO enforce sequential index for the id?
                // get the entry for field names and rest of data
                let (fields, continuation) = match &rest[..last] {
                    [fields, rest @ ..] if id_subkey_from_key::<K>(&fields.key[..]) == Some((address, b'S', Some(K::Usize::from(0x3001u16)))) => {
                        // convert the value into fields
                        // usually this string ends with \x00, but bmaybe there is no garanty for that.
                        let value = parse_maybe_cstr(&fields.value).ok_or_else(||anyhow!("Incomplete Fields for TIL Type"))?;
                        let fields = crate::ida_reader::split_strings_from_array(value).ok_or_else(||anyhow!("Invalid Fields for TIL Type"))?;
                        (fields, rest)
                    }
                    rest => (vec![], rest),
                };

                // condensate the data into a single buffer
                let buf: Vec<u8> = current.value.iter().chain(continuation.iter().flat_map(|entry| &entry.value[..])).copied().collect();
                // create the raw type
                let til = til::Type::new_from_id0(&buf[..], fields)?;
                Ok(Some((address, AddressInfo::TilType(til))))
            },
            // field names and continuation in from the previous til type [citation needed]
            (flag::netnode::nn_res::ARRAY_SUP_TAG, Some(0x3001..=0x3999)) => {
                Err(anyhow!("ID0 Til type info without a previous TIL type"))
            },

            // Name, aka a label to this memory address
            (flag::netnode::nn_res::NAME_TAG, None) => {
                let value = ID0CStr::<'_, K>::parse_cstr_or_subkey(&current.value)
                    .ok_or_else(|| anyhow!("Label is not a valid CStr or ID0 Ref"))?;
                let label = match value {
                    ID0CStr::CStr(label_raw) => {
                        let label = core::str::from_utf8(label_raw).map_err(|_|
                            anyhow!("Label is not valid UTF-8")
                        )?;
                        Cow::Borrowed(label)
                    },
                    ID0CStr::Ref(label_ref) => {
                        let entries = self.id0.address_info_value(label_ref)?;
                        let label_raw = entries.iter().flat_map(|x| &x.value[..]).copied().collect();
                        let label = String::from_utf8(label_raw).map_err(|_| {
                            anyhow!("LabelRef is not valid UTF-8")
                        })?;
                        Cow::Owned(label)
                    },
                };
                Ok(Some((address, AddressInfo::Label(label))))
            },

            // Used to define what struct is apply at the address
            (flag::nalt::x::NALT_DREF_FROM, Some(_)) if &current.value[..] == &[0x03] => {
                Ok(Some((address, AddressInfo::DefinedStruct(SubtypeId(subkey.unwrap())))))
            }

            // Seems related to datatype, maybe cstr, align and stuff like that
            (flag::netnode::nn_res::ARRAY_ALT_TAG, Some(_)) |
            // Know to happen to data that represent an memory location
            (flag::netnode::nn_res::ARRAY_SUP_TAG, Some(0x09)) |
            // Seem defined on procedures
            (flag::netnode::nn_res::ARRAY_SUP_TAG, Some(0x1000)) |
            // seems to be a code reference to memory, key is the destination memory
            (flag::nalt::x::NALT_CREF_FROM, Some(_)) |
            // The oposite of 'x', memory being referenced by an instruction
            (flag::nalt::x::NALT_CREF_TO, Some(_)) |
            // Seems to represent a XREF, key being the location that points to this address
            (flag::nalt::x::NALT_DREF_TO, Some(_)) |
            // The oposite of 'D", is a memory location that points to other
            (flag::nalt::x::NALT_DREF_FROM, Some(_)) |
            // other unknown values
            _ => Ok(Some((address, AddressInfo::Other { key: cursor, value: &current.value }))),
        }
    }
}

impl<'a, K: IDAKind> Iterator for AddressInfoIter<'a, K> {
    type Item = Result<(K::Usize, AddressInfo<'a, K>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_inner().transpose()
    }
}

#[derive(Clone, Copy)]
pub struct AddressInfoIterAt<'a, K: IDAKind> {
    iter: AddressInfoIter<'a, K>,
}

impl<'a, K: IDAKind> AddressInfoIterAt<'a, K> {
    pub fn new(iter: AddressInfoIter<'a, K>) -> Self {
        Self { iter }
    }
}

impl<'a, K: IDAKind> Iterator for AddressInfoIterAt<'a, K> {
    type Item = Result<AddressInfo<'a, K>>;

    fn next(&mut self) -> Option<Self::Item> {
        // ignore the address, it will always be the same, the one request
        self.iter.next().map(|x| x.map(|(_, x)| x))
    }
}

fn id_subkey_from_key<K: IDAKind>(
    mut cursor: &[u8],
) -> Option<(K::Usize, u8, Option<K::Usize>)> {
    let Some(b'.') = cursor.read_u8().ok() else {
        return None;
    };
    let Some(address) = K::Usize::from_bytes_reader::<BE>(&mut cursor).ok()
    else {
        return None;
    };
    let Some((sub_type, id)) = id_subkey_from_idx::<K>(cursor) else {
        return None;
    };
    Some((address, sub_type, id))
}

fn id_subkey_from_idx<K: IDAKind>(
    key: &[u8],
) -> Option<(u8, Option<K::Usize>)> {
    let (sub_type, id) = key.split_first()?;
    Some((*sub_type, K::Usize::from_bytes::<BE>(id)))
}

fn advance_region<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    mut regions: impl Iterator<Item = Result<FileRegions<K>>>,
) -> Result<Option<&'a [ID0Entry]>> {
    // get the next region
    let region = match regions.next() {
        Some(Ok(region)) => region,
        // if no more regions, finish the iter (AKA return None)
        None => return Ok(None),
        // return the error if err
        Some(Err(err)) => return Err(err),
    };
    Ok(Some(get_next_address_region(&region, &id0.all_entries())))
}

fn get_next_address_region<'a, K: IDAKind>(
    region: &FileRegions<K>,
    all_entries: &'a [ID0Entry],
) -> &'a [ID0Entry] {
    // get the next region
    let start_key: Vec<u8> =
        crate::id0::key_from_address::<K>(region.start).collect();
    let end_key: Vec<u8> =
        crate::id0::key_from_address::<K>(region.end).collect();
    let start = all_entries
        .binary_search_by_key(&&start_key[..], |b| &b.key[..])
        .unwrap_or_else(|start| start);
    let end = all_entries
        .binary_search_by_key(&&end_key[..], |b| &b.key[..])
        .unwrap_or_else(|end| end);

    &all_entries[start..end]
}

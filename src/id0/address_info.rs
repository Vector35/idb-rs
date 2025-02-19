use std::borrow::Cow;

use anyhow::{anyhow, Result};

use crate::til;

use super::{
    parse_maybe_cstr, FileRegionIter, FileRegions, ID0CStr, ID0Entry,
    ID0Section,
};

#[derive(Clone, Debug)]
pub enum AddressInfo<'a> {
    Comment(Comments<'a>),
    Label(Cow<'a, str>),
    TilType(til::Type),
    Other { key: &'a [u8], value: &'a [u8] },
}

#[derive(Clone, Debug)]
pub enum Comments<'a> {
    Comment(&'a [u8]),
    RepeatableComment(&'a [u8]),
    PreComment(&'a [u8]),
    PostComment(&'a [u8]),
}

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
pub struct SectionAddressInfoByAddressIter<'a> {
    id0: &'a ID0Section,
    regions: FileRegionIter<'a>,
    current_region: &'a [ID0Entry],
}

impl<'a> SectionAddressInfoByAddressIter<'a> {
    pub fn new(id0: &'a ID0Section, version: u16) -> Result<Self> {
        let idx = id0
            .file_regions_idx()
            .ok_or_else(|| anyhow!("Could not find $ fileregions"))?;
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
}

impl<'a> Iterator for SectionAddressInfoByAddressIter<'a> {
    type Item = Result<(u64, AddressInfoIter<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        // get the next address of the current region, if nothing, next region
        let Some(first) = self.current_region.first() else {
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

        let addr_len = if self.id0.is_64 { 8 } else { 4 };
        // 1.. because it starts with '.'
        let key_start = addr_len + 1;
        let key = &first.key[..key_start];
        let end = self
            .current_region
            .iter()
            .position(|e| !e.key.starts_with(&key))
            .unwrap_or(self.current_region.len());
        let (current_addr, rest) = self.current_region.split_at(end);
        self.current_region = rest;
        let address =
            super::parse_number(&key[1..], true, self.id0.is_64).unwrap();
        Some(Ok((address, AddressInfoIter::new(current_addr, &self.id0))))
    }
}

#[derive(Clone, Copy)]
pub struct SectionAddressInfoIter<'a> {
    id0: &'a ID0Section,
    regions: FileRegionIter<'a>,
    current_region: AddressInfoIter<'a>,
}

impl<'a> SectionAddressInfoIter<'a> {
    pub fn new(id0: &'a ID0Section, version: u16) -> Result<Self> {
        let idx = id0
            .file_regions_idx()
            .ok_or_else(|| anyhow!("Could not find $ fileregions"))?;
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

impl<'a> Iterator for SectionAddressInfoIter<'a> {
    type Item = Result<(u64, AddressInfo<'a>)>;

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
pub struct AddressInfoIter<'a> {
    id0: &'a ID0Section,
    entries: &'a [ID0Entry],
}

impl<'a> AddressInfoIter<'a> {
    pub fn new(entries: &'a [ID0Entry], section: &'a ID0Section) -> Self {
        Self {
            entries,
            id0: section,
        }
    }
}

impl<'a> Iterator for AddressInfoIter<'a> {
    type Item = Result<(u64, AddressInfo<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let (current, rest) = self.entries.split_first()?;
        self.entries = rest;
        let value = &current.value[..];
        // 1.. because it starts with '.'
        let addr_len = if self.id0.is_64 { 8 } else { 4 };
        let key_start = addr_len + 1;
        let address = super::parse_number(
            &current.key[1..key_start],
            true,
            self.id0.is_64,
        )
        .unwrap();
        let key = &current.key[key_start..];
        let Some((sub_type, id_value)) =
            id_subkey_from_idx(key, self.id0.is_64)
        else {
            return Some(Err(anyhow!("Missing SubType")));
        };

        // Non UTF-8 comment: "C:\\Documents and Settings\\Administrator\\\xb9\xd9\xc5\xc1 \xc8\xad\xb8\xe9\ls"
        // \xb9\xd9\xc5\xc1 \xc8\xad\xb8\xe9 = "바탕 화면" = "Desktop" in Korean encoded using Extended Unix Code
        #[allow(clippy::wildcard_in_or_patterns)]
        match (sub_type, id_value) {
            // Comments
            // NOTE
            // pre comments start at index 1000
            // post comments start at index 2000
            // if you create more then a 1000 pre/post comments ida start acting strange, BUG?
            (b'S', Some(1000..=1999)) => {
                let Some(comment) = parse_maybe_cstr(value) else {
                    return Some(Err(anyhow!("Pre-Comment is not valid CStr")));
                };
                Some(Ok((address, AddressInfo::Comment(Comments::PreComment(comment)))))
            },
            (b'S', Some(2000..=2999)) => {
                let Some(comment) = parse_maybe_cstr(value) else {
                    return Some(Err(anyhow!("Post-Comment is not valid CStr")));
                };
                Some(Ok((address, AddressInfo::Comment(Comments::PostComment(comment)))))
            },
            (b'S', Some(0x0)) => {
                let Some(comment) = parse_maybe_cstr(value) else {
                    return Some(Err(anyhow!("Comment is not valid CStr")));
                };
                Some(Ok((address, AddressInfo::Comment(Comments::Comment(comment)))))
            },
            // Repeatable comment
            (b'S', Some(0x1)) => {
                let Some(comment) = parse_maybe_cstr(value) else {
                    return Some(Err(anyhow!("Repeatable Comment is not valid CStr")));
                };
                Some(Ok((address, AddressInfo::Comment(Comments::RepeatableComment(comment)))))
            },

            // Type at this address
            (b'S', Some(0x3000)) => {
                // take the field names (optional?) and the continuation (optional!)
                let last = rest.iter().position(|entry| {
                    let Some((sub_type, id)) = entry.key[key_start..].split_first() else {
                        return true
                    };
                    let id_value = id_from_key(id, self.id0.is_64);
                    !matches!((*sub_type, id_value), (b'S', Some(0x3000..=0x3999)))
                }).unwrap_or(rest.len());
                self.entries = &rest[last..];
                // TODO enforce sequential index for the id?
                // get the entry for field names and rest of data
                let (fields, continuation) = match &rest[..last] {
                    [fields, rest @ ..] if matches!(id_subkey_from_idx(&fields.key[key_start..], self.id0.is_64), Some((b'S', Some(0x3001)))) => {
                        // convert the value into fields
                        // usually this string ends with \x00, but bmaybe there is no garanty for that.
                        let Some(value) = parse_maybe_cstr(&fields.value) else {
                            // TODO: maybe those fields are continuated by the next entry
                            return Some(Err(anyhow!("Incomplete Fields for TIL Type")));
                        };
                        let Some(fields) = crate::ida_reader::split_strings_from_array(value) else {
                            return Some(Err(anyhow!("Invalid Fields for TIL Type")));
                        };
                        (fields, rest)
                    }
                    rest => (vec![], rest),
                };

                // condensate the data into a single buffer
                let buf: Vec<u8> = current.value.iter().chain(continuation.iter().flat_map(|entry| &entry.value[..])).copied().collect();
                // create the raw type
                let til = match til::Type::new_from_id0(&buf[..], fields) {
                    Ok(til) => til,
                    Err(err) => return Some(Err(err)),
                };
                Some(Ok((address, AddressInfo::TilType(til))))
            },
            // field names and continuation in from the previous til type [citation needed]
            (b'S', Some(0x3001..=0x3999)) => {
                Some(Err(anyhow!("ID0 Til type info without a previous TIL type")))
            },

            // Name, aka a label to this memory address
            (b'N', None) => {
                let value = super::parse_cstr_or_subkey(value, self.id0.is_64);
                let label_raw = match value {
                    None => {
                        return Some(Err(anyhow!("Label is not a valid CStr or ID0 Ref")))
                    }
                    Some(ID0CStr::CStr(label_raw)) => Cow::Borrowed(label_raw),
                    Some(ID0CStr::Ref(label_ref)) => {
                        let entries = match self.id0.address_info_value(label_ref) {
                            Ok(entries) => entries,
                            Err(e) => return Some(Err(e)),
                        };
                        Cow::Owned(entries.iter().flat_map(|x| &x.value[..]).copied().collect())
                    },
                };
                let label = match label_raw {
                    Cow::Borrowed(x) => {
                        core::str::from_utf8(x).map_err(|_|
                            anyhow!("Label is not valid UTF-8")
                        ).map(Cow::Borrowed)
                    },
                    Cow::Owned(x) => {
                        String::from_utf8(x).map_err(|_| {
                            anyhow!("LabelRef is not valid UTF-8")
                        }).map(Cow::Owned)
                    },
                };
                match label {
                    Err(e) => Some(Err(e)),
                    Ok(label) => Some(Ok((address, AddressInfo::Label(label)))),
                }
            },

            // Seems related to datatype, maybe cstr, align and stuff like that
            (b'A', Some(_)) |
            // Know to happen to data that represent an memory location
            (b'S', Some(0x09)) |
            // Seem defined on procedures
            (b'S', Some(0x1000)) |
            // seems to be a code reference to memory, key is the destination memory
            (b'x', Some(_)) |
            // The oposite of 'x', memory being referenced by an instruction
            (b'X', Some(_)) |
            // Seems to represent a XREF, key being the location that points to this address
            (b'D', Some(_)) |
            // The oposite of 'D", is a memory location that points to other
            (b'd', Some(_)) |
            // other unknown values
            _ => Some(Ok((address, AddressInfo::Other { key, value }))),
        }
    }
}

#[derive(Clone, Copy)]
pub struct AddressInfoIterAt<'a> {
    iter: AddressInfoIter<'a>,
}

impl<'a> AddressInfoIterAt<'a> {
    pub fn new(iter: AddressInfoIter<'a>) -> Self {
        Self { iter }
    }
}

impl<'a> Iterator for AddressInfoIterAt<'a> {
    type Item = Result<AddressInfo<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        // ignore the address, it will always be the same, the one request
        self.iter.next().map(|x| x.map(|(_, x)| x))
    }
}

fn id_subkey_from_idx(key: &[u8], is_64: bool) -> Option<(u8, Option<u64>)> {
    let (sub_type, id) = key.split_first()?;
    Some((*sub_type, id_from_key(id, is_64)))
}

fn id_from_key(key: &[u8], is_64: bool) -> Option<u64> {
    if is_64 {
        <[u8; 8]>::try_from(key).ok().map(u64::from_be_bytes)
    } else {
        <[u8; 4]>::try_from(key)
            .ok()
            .map(u32::from_be_bytes)
            .map(u64::from)
    }
}

fn advance_region<'a>(
    id0: &'a ID0Section,
    mut regions: impl Iterator<Item = Result<FileRegions>>,
) -> Result<Option<&'a [ID0Entry]>> {
    // get the next region
    let region = match regions.next() {
        Some(Ok(region)) => region,
        // if no more regions, finish the iter (AKA return None)
        None => return Ok(None),
        // return the error if err
        Some(Err(err)) => return Err(err),
    };
    Ok(Some(get_next_address_region(
        &region,
        &id0.all_entries(),
        id0.is_64,
    )))
}

fn get_next_address_region<'a>(
    region: &FileRegions,
    all_entries: &'a [ID0Entry],
    is_64: bool,
) -> &'a [ID0Entry] {
    // get the next region
    let start_key: Vec<u8> =
        crate::id0::key_from_address(region.start, is_64).collect();
    let end_key: Vec<u8> =
        crate::id0::key_from_address(region.end, is_64).collect();
    let start = all_entries
        .binary_search_by_key(&&start_key[..], |b| &b.key[..])
        .unwrap_or_else(|start| start);
    let end = all_entries
        .binary_search_by_key(&&end_key[..], |b| &b.key[..])
        .unwrap_or_else(|end| end);

    &all_entries[start..end]
}

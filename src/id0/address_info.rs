use anyhow::{anyhow, Result};

use crate::til;

use super::{parse_maybe_cstr, ID0Entry, IDBFileRegions};

#[derive(Clone, Debug)]
pub enum AddressInfo<'a> {
    Comment(Comments<'a>),
    Label(&'a str),
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

pub(crate) struct SectionAddressInfoIter<'a, I: Iterator<Item = Result<IDBFileRegions>>> {
    all_entries: &'a [ID0Entry],
    regions: I,
    current_region: AddressInfoIter<'a>,
}

impl<'a, I: Iterator<Item = Result<IDBFileRegions>>> SectionAddressInfoIter<'a, I> {
    pub fn new(all_entries: &'a [ID0Entry], regions: I, is_64: bool) -> Self {
        Self {
            all_entries,
            regions,
            current_region: AddressInfoIter::new(&[], is_64),
        }
    }
}

impl<'a, I: Iterator<Item = Result<IDBFileRegions>> + 'a> Iterator
    for SectionAddressInfoIter<'a, I>
{
    type Item = Result<(u64, AddressInfo<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(next_addr_info) = self.current_region.next() else {
            // get the next region
            let region = match self.regions.next() {
                Some(Ok(region)) => region,
                // if no more regions, finish the iter (AKA return None)
                None => return None,
                // return the error if err
                Some(Err(err)) => return Some(Err(err)),
            };
            let is_64 = self.current_region.is_64;
            let start_key: Vec<u8> = crate::id0::key_from_address(region.start, is_64).collect();
            let end_key: Vec<u8> = crate::id0::key_from_address(region.end, is_64).collect();
            let start = self
                .all_entries
                .binary_search_by_key(&&start_key[..], |b| &b.key[..])
                .unwrap_or_else(|start| start);
            let end = self
                .all_entries
                .binary_search_by_key(&&end_key[..], |b| &b.key[..])
                .unwrap_or_else(|end| end);

            let entries = &self.all_entries[start..end];
            self.current_region = AddressInfoIter::new(entries, is_64);
            // try again using this new region
            return self.next();
        };
        Some(next_addr_info)
    }
}

pub(crate) struct AddressInfoIter<'a> {
    entries: &'a [ID0Entry],
    is_64: bool,
}

impl<'a> AddressInfoIter<'a> {
    pub fn new(entries: &'a [ID0Entry], is_64: bool) -> Self {
        Self { entries, is_64 }
    }
}

impl<'a> Iterator for AddressInfoIter<'a> {
    type Item = Result<(u64, AddressInfo<'a>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let (current, rest) = self.entries.split_first()?;
        self.entries = rest;
        let value = &current.value[..];
        // 1.. because it starts with '.'
        let addr_len = if self.is_64 { 8 } else { 4 };
        let key_start = addr_len + 1;
        let address = super::parse_number(&current.key[1..key_start], true, self.is_64).unwrap();
        let key = &current.key[key_start..];
        let Some((sub_type, id_value)) = id_subkey_from_idx(key, self.is_64) else {
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
                Some(Ok((address, AddressInfo::Comment(Comments::PreComment(comment)))))
            },
            (b'S', Some(0x0)) => {
                let Some(comment) = parse_maybe_cstr(value) else {
                    return Some(Err(anyhow!("Comment is not valid CStr")));
                };
                Some(Ok((address, AddressInfo::Comment(Comments::PreComment(comment)))))
            },
            // Repeatable comment
            (b'S', Some(0x1)) => {
                let Some(comment) = parse_maybe_cstr(value) else {
                    return Some(Err(anyhow!("Repeatable Comment is not valid CStr")));
                };
                Some(Ok((address, AddressInfo::Comment(Comments::PreComment(comment)))))
            },

            // Type at this address
            (b'S', Some(0x3000)) => {
                // take the field names (optional?) and the continuation (optional!)
                let last = rest.iter().position(|entry| {
                    let Some((sub_type, id)) = entry.key[key_start..].split_first() else {
                        return true
                    };
                    let id_value = id_from_key(id, self.is_64);
                    !matches!((*sub_type, id_value), (b'S', Some(0x3000..=0x3999)))
                }).unwrap_or(0);
                // TODO enforce sequential index for the id?
                // get the entry for field names and rest of data
                let (fields, continuation) = match &rest[..last] {
                    [fields, rest @ ..] if matches!(id_subkey_from_idx(&fields.key, self.is_64), Some((b'S', Some(0x3001)))) => {
                        // convert the value into fields
                        let Some(fields) = crate::ida_reader::split_strings_from_array(&fields.value) else {
                            return Some(Err(anyhow!("Invalid Fields for TIL Type")));
                        };
                        (Some(fields), rest)
                    }
                    rest => (None, rest),
                };
                self.entries = &rest[last..];

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
                let Some(label_raw) = parse_maybe_cstr(value) else {
                    return Some(Err(anyhow!("Label is not a valid CStr")));
                };
                let Some(label) = core::str::from_utf8(label_raw).ok() else {
                    return Some(Err(anyhow!("Label is not valid UTF-8")))
                };
                Some(Ok((address, AddressInfo::Label(label))))
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

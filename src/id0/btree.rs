use std::io::BufRead;

use anyhow::Result;

use crate::ida_reader::{IdbBufRead, IdbRead};

use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ID0Version {
    V15,
    V16,
    V20,
}

impl ID0Version {
    pub(crate) fn read(input: &mut impl BufRead) -> Result<Self> {
        let value = input.read_c_string_raw()?;
        match &value[..] {
            b"B-tree v 1.5 (C) Pol 1990" => Ok(Self::V15),
            b"B-tree v 1.6 (C) Pol 1990" => Ok(Self::V16),
            b"B-tree v2" => Ok(Self::V20),
            name => Err(anyhow!(
                "Unknown B-tree version: {}",
                String::from_utf8_lossy(name)
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ID0Header {
    // TODO handle the next_free_offset being the fist free page
    pub _next_free_offset: Option<NonZeroU32>,
    pub page_size: u16,
    // assuming None here means there are no entries in this ID0
    pub root_page: Option<NonZeroU32>,
    pub record_count: u32,
    pub page_count: u32,
    //pub unk12: u8,
    pub version: ID0Version,
}

impl ID0Header {
    pub(crate) fn read(
        input: &mut impl BufRead,
        buf: &mut Vec<u8>,
    ) -> Result<Self> {
        buf.resize(64, 0);
        input.read_exact(buf)?;
        // TODO handle the 15 version of the header:
        // {
        //    let next_free_offset: u16 = bincode::deserialize_from(&mut *input)?;
        //    let page_size: u16 = bincode::deserialize_from(&mut *input)?;
        //    let root_page: u16 = bincode::deserialize_from(&mut *input)?;
        //    let record_count: u32 = bincode::deserialize_from(&mut *input)?;
        //    let page_count: u16 = bincode::deserialize_from(&mut *input)?;
        //    let unk12: u8 = bincode::deserialize_from(&mut *input)?;
        //    let version = ID0Version::read(input)?;
        // }

        let mut buf_current = &buf[..];
        let next_free_offset: u32 =
            bincode::deserialize_from(&mut buf_current)?;
        let page_size: u16 = bincode::deserialize_from(&mut buf_current)?;
        let root_page: u32 = bincode::deserialize_from(&mut buf_current)?;
        let record_count: u32 = bincode::deserialize_from(&mut buf_current)?;
        let page_count: u32 = bincode::deserialize_from(&mut buf_current)?;
        let _unk12: u8 = bincode::deserialize_from(&mut buf_current)?;
        let version = ID0Version::read(&mut buf_current)?;
        // TODO maybe this is a u64/u32/u16
        let _unk1d = buf_current.read_u8()?;
        let header_len = 64 - buf_current.len();
        // TODO move this code out of here and use seek instead
        // read the rest of the page
        ensure!(page_size >= 64);
        buf.resize(page_size.into(), 0);
        input.read_exact(&mut buf[64..])?;
        // the rest of the header should be only zeros
        ensure!(
            buf[header_len..].iter().all(|b| *b == 0),
            "Extra data on the header was not parsed"
        );
        Ok(ID0Header {
            _next_free_offset: NonZeroU32::new(next_free_offset),
            page_size,
            root_page: NonZeroU32::new(root_page),
            record_count,
            page_count,
            version,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ID0Page {
    Index {
        preceding: Option<NonZeroU32>,
        entries: Vec<ID0PageIndex>,
    },
    Leaf(Vec<ID0Entry>),
}

#[derive(Debug, Clone)]
pub(crate) struct ID0PageIndex {
    page: Option<NonZeroU32>,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl ID0Page {
    fn read(page: &[u8], header: &ID0Header) -> Result<Self> {
        match header.version {
            ID0Version::V15 => Self::read_xx(
                page,
                header,
                4,
                Self::header_4,
                Self::index_header_4,
                Self::leaf_header_v15,
                Self::index_value_v1x,
                Self::leaf_value_v1x,
                Self::freeptr_v1x,
            ),
            ID0Version::V16 => Self::read_xx(
                page,
                header,
                6,
                Self::header_6,
                Self::index_header_6,
                Self::leaf_header_v16,
                Self::index_value_v1x,
                Self::leaf_value_v1x,
                Self::freeptr_v1x,
            ),
            ID0Version::V20 => Self::read_xx(
                page,
                header,
                6,
                Self::header_6,
                Self::index_header_6,
                Self::leaf_header_v20,
                Self::index_value_v20,
                Self::leaf_value_v20,
                Self::freeptr_v20,
            ),
        }
    }

    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn read_xx(
        page_buf: &[u8],
        id0_header: &ID0Header,
        entry_len: u16,
        header: fn(&mut &[u8]) -> Result<(Option<NonZeroU32>, u16)>,
        index_header: fn(&mut &[u8]) -> Result<(Option<NonZeroU32>, u16)>,
        leaf_header: fn(&mut &[u8]) -> Result<(u16, u16)>,
        index_value: fn(&mut &[u8]) -> Result<(Vec<u8>, Vec<u8>)>,
        leaf_value: fn(&mut &[u8]) -> Result<(Vec<u8>, Vec<u8>)>,
        freeptr: fn(&mut &[u8]) -> Result<u16>,
    ) -> Result<Self> {
        let mut input = page_buf;
        let (preceding, count) = header(&mut input)?;
        let min_data_pos = entry_len
            .checked_mul(count + 2)
            .ok_or_else(|| anyhow!("Invalid number of entries"))?;
        ensure!(
            min_data_pos <= id0_header.page_size,
            "ID0 page have more data then space available"
        );

        let mut data_offsets = (entry_len..).step_by(entry_len.into());
        let entry_offsets = (&mut data_offsets).take(count.into());
        // TODO is root always entry and never leaf?
        let entry = if preceding.is_some() {
            // index
            let entries = entry_offsets
                .map(|offset| {
                    input = &page_buf[offset.into()..];
                    let (page, recofs) = index_header(&mut input)?;
                    ensure!(
                        recofs >= min_data_pos,
                        "Invalid recofs value {recofs} >= {min_data_pos}"
                    );
                    ensure!(recofs < id0_header.page_size);
                    input = &page_buf[recofs.into()..];
                    let (key, value) = index_value(&mut input)?;
                    Ok(ID0PageIndex { page, key, value })
                })
                .collect::<Result<Vec<_>, _>>()?;
            ID0Page::Index { preceding, entries }
        } else {
            // leaf
            // keys are usually very similar to one another, so it reuses the last key
            // value to build the next
            let mut last_key = Vec::new();
            let entry = entry_offsets
                .map(|offset| {
                    input = &page_buf[offset.into()..];
                    let (indent, recofs) = leaf_header(&mut input)?;
                    if recofs == 0 {
                        // TODO this only happen in deleted entries?
                        // TODO have an option to diferenciate?
                        return Ok(ID0Entry {
                            key: vec![],
                            value: vec![],
                        });
                    }
                    ensure!(
                        recofs >= min_data_pos,
                        "Invalid recofs value {recofs} >= {min_data_pos}"
                    );
                    ensure!(recofs < id0_header.page_size);
                    input = &page_buf[recofs.into()..];
                    let (ext_key, value) = leaf_value(&mut input)?;

                    // keys may reutilize the start of the last key
                    let reused_key = last_key
                        .get(..indent.into())
                        .ok_or_else(|| anyhow!("key indent is too small"))?;
                    let key: Vec<u8> =
                        reused_key.iter().copied().chain(ext_key).collect();

                    // update the last key
                    last_key.clear();
                    last_key.extend(&key);

                    Ok(ID0Entry { key, value })
                })
                .collect::<Result<Vec<_>, _>>()?;
            ID0Page::Leaf(entry)
        };

        input = &page_buf[data_offsets.next().unwrap().into()..];
        // TODO what is the freeptr?
        let _freeptr = freeptr(&mut input)?;
        Ok(entry)
    }

    fn header_4(input: &mut &[u8]) -> Result<(Option<NonZeroU32>, u16)> {
        let preceding: u16 = bincode::deserialize_from(&mut *input)?;
        let count: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(preceding.into()), count))
    }

    fn header_6(input: &mut &[u8]) -> Result<(Option<NonZeroU32>, u16)> {
        let preceding: u32 = bincode::deserialize_from(&mut *input)?;
        let count: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(preceding), count))
    }

    fn index_header_4(input: &mut &[u8]) -> Result<(Option<NonZeroU32>, u16)> {
        let page: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(page.into()), recofs))
    }

    fn index_header_6(input: &mut &[u8]) -> Result<(Option<NonZeroU32>, u16)> {
        let page: u32 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(page), recofs))
    }

    fn leaf_header_v15(input: &mut &[u8]) -> Result<(u16, u16)> {
        let indent: u8 = bincode::deserialize_from(&mut *input)?;
        let _unknown1: u8 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent.into(), recofs))
    }

    fn leaf_header_v16(input: &mut &[u8]) -> Result<(u16, u16)> {
        let indent: u8 = bincode::deserialize_from(&mut *input)?;
        // TODO is this _unknown1 just part of indent (u16)?
        let _unknown1: u8 = bincode::deserialize_from(&mut *input)?;
        let _unknown2: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent.into(), recofs))
    }

    fn leaf_header_v20(input: &mut &[u8]) -> Result<(u16, u16)> {
        let indent: u16 = bincode::deserialize_from(&mut *input)?;
        let _unknown1: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent, recofs))
    }

    fn index_value_v1x(input: &mut &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let _unknown: u8 = input.read_u8()?;
        let key = input.read_bytes_len_u16()?;
        let value = input.read_bytes_len_u16()?;
        Ok((key, value))
    }

    fn index_value_v20(input: &mut &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = input.read_bytes_len_u16()?;
        let value = input.read_bytes_len_u16()?;
        Ok((key, value))
    }

    fn leaf_value_v1x(input: &mut &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let _unknown = input.read_u8()?;
        let key = input.read_bytes_len_u16()?;
        let value = input.read_bytes_len_u16()?;
        Ok((key, value))
    }

    fn leaf_value_v20(input: &mut &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = input.read_bytes_len_u16()?;
        let value = input.read_bytes_len_u16()?;
        Ok((key, value))
    }

    fn freeptr_v1x(input: &mut &[u8]) -> Result<u16> {
        let _unknown = input.read_u16()?;
        let freeptr = input.read_u16()?;
        Ok(freeptr)
    }

    fn freeptr_v20(input: &mut &[u8]) -> Result<u16> {
        let _unknown: u32 = bincode::deserialize_from(&mut *input)?;
        let freeptr: u16 = bincode::deserialize_from(input)?;
        Ok(freeptr)
    }
}

pub trait Id0AddressKey<K: IDAUsize> {
    // TODO fix this name
    fn as_u64(&self) -> K;
}

impl<K: IDAUsize> Id0AddressKey<K> for K {
    fn as_u64(&self) -> K {
        *self
    }
}

pub(crate) struct ID0BTree {
    pub header: ID0Header,
    pub pages: Option<ID0BTreePages>,
}

pub(crate) struct ID0BTreePages {
    pub root: NonZeroU32,
    pub pages: HashMap<NonZeroU32, ID0Page>,
}

impl ID0BTree {
    // NOTE this was written this way to validate the data in each file, so it's clear that no
    // data is being parsed incorrectly or is left unparsed. There way too many validations
    // and non-necessary parsing is done on delete data.
    pub(crate) fn read_inner(input: &[u8]) -> Result<Self> {
        let mut reader = input;

        // pages size are usually around that size
        let mut buf = Vec::with_capacity(0x2000);
        let header = ID0Header::read(&mut reader, &mut buf)?;

        let page_count: usize = header.page_count.try_into().unwrap();
        let page_size: usize = header.page_size.into();
        // in compressed sectors extra data can be present
        //ensure!(input.len() % page_size == 0);
        let pages_in_section = input.len() / page_size;
        // +1 for the header, some times there is more space then pages, usually empty pages at the end
        ensure!(page_count + 1 <= pages_in_section);

        let Some(root) = header.root_page else {
            ensure!(header.record_count == 0);
            // if root is not set, then the DB is empty
            return Ok(Self {
                header,
                pages: None,
            });
        };

        buf.resize(page_size, 0);
        let mut pages =
            HashMap::with_capacity(header.page_count.try_into().unwrap());
        let mut pending_pages = vec![root];
        loop {
            if pending_pages.is_empty() {
                break;
            }
            let page_idx = pending_pages.pop().unwrap();
            // if already parsed, ignore
            if pages.contains_key(&page_idx) {
                continue;
            }
            // read the full page
            ensure!((page_idx.get() as usize) < pages_in_section);
            let page_offset =
                page_idx.get() as usize * header.page_size as usize;
            let page_raw =
                &input[page_offset..page_offset + header.page_size as usize];
            let page = ID0Page::read(page_raw, &header)?;
            // put in the queue the pages that need parsing, AKA children of this page
            match &page {
                ID0Page::Index { preceding, entries } => {
                    pending_pages.extend(
                        entries
                            .iter()
                            .filter_map(|entry| entry.page)
                            .chain(*preceding),
                    );
                }
                ID0Page::Leaf(_) => {}
            }
            // insert the parsed page
            if let Some(_old) = pages.insert(page_idx, page) {
                unreachable!();
            }
        }

        // verify that the correct number of pages were consumed and added to the tree
        ensure!(pages.len() <= header.page_count.try_into().unwrap());

        // TODO verify why this is not true
        // verify that we read the correct number of entries
        //#[cfg(feature = "restrictive")]
        //{
        //    fn page_entry_num(
        //        pages: &HashMap<NonZeroU32, ID0Page>,
        //        page: &ID0Page,
        //    ) -> usize {
        //        match page {
        //            ID0Page::Index { preceding, entries } => {
        //                let preceding = preceding
        //                    .and_then(|preceding| pages.get(&preceding));
        //                let entries = entries
        //                    .iter()
        //                    .filter_map(|x| x.page)
        //                    .filter_map(|page_idx| pages.get(&page_idx));
        //                preceding
        //                    .into_iter()
        //                    .chain(entries)
        //                    .map(|entries| page_entry_num(pages, entries))
        //                    .sum()
        //            }
        //            ID0Page::Leaf(items) => items.len(),
        //        }
        //    }
        //    let entry_num = page_entry_num(&pages, pages.get(&root).unwrap());
        //    //ensure!(entry_num == usize::try_from(header.record_count).unwrap());
        //}

        Ok(Self {
            header,
            pages: Some(ID0BTreePages { root, pages }),
        })
    }

    pub(crate) fn into_vec(mut self) -> Vec<ID0Entry> {
        let mut output =
            Vec::with_capacity(self.header.record_count.try_into().unwrap());
        let Some(pages) = &mut self.pages else {
            return vec![];
        };
        pages.inner_into_vec(pages.root, &mut output);
        output
    }
}

impl ID0BTreePages {
    fn inner_into_vec(
        &mut self,
        page_idx: NonZeroU32,
        output: &mut Vec<ID0Entry>,
    ) {
        match self.pages.remove(&page_idx).unwrap() {
            ID0Page::Index { preceding, entries } => {
                if let Some(preceding) = preceding {
                    // if not root, add the preceding page before this one
                    self.inner_into_vec(preceding, &mut *output);
                }
                for ID0PageIndex { page, key, value } in entries {
                    output.push(ID0Entry { key, value });
                    if let Some(page) = page {
                        self.inner_into_vec(page, &mut *output);
                    }
                }
            }
            ID0Page::Leaf(entries) => output.extend(entries),
        }
    }
}

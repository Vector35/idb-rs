use std::io::{BufRead, BufReader, Cursor, ErrorKind, Seek, SeekFrom};
use std::num::NonZeroU32;

use crate::{read_bytes_len_u16, read_c_string_raw, IDBSectionCompression};

use anyhow::{anyhow, ensure, Result};

#[derive(Debug, Clone, Copy)]
enum ID0Version {
    V15,
    V16,
    V20,
}

impl ID0Version {
    pub(crate) fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let value = read_c_string_raw(input)?;
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
struct ID0Header {
    // TODO handle the next_free_offset being the fist free page
    _next_free_offset: Option<NonZeroU32>,
    page_size: u16,
    // assuming None here means there are no entries in this ID0
    root_page: Option<NonZeroU32>,
    record_count: u32,
    page_count: u32,
    //unk12: u8,
    version: ID0Version,
}

impl ID0Header {
    pub(crate) fn read<I: BufRead>(input: &mut I) -> Result<Self> {
        let mut buf = [0; 64];
        input.read_exact(&mut buf)?;
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

        let mut cursor = Cursor::new(&buf);
        let next_free_offset: u32 = bincode::deserialize_from(&mut cursor)?;
        let page_size: u16 = bincode::deserialize_from(&mut cursor)?;
        let root_page: u32 = bincode::deserialize_from(&mut cursor)?;
        let record_count: u32 = bincode::deserialize_from(&mut cursor)?;
        let page_count: u32 = bincode::deserialize_from(&mut cursor)?;
        let _unk12: u8 = bincode::deserialize_from(&mut cursor)?;
        let version = ID0Version::read(&mut cursor)?;
        // TODO move this code out of here and use seek instead
        // read the rest of the page
        ensure!(page_size >= 64);
        let mut buf = vec![0; usize::from(page_size) - 64];
        input.read_exact(&mut buf)?;
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
pub struct ID0Entry {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl ID0Entry {
    pub(crate) fn read<I: BufRead>(
        input: &mut I,
        compress: IDBSectionCompression,
    ) -> Result<Vec<Self>> {
        match compress {
            IDBSectionCompression::None => Self::read_inner(input),
            IDBSectionCompression::Zlib => {
                let mut input = BufReader::new(flate2::read::ZlibDecoder::new(input));
                Self::read_inner(&mut input)
            }
        }
    }

    // NOTE this was written this way to validate the data in each file, so it's clear that no
    // data is being parsed incorrectly or is left unparsed. There way too many validations
    // and non-necessary parsing is done on delete data.
    // TODO This is probably much more efficient if written with <I: BufRead + Seek>, this
    // way it's not necessary to read and cache the unused/deleted pages, if you are sure this
    // implementation is correct, you could rewrite this function to do that.
    fn read_inner<I: BufRead>(input: &mut I) -> Result<Vec<Self>> {
        let header = ID0Header::read(&mut *input)?;
        let mut buf = vec![0; header.page_size.into()];
        // NOTE sometimes deleted pages are included here, seems to happen specially if a
        // index is deleted with all it's leafs, leaving the now-empty index and the
        // now-disconnected children
        let mut pages = Vec::with_capacity(header.page_count.try_into().unwrap());
        loop {
            let read = read_exact_or_nothing(&mut *input, &mut buf)?;
            if read == 0 {
                // no more data, hit eof
                break;
            }
            if read != header.page_size.into() {
                // only read part of the page
                return Err(anyhow!("Found EoF in the middle of the page"));
            }
            // read the full page
            let page = ID0TreeEntrRaw::read(&buf, &header)?;
            pages.push(Some(page));
        }

        // verify for unused or duplicated entries
        let pages_tree = Self::create_tree(header.root_page, &mut pages)?;

        // verify that the correct number of pages were consumed and added to the tree
        let in_tree_pages = pages
            .iter()
            .map(Option::as_ref)
            .filter(Option::is_none)
            .count();
        ensure!(in_tree_pages == header.page_count.try_into().unwrap());

        // make sure only empty pages are left out-of-the-tree
        for page in pages.into_iter().flatten() {
            match page {
                ID0TreeEntrRaw::Leaf(leaf) if leaf.is_empty() => {}
                ID0TreeEntrRaw::Index { entries, .. } if entries.is_empty() => {}
                ID0TreeEntrRaw::Index {
                    preceeding,
                    entries,
                } => {
                    return Err(anyhow!(
                        "Extra Index preceeding {}, with {} entries",
                        preceeding.get(),
                        entries.len()
                    ))
                }
                ID0TreeEntrRaw::Leaf(entries) => {
                    let entries_len = entries
                        .iter()
                        .filter(|e| !e.key.is_empty() || !e.value.is_empty())
                        .count();
                    if entries_len != 0 {
                        return Err(anyhow!("Extra Leaf with {} entry", entries_len));
                    }
                }
            }
        }

        // put it all in order on the vector
        let mut entries = Vec::with_capacity(header.record_count.try_into().unwrap());
        Self::tree_to_vec(pages_tree, &mut entries);

        // make sure all entries are in the final vector
        ensure!(entries.len() == header.record_count.try_into().unwrap());

        Ok(entries)
    }

    fn create_tree(
        index: Option<NonZeroU32>,
        pages: &mut Vec<Option<ID0TreeEntrRaw>>,
    ) -> Result<ID0TreeEntry> {
        let Some(index) = index else {
            return Ok(ID0TreeEntry::Leaf(vec![]));
        };

        let index = usize::try_from(index.get()).unwrap() - 1;
        let entry = pages
            .get_mut(index)
            .ok_or_else(|| anyhow!("invalid page index: {index}"))?
            .take()
            .ok_or_else(|| anyhow!("page index {index} is referenciated multiple times"))?;
        match entry {
            ID0TreeEntrRaw::Leaf(leaf) => Ok(ID0TreeEntry::Leaf(leaf)),
            ID0TreeEntrRaw::Index {
                preceeding,
                entries,
            } => {
                let preceeding = Self::create_tree(Some(preceeding), &mut *pages)?;
                let index = entries
                    .into_iter()
                    .map(|e| {
                        let page = Self::create_tree(e.page, &mut *pages)?;
                        Ok(ID0TreeIndex {
                            page: Box::new(page),
                            key: e.key,
                            value: e.value,
                        })
                    })
                    .collect::<Result<_>>()?;
                Ok(ID0TreeEntry::Index {
                    preceeding: Box::new(preceeding),
                    index,
                })
            }
        }
    }

    fn tree_to_vec(entry: ID0TreeEntry, output: &mut Vec<ID0Entry>) {
        match entry {
            ID0TreeEntry::Index { preceeding, index } => {
                Self::tree_to_vec(*preceeding, &mut *output);
                for ID0TreeIndex { page, key, value } in index {
                    output.push(ID0Entry { key, value });
                    Self::tree_to_vec(*page, &mut *output);
                }
            }
            ID0TreeEntry::Leaf(entries) => output.extend(entries),
        }
    }
}

#[derive(Debug, Clone)]
enum ID0TreeEntry {
    Index {
        preceeding: Box<ID0TreeEntry>,
        index: Vec<ID0TreeIndex>,
    },
    Leaf(Vec<ID0Entry>),
}

#[derive(Debug, Clone)]
struct ID0TreeIndex {
    page: Box<ID0TreeEntry>,
    key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
enum ID0TreeEntrRaw {
    Index {
        preceeding: NonZeroU32,
        entries: Vec<ID0TreeIndexRaw>,
    },
    Leaf(Vec<ID0Entry>),
}

#[derive(Debug, Clone)]
struct ID0TreeIndexRaw {
    page: Option<NonZeroU32>,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl ID0TreeEntrRaw {
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

    fn read_xx(
        page: &[u8],
        id0_header: &ID0Header,
        entry_len: u16,
        header: fn(&mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)>,
        index_header: fn(&mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)>,
        leaf_header: fn(&mut Cursor<&[u8]>) -> Result<(u16, u16)>,
        index_value: fn(&mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)>,
        leaf_value: fn(&mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)>,
        freeptr: fn(&mut Cursor<&[u8]>) -> Result<u16>,
    ) -> Result<Self> {
        let mut input = Cursor::new(page);
        let (preceeding, count) = header(&mut input)?;
        let min_data_pos = entry_len
            .checked_mul(count + 2)
            .ok_or_else(|| anyhow!("Invalid number of entries"))?;
        ensure!(min_data_pos <= id0_header.page_size);

        let mut data_offsets = (entry_len..).step_by(entry_len.into());
        let entry_offsets = (&mut data_offsets).take(count.into());
        let entry = if let Some(preceeding) = preceeding {
            // index
            let entries = entry_offsets
                .map(|offset| {
                    input.seek(SeekFrom::Start(offset.into())).unwrap();
                    let (page, recofs) = index_header(&mut input)?;
                    ensure!(
                        recofs >= min_data_pos,
                        "Invalid recofs value {recofs} >= {min_data_pos}"
                    );
                    ensure!(recofs < id0_header.page_size);
                    input.seek(SeekFrom::Start(recofs.into())).unwrap();
                    let (key, value) = index_value(&mut input)?;
                    Ok(ID0TreeIndexRaw { page, key, value })
                })
                .collect::<Result<Vec<_>, _>>()?;
            ID0TreeEntrRaw::Index {
                preceeding,
                entries,
            }
        } else {
            // leaf
            // keys are usually very similar to one another, so it reuses the last key
            // value to build the next
            let mut last_key = Vec::new();
            let entry = entry_offsets
                .map(|offset| {
                    input.seek(SeekFrom::Start(offset.into())).unwrap();
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
                    input.seek(SeekFrom::Start(recofs.into())).unwrap();
                    let (ext_key, value) = leaf_value(&mut input)?;

                    // keys may reutilize the start of the last key
                    let reused_key = last_key
                        .get(..indent.into())
                        .ok_or_else(|| anyhow!("key indent is too small"))?;
                    let key: Vec<u8> = reused_key.iter().copied().chain(ext_key).collect();

                    // update the last key
                    last_key.clear();
                    last_key.extend(&key);

                    Ok(ID0Entry { key, value })
                })
                .collect::<Result<Vec<_>, _>>()?;
            ID0TreeEntrRaw::Leaf(entry)
        };

        input
            .seek(SeekFrom::Start(data_offsets.next().unwrap().into()))
            .unwrap();
        // TODO what is the freeptr?
        let _freeptr = freeptr(&mut input)?;
        Ok(entry)
    }

    fn header_4(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let preceeding: u16 = bincode::deserialize_from(&mut *input)?;
        let count: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(preceeding.into()), count))
    }

    fn header_6(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let preceeding: u32 = bincode::deserialize_from(&mut *input)?;
        let count: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(preceeding), count))
    }

    fn index_header_4(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let page: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(page.into()), recofs))
    }

    fn index_header_6(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let page: u32 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(page), recofs))
    }

    fn leaf_header_v15(input: &mut Cursor<&[u8]>) -> Result<(u16, u16)> {
        let indent: u8 = bincode::deserialize_from(&mut *input)?;
        let _unknown1: u8 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent.into(), recofs))
    }

    fn leaf_header_v16(input: &mut Cursor<&[u8]>) -> Result<(u16, u16)> {
        let indent: u8 = bincode::deserialize_from(&mut *input)?;
        // TODO is this _unknown1 just part of indent (u16)?
        let _unknown1: u8 = bincode::deserialize_from(&mut *input)?;
        let _unknown2: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent.into(), recofs))
    }

    fn leaf_header_v20(input: &mut Cursor<&[u8]>) -> Result<(u16, u16)> {
        let indent: u16 = bincode::deserialize_from(&mut *input)?;
        let _unknown1: u16 = bincode::deserialize_from(&mut *input)?;
        let recofs: u16 = bincode::deserialize_from(input)?;
        Ok((indent, recofs))
    }

    fn index_value_v1x(input: &mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let _unknown: u8 = bincode::deserialize_from(&mut *input)?;
        let key = read_bytes_len_u16(&mut *input)?;
        let value = read_bytes_len_u16(input)?;
        Ok((key, value))
    }

    fn index_value_v20(input: &mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = read_bytes_len_u16(&mut *input)?;
        let value = read_bytes_len_u16(input)?;
        Ok((key, value))
    }

    fn leaf_value_v1x(input: &mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let _unknown: u8 = bincode::deserialize_from(&mut *input)?;
        let key = read_bytes_len_u16(&mut *input)?;
        let value = read_bytes_len_u16(input)?;
        Ok((key, value))
    }

    fn leaf_value_v20(input: &mut Cursor<&[u8]>) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = read_bytes_len_u16(&mut *input)?;
        let value = read_bytes_len_u16(input)?;
        Ok((key, value))
    }

    fn freeptr_v1x(input: &mut Cursor<&[u8]>) -> Result<u16> {
        let _unknown: u16 = bincode::deserialize_from(&mut *input)?;
        let freeptr: u16 = bincode::deserialize_from(input)?;
        Ok(freeptr)
    }

    fn freeptr_v20(input: &mut Cursor<&[u8]>) -> Result<u16> {
        let _unknown: u32 = bincode::deserialize_from(&mut *input)?;
        let freeptr: u16 = bincode::deserialize_from(input)?;
        Ok(freeptr)
    }
}

fn read_exact_or_nothing<R: std::io::Read + ?Sized>(
    this: &mut R,
    mut buf: &mut [u8],
) -> std::io::Result<usize> {
    let len = buf.len();
    while !buf.is_empty() {
        match this.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(len - buf.len())
}

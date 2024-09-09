use std::io::{BufRead, Cursor, ErrorKind, Read, Seek, SeekFrom};
use std::num::NonZeroU32;

use crate::{read_bytes_len_u16, read_c_string_raw, IDBHeader, IDBSectionCompression};

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
    pub(crate) fn read<I: Read>(input: &mut I, buf: &mut Vec<u8>) -> Result<Self> {
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
        buf.resize(page_size.into(), 0);
        input.read_exact(&mut buf[64..])?;
        // the rest of the header should be only zeros
        ensure!(
            buf[64..].iter().all(|b| *b == 0),
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
pub struct ID0Section {
    is_64: bool,
    pub entries: Vec<ID0Entry>,
}

#[derive(Debug, Clone)]
pub struct ID0Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl ID0Section {
    pub(crate) fn read<I: Read>(
        input: &mut I,
        header: &IDBHeader,
        compress: IDBSectionCompression,
    ) -> Result<Self> {
        match compress {
            IDBSectionCompression::None => Self::read_inner(input, header),
            IDBSectionCompression::Zlib => {
                let mut input = flate2::read::ZlibDecoder::new(input);
                Self::read_inner(&mut input, header)
            }
        }
    }

    // NOTE this was written this way to validate the data in each file, so it's clear that no
    // data is being parsed incorrectly or is left unparsed. There way too many validations
    // and non-necessary parsing is done on delete data.
    // TODO This is probably much more efficient if written with <I: BufRead + Seek>, this
    // way it's not necessary to read and cache the unused/deleted pages, if you are sure this
    // implementation is correct, you could rewrite this function to do that.
    fn read_inner<I: Read>(input: &mut I, idb_header: &IDBHeader) -> Result<Self> {
        // pages size are usually around that size
        let mut buf = Vec::with_capacity(0x2000);
        let header = ID0Header::read(&mut *input, &mut buf)?;
        buf.resize(header.page_size.into(), 0);
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

        // verify for duplicated entries
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

        // make sure the vector is sorted
        ensure!(entries.windows(2).all(|win| {
            let [a, b] = win else { unreachable!() };
            a.key < b.key
        }));

        // make sure the right number of entries are in the final vector
        ensure!(entries.len() == header.record_count.try_into().unwrap());

        Ok(ID0Section {
            is_64: idb_header.magic_version.is_64(),
            entries,
        })
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

    fn binary_search(&self, key: impl AsRef<[u8]>) -> Result<usize, usize> {
        let key = key.as_ref();
        self.entries.binary_search_by(|b| b.key[..].cmp(&key))
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<&ID0Entry> {
        self.binary_search(key).ok().map(|i| &self.entries[i])
    }

    pub fn sub_values(&self, value: &[u8]) -> Result<impl Iterator<Item = &ID0Entry>> {
        let mut key: Vec<u8> = [b'.']
            .into_iter()
            .chain(value.iter().rev().copied())
            .chain([b'S'])
            .collect();
        let start = self.binary_search(&key);
        let start = match start {
            Ok(pos) => pos,
            Err(start) => start,
        };

        *key.last_mut().unwrap() = b'T';
        let end = self.binary_search(&key);
        let end = match end {
            Ok(pos) => pos,
            Err(end) => end,
        };

        ensure!(start <= end);
        ensure!(end <= self.entries.len());

        Ok(self.entries[start..end].iter())
    }

    pub fn segments<'a>(&'a self) -> Result<impl Iterator<Item = Result<Segment>> + 'a> {
        let entry = self
            .get("N$ segs")
            .ok_or_else(|| anyhow!("Unable to find entry segs"))?;
        Ok(self
            .sub_values(&entry.value)?
            .map(|e| Segment::read(&e.value, self.is_64)))
    }
}

#[derive(Clone, Debug)]
pub struct Segment {
    startea: u64,
    size: u64,
    name_id: u64,
    class_id: u64,
    orgbase: u64,
    flags: u32,
    align: u32,
    comb: u32,
    perm: u32,
    bitness: u32,
    seg_type: u32,
    selector: u64,
    defsr: [u64; 16],
    color: u32,
}

impl Segment {
    fn read(value: &[u8], is_64: bool) -> Result<Self> {
        let mut cursor = Cursor::new(value);
        let startea = parse_word(&mut cursor, is_64)?;
        let size = parse_word(&mut cursor, is_64)?;
        let name_id = parse_word(&mut cursor, is_64)?;
        let class_id = parse_word(&mut cursor, is_64)?;
        let orgbase = parse_word(&mut cursor, is_64)?;
        let flags = read_dd(&mut cursor)?;
        let align = read_dd(&mut cursor)?;
        let comb = read_dd(&mut cursor)?;
        let perm = read_dd(&mut cursor)?;
        let bitness = read_dd(&mut cursor)?;
        let seg_type = read_dd(&mut cursor)?;
        let selector = parse_word(&mut cursor, is_64)?;
        let defsr: Vec<_> = (0..16)
            .map(|_| parse_word(&mut cursor, is_64))
            .collect::<Result<_, _>>()?;
        let color = read_dd(&mut cursor)?;

        // TODO maybe new versions include extra information and thid check fails
        ensure!(cursor.position() == value.len().try_into().unwrap());
        Ok(Segment {
            startea,
            size,
            name_id,
            class_id,
            orgbase,
            flags,
            align,
            comb,
            perm,
            bitness,
            seg_type,
            selector,
            defsr: defsr.try_into().unwrap(),
            color,
        })
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

fn parse_word<I: Read>(input: &mut I, is_64: bool) -> Result<u64> {
    if is_64 {
        read_dq(input)
    } else {
        read_dd(input).map(u64::from)
    }
}

/// Reads 1 to 5 bytes.
fn read_dd<I: Read>(input: &mut I) -> Result<u32> {
    let header: u8 = bincode::deserialize_from(&mut *input)?;
    if header & 0x80 == 0 {
        return Ok(header.into());
    }

    if header & 0xC0 != 0xC0 {
        let low: u8 = bincode::deserialize_from(&mut *input)?;
        return Ok((u32::from(header) & 0x7F) << 8 | u32::from(low));
    }

    let data = if header & 0xE0 == 0xE0 {
        bincode::deserialize_from(&mut *input)?
    } else {
        let data: [u8; 3] = bincode::deserialize_from(&mut *input)?;
        [header & 0x3F, data[0], data[1], data[2]]
    };
    Ok(u32::from_be_bytes(data))
}

/// Reads 2 to 10 bytes.
fn read_dq<I: Read>(input: &mut I) -> Result<u64> {
    let lo = read_dd(&mut *input)?;
    let hi = read_dd(&mut *input)?;
    Ok((u64::from(hi) << 32) | u64::from(lo))
}

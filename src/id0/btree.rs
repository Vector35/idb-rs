use anyhow::Result;

use std::io::Cursor;

use super::*;

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
        // NOTE sometimes deleted pages are included here, seems to happen especially if an
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
                ID0TreeEntrRaw::Index { preceding, entries } => {
                    return Err(anyhow!(
                        "Extra Index preceding {}, with {} entries",
                        preceding.get(),
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
            .ok_or_else(|| anyhow!("page index {index} is referenced multiple times"))?;
        match entry {
            ID0TreeEntrRaw::Leaf(leaf) => Ok(ID0TreeEntry::Leaf(leaf)),
            ID0TreeEntrRaw::Index { preceding, entries } => {
                let preceding = Self::create_tree(Some(preceding), &mut *pages)?;
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
                    preceding: Box::new(preceding),
                    index,
                })
            }
        }
    }

    fn tree_to_vec(entry: ID0TreeEntry, output: &mut Vec<ID0Entry>) {
        match entry {
            ID0TreeEntry::Index { preceding, index } => {
                Self::tree_to_vec(*preceding, &mut *output);
                for ID0TreeIndex { page, key, value } in index {
                    output.push(ID0Entry { key, value });
                    Self::tree_to_vec(*page, &mut *output);
                }
            }
            ID0TreeEntry::Leaf(entries) => output.extend(entries),
        }
    }

    pub fn all_entries(&self) -> impl Iterator<Item = &ID0Entry> {
        self.entries.iter()
    }

    fn binary_search(&self, key: impl AsRef<[u8]>) -> Result<usize, usize> {
        let key = key.as_ref();
        self.entries.binary_search_by_key(&key, |b| &b.key[..])
    }

    fn binary_search_end(&self, key: impl AsRef<[u8]>) -> Result<usize, usize> {
        let key = key.as_ref();
        self.entries.binary_search_by(|b| {
            if b.key.starts_with(key) {
                std::cmp::Ordering::Less
            } else {
                b.key.as_slice().cmp(key)
            }
        })
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<&ID0Entry> {
        self.binary_search(key).ok().map(|i| &self.entries[i])
    }

    /// search for entries in this inclusive range
    pub fn get_inclusive_range(
        &self,
        start: impl AsRef<[u8]>,
        end: impl AsRef<[u8]>,
    ) -> impl Iterator<Item = &ID0Entry> {
        let start = self.binary_search(start).unwrap_or_else(|start| start);
        let end = self.binary_search_end(end).unwrap_or_else(|end| end);

        self.entries[start..end].iter()
    }

    pub fn sub_values(&self, key: impl AsRef<[u8]>) -> impl Iterator<Item = &ID0Entry> {
        let key = key.as_ref();
        let start = self.binary_search(key).unwrap_or_else(|start| start);
        let end = self.binary_search_end(key).unwrap_or_else(|end| end);

        self.entries[start..end].iter()
    }

    pub fn segments(&self) -> Result<impl Iterator<Item = Result<Segment>> + '_> {
        let entry = self
            .get("N$ segs")
            .ok_or_else(|| anyhow!("Unable to find entry segs"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        let names = self.segment_strings()?;
        Ok(self
            .sub_values(key)
            .map(move |e| Segment::read(&e.value, self.is_64, names.as_ref(), self)))
    }

    fn segment_strings(&self) -> Result<Option<HashMap<NonZeroU32, String>>> {
        let Some(entry) = self.get("N$ segstrings") else {
            // no entry means no strings
            return Ok(None);
        };
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        let mut entries = HashMap::new();
        for entry in self.sub_values(key) {
            let mut value = Cursor::new(&entry.value);
            let start = unpack_dd(&mut value)?;
            let end = unpack_dd(&mut value)?;
            ensure!(start > 0);
            ensure!(start <= end);
            for i in start..end {
                let name = unpack_ds(&mut value)?;
                if let Some(_old) = entries.insert(i.try_into().unwrap(), String::from_utf8(name)?)
                {
                    return Err(anyhow!("Duplicated id in segstrings {start}"));
                }
            }
            // TODO always end with '\x0a'?
            ensure!(
                usize::try_from(value.position()).unwrap() == entry.value.len(),
                "Unparsed data in SegsString: {}",
                entry.value.len() - usize::try_from(value.position()).unwrap()
            );
        }
        Ok(Some(entries))
    }

    pub(crate) fn name_by_index(&self, idx: u64) -> Result<&str> {
        // if there is no names, AKA `$ segstrings`, search for the key directly
        let key: Vec<u8> = b"."
            .iter()
            .copied()
            .chain(if self.is_64 {
                (idx | (0xFF << 56)).to_be_bytes().to_vec()
            } else {
                (u32::try_from(idx).unwrap() | (0xFF << 24))
                    .to_be_bytes()
                    .to_vec()
            })
            .chain(b"N".iter().copied())
            .collect();
        let name = self
            .get(key)
            .ok_or_else(|| anyhow!("Not found name for segment {idx}"))?;
        parse_maybe_cstr(&name.value).ok_or_else(|| anyhow!("Invalid segment name {idx}"))
    }

    pub fn loader_name(&self) -> Result<impl Iterator<Item = Result<&str>>> {
        let entry = self
            .get("N$ loader name")
            .ok_or_else(|| anyhow!("Unable to find entry loader name"))?;
        // TODO check that keys are 0 => plugin, or 1 => format
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        Ok(self
            .sub_values(key)
            .map(|e| Ok(CStr::from_bytes_with_nul(&e.value)?.to_str()?)))
    }

    pub fn root_info(&self) -> Result<impl Iterator<Item = Result<IDBRootInfo>>> {
        let entry = self
            .get("NRoot Node")
            .ok_or_else(|| anyhow!("Unable to find entry Root Node"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .copied()
            .collect();
        let key_len = key.len();
        Ok(self.sub_values(key).map(move |entry| {
            let sub_key = &entry.key[key_len..];
            let Some(sub_type) = sub_key.first().copied() else {
                return Ok(IDBRootInfo::Unknown(entry));
            };
            match (sub_type, sub_key.len()) {
                (b'N', 1) => {
                    ensure!(
                        parse_maybe_cstr(&entry.value) == Some("Root Node"),
                        "Invalid Root Node Name"
                    );
                    return Ok(IDBRootInfo::RootNodeName);
                }
                // TODO filenames can be non-utf-8, but are they always CStr?
                (b'V', 1) => return Ok(IDBRootInfo::InputFile(&entry.value)),
                _ => {}
            }
            let Some(value) = parse_number(&sub_key[1..], true, self.is_64) else {
                return Ok(IDBRootInfo::Unknown(entry));
            };
            match (sub_type, value as i64) {
                (b'A', -6) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse imagebase value"))
                    .map(IDBRootInfo::ImageBase),
                (b'A', -5) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse crc value"))
                    .map(IDBRootInfo::Crc),
                (b'A', -4) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse open_count value"))
                    .map(IDBRootInfo::OpenCount),
                (b'A', -2) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse CreatedDate value"))
                    .map(IDBRootInfo::CreatedDate),
                (b'A', -1) => parse_number(&entry.value, false, self.is_64)
                    .ok_or_else(|| anyhow!("Unable to parse Version value"))
                    .map(IDBRootInfo::Version),
                (b'S', 1302) => entry
                    .value
                    .as_slice()
                    .try_into()
                    .map(IDBRootInfo::Md5)
                    .map_err(|_| anyhow!("Value Md5 with invalid len")),
                (b'S', 1303) => parse_maybe_cstr(&entry.value)
                    .map(IDBRootInfo::VersionString)
                    .ok_or_else(|| anyhow!("Unable to parse VersionString string")),
                (b'S', 1349) => entry
                    .value
                    .as_slice()
                    .try_into()
                    .map(IDBRootInfo::Sha256)
                    .map_err(|_| anyhow!("Value Sha256 with invalid len")),
                (b'S', 0x41b994) => IDBParam::read(&entry.value, self.is_64)
                    .map(Box::new)
                    .map(IDBRootInfo::IDAInfo),
                _ => Ok(IDBRootInfo::Unknown(entry)),
            }
        }))
    }

    pub fn ida_info(&self) -> Result<IDBParam> {
        // TODO Root Node is always the last one?
        let entry = self
            .get("NRoot Node")
            .ok_or_else(|| anyhow!("Unable to find entry Root Node"))?;
        let sub_key = if self.is_64 {
            0x41B994u64.to_be_bytes().to_vec()
        } else {
            0x41B994u32.to_be_bytes().to_vec()
        };
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .chain(sub_key.iter())
            .copied()
            .collect();
        let description = self
            .sub_values(key)
            .next()
            .ok_or_else(|| anyhow!("Unable to find id_params inside Root Node"))?;
        IDBParam::read(&description.value, self.is_64)
    }

    pub fn file_regions(
        &self,
        version: u16,
    ) -> Result<impl Iterator<Item = Result<IDBFileRegions>> + '_> {
        let entry = self
            .get("N$ fileregions")
            .ok_or_else(|| anyhow!("Unable to find fileregions"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        let key_len = key.len();
        // TODO find the meaning of "$ fileregions" b'V' entries
        Ok(self.sub_values(key).map(move |e| {
            let key = &e.key[key_len..];
            IDBFileRegions::read(key, &e.value, version, self.is_64)
        }))
    }

    pub fn functions_and_comments(
        &self,
    ) -> Result<impl Iterator<Item = Result<FunctionsAndComments>>> {
        let entry = self
            .get("N$ funcs")
            .ok_or_else(|| anyhow!("Unable to find functions"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .copied()
            .collect();
        let key_len = key.len();
        Ok(self.sub_values(key).map(move |e| {
            let key = &e.key[key_len..];
            FunctionsAndComments::read(key, &e.value, self.is_64)
        }))
    }

    // TODO implement $ fixups
    // TODO implement $ imports
    // TODO implement $ scriptsnippets
    // TODO implement $ enums
    // TODO implement $ structs

    // TODO implement $ hidden_ranges
    // TODO the address_info for 0xff00_00XX (or 0xff00_0000__0000_00XX for 64bits) seesm to be reserved, what happens if there is data at that page?

    fn entry_points_raw(&self) -> Result<impl Iterator<Item = Result<EntryPointRaw>>> {
        let entry = self
            .get("N$ entry points")
            .ok_or_else(|| anyhow!("Unable to find functions"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .copied()
            .collect();
        let key_len = key.len();
        Ok(self.sub_values(key).map(move |e| {
            let key = &e.key[key_len..];
            EntryPointRaw::read(key, &e.value, self.is_64)
        }))
    }

    pub fn entry_points(&self) -> Result<Vec<EntryPoint>> {
        type RawEntryPoint<'a> = HashMap<u64, (Option<u64>, Option<&'a str>, Option<&'a str>)>;
        let mut entry_points: RawEntryPoint = HashMap::new();
        for entry_point in self.entry_points_raw()? {
            match entry_point? {
                EntryPointRaw::Unknown { .. }
                | EntryPointRaw::Name
                | EntryPointRaw::Ordinal { .. } => {}
                EntryPointRaw::Address { key, address } => {
                    if let Some(_old) = entry_points.entry(key).or_default().0.replace(address) {
                        return Err(anyhow!("Duplicated function address for {key}"));
                    }
                }
                EntryPointRaw::ForwardedSymbol { key, symbol } => {
                    if let Some(_old) = entry_points.entry(key).or_default().1.replace(symbol) {
                        return Err(anyhow!("Duplicated function symbol for {key}"));
                    }
                }
                EntryPointRaw::FunctionName { key, name } => {
                    if let Some(_old) = entry_points.entry(key).or_default().2.replace(name) {
                        return Err(anyhow!("Duplicated function name for {key}"));
                    }
                }
            }
        }
        let mut result: Vec<_> = entry_points
            .into_iter()
            .filter_map(
                |(key, (address, symbol, name))| match (address, symbol, name) {
                    // Function without name or address is possible, this is
                    // probably some label that got deleted
                    (Some(_), _, None) | (None, _, Some(_)) | (None, _, None) => None,
                    (Some(address), forwarded, Some(name)) => {
                        let entry = match self.find_entry_point_type(key, address) {
                            Ok(entry) => entry,
                            Err(error) => return Some(Err(error)),
                        };
                        Some(Ok(EntryPoint {
                            name: name.to_owned(),
                            address,
                            forwarded: forwarded.map(str::to_string),
                            entry_type: entry,
                        }))
                    }
                },
            )
            .collect::<Result<_, _>>()?;
        result.sort_by_key(|entry| entry.address);
        Ok(result)
    }

    fn find_entry_point_type(&self, key: u64, address: u64) -> Result<Option<til::Type>> {
        if let Some(key_entry) = self.find_entry_point_type_value(key, 0x3000)? {
            return Ok(Some(key_entry));
        }
        // TODO some times it uses the address as key, it's based on the version?
        if let Some(key_entry) = self.find_entry_point_type_value(address, 0x3000)? {
            return Ok(Some(key_entry));
        }
        Ok(None)
    }

    fn find_entry_point_type_value(&self, value: u64, key_find: u64) -> Result<Option<til::Type>> {
        let key: Vec<u8> = b"."
            .iter()
            .copied()
            .chain(if self.is_64 {
                value.to_be_bytes().to_vec()
            } else {
                u32::try_from(value).unwrap().to_be_bytes().to_vec()
            })
            .chain([b'S'])
            .collect();
        let key_len = key.len();
        for entry in self.sub_values(key) {
            let key = &entry.key[key_len..];
            let key = parse_number(key, true, self.is_64).unwrap();
            // TODO handle other values for the key
            if key == key_find {
                return til::Type::new_from_id0(&entry.value)
                    .map(Option::Some)
                    .map_err(|e| {
                        todo!("Error parsing {:#04x?}: {e:?}", &entry.value);
                    });
            }
        }
        Ok(None)
    }

    pub fn address_info(
        &self,
        version: u16,
    ) -> Result<impl Iterator<Item = Result<(u64, AddressInfo)>>> {
        let regions = self.file_regions(version)?;
        // TODO remove the Vec/for-loop here if you want to use `itertools::flatten_ok` or implement it yourself
        let mut info = vec![];
        for region in regions {
            let region = region?;
            let start_key = key_from_address(region.start, self.is_64);
            let end_key = key_from_address(region.end, self.is_64);
            let start = self.binary_search(&start_key).unwrap_or_else(|start| start);
            let end = self.binary_search(&end_key).unwrap_or_else(|end| end);

            let entries = &self.entries[start..end];
            info.extend(entries.iter().map(|entry| {
                let key = &entry.key[start_key.len()..];
                // 1.. because it starts with '.'
                let address =
                    parse_number(&entry.key[1..start_key.len()], true, self.is_64).unwrap();
                let info = address_info::AddressInfo::parse(key, &entry.value, self.is_64)?;
                Ok((address, info))
            }));
        }
        Ok(info.into_iter())
    }

    pub fn address_info_at(
        &self,
        address: u64,
    ) -> Result<impl Iterator<Item = Result<(u64, AddressInfo)>>> {
        let key = key_from_address(address, self.is_64);
        let start = self.binary_search(&key).unwrap_or_else(|start| start);
        let end = self.binary_search_end(&key).unwrap_or_else(|end| end);

        let entries = &self.entries[start..end];
        let key_len = key.len();
        Ok(entries.iter().map(move |entry| {
            let key = &entry.key[key_len..];
            // 1.. because it starts with '.'
            let address = parse_number(&entry.key[1..key.len()], true, self.is_64).unwrap();
            let info = address_info::AddressInfo::parse(key, &entry.value, self.is_64)?;
            Ok((address, info))
        }))
    }

    pub(crate) fn dirtree_from_name<T: FromDirTreeNumber>(
        &self,
        name: impl AsRef<[u8]>,
    ) -> Result<DirTreeEntry<T>> {
        let index = self
            .binary_search(name)
            .map_err(|_| anyhow!("Unable to find dirtree"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(self.entries[index].value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        let key_len = key.len();
        let mut sub_values = self.sub_values(key).map(|entry| {
            let raw_idx = parse_number(&entry.key[key_len..], true, self.is_64)
                .ok_or_else(|| anyhow!("invalid dirtree entry key"))?;
            ensure!(
                raw_idx & 0xFFFF == 0,
                "Invalid lower byte for dirtree entry key"
            );
            Ok((raw_idx >> 16, &entry.value[..]))
        });
        let dirs = dirtree::parse_dirtree(&mut sub_values, self.is_64)?;
        ensure!(sub_values.next().is_none(), "unparsed diretree entries");
        Ok(dirs)
    }

    // https://hex-rays.com/products/ida/support/idapython_docs/ida_dirtree.html

    // TODO remove the u64 and make it a TILOrdIndex type
    pub fn dirtree_tinfos(&self) -> Result<DirTreeEntry<u64>> {
        self.dirtree_from_name("N$ dirtree/tinfos")
    }

    // TODO remove the u64 and make it a TILOrdIndex type
    pub fn dirtree_structs(&self) -> Result<DirTreeEntry<u64>> {
        self.dirtree_from_name("N$ dirtree/structs")
    }

    // TODO remove the u64 and make it a TILOrdIndex type
    pub fn dirtree_enums(&self) -> Result<DirTreeEntry<u64>> {
        self.dirtree_from_name("N$ dirtree/enums")
    }

    // TODO remove the u64 and make it a FuncAddress type
    pub fn dirtree_funcs(&self) -> Result<DirTreeEntry<u64>> {
        self.dirtree_from_name("N$ dirtree/funcs")
    }

    // TODO remove the u64 and make it a NameAddress type
    pub fn dirtree_names(&self) -> Result<DirTreeEntry<u64>> {
        self.dirtree_from_name("N$ dirtree/names")
    }

    // TODO implement $ dirtree/imports
    // TODO implement $ dirtree/bpts
    // TODO implement $ dirtree/bookmarks_idaplace_t
    // TODO implement $ dirtree/bookmarks_structplace_t
    // TODO implement $ dirtree/bookmarks_tiplace_t
}

#[derive(Debug, Clone)]
enum ID0TreeEntry {
    Index {
        preceding: Box<ID0TreeEntry>,
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
        preceding: NonZeroU32,
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

    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
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
        let (preceding, count) = header(&mut input)?;
        let min_data_pos = entry_len
            .checked_mul(count + 2)
            .ok_or_else(|| anyhow!("Invalid number of entries"))?;
        ensure!(min_data_pos <= id0_header.page_size);

        let mut data_offsets = (entry_len..).step_by(entry_len.into());
        let entry_offsets = (&mut data_offsets).take(count.into());
        let entry = if let Some(preceding) = preceding {
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
            ID0TreeEntrRaw::Index { preceding, entries }
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
        let preceding: u16 = bincode::deserialize_from(&mut *input)?;
        let count: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(preceding.into()), count))
    }

    fn header_6(input: &mut Cursor<&[u8]>) -> Result<(Option<NonZeroU32>, u16)> {
        let preceding: u32 = bincode::deserialize_from(&mut *input)?;
        let count: u16 = bincode::deserialize_from(input)?;
        Ok((NonZeroU32::new(preceding), count))
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

fn key_from_address(address: u64, is_64: bool) -> Vec<u8> {
    b".".iter()
        .copied()
        .chain(if is_64 {
            address.to_be_bytes().to_vec()
        } else {
            u32::try_from(address).unwrap().to_be_bytes().to_vec()
        })
        .collect()
}

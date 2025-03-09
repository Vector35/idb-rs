use std::borrow::Cow;
use std::ffi::CStr;

use anyhow::Result;
use byteorder::{BE, LE};
use num_traits::{AsPrimitive, PrimInt, ToBytes};

use crate::{ida_reader::IdbReadKind, IDAUsize, IDAVariants, IDA32, IDA64};

use super::*;

pub type ID0SectionVariants = IDAVariants<ID0Section<IDA32>, ID0Section<IDA64>>;

#[derive(Debug, Clone)]
pub struct ID0Section<K: IDAKind> {
    // the data itself don't have a kind, but it's required to handle the data
    _kind: std::marker::PhantomData<K>,
    pub entries: Vec<ID0Entry>,
}

#[derive(Debug, Clone)]
pub struct ID0Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl<K: IDAKind> ID0Section<K> {
    pub(crate) fn read(
        input: &mut impl IdbReadKind<K>,
        compress: IDBSectionCompression,
    ) -> Result<Self> {
        ID0BTree::read(input, compress)
            .map(ID0BTree::into_vec)
            .map(|entries| Self {
                _kind: std::marker::PhantomData,
                entries,
            })
    }

    pub fn all_entries(&self) -> &[ID0Entry] {
        &self.entries
    }

    pub(crate) fn binary_search(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<usize, usize> {
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
    ) -> &[ID0Entry] {
        let start = self.binary_search(start).unwrap_or_else(|start| start);
        let end = self.binary_search_end(end).unwrap_or_else(|end| end);

        &self.entries[start..end]
    }

    pub fn sub_values(&self, key: impl AsRef<[u8]>) -> &[ID0Entry] {
        let key = key.as_ref();
        let start = self.binary_search(key).unwrap_or_else(|start| start);
        let end = self.binary_search_end(key).unwrap_or_else(|end| end);

        &self.entries[start..end]
    }

    pub(crate) fn address_info_value(
        &self,
        label_ref: K::Usize,
    ) -> Result<&[ID0Entry]> {
        // NOTE for some reasong the key is only 7 bytes,
        // there is also a subindex, in case the value is very big
        #[cfg(feature = "restrictive")]
        {
            let max_ref_value =
                <K::Usize as num_traits::Bounded>::max_value() >> 8;
            ensure!(
                label_ref <= max_ref_value,
                "Ivanlid Address Info value Ref"
            );
        }
        let label_ref = (label_ref << 8).to_be_bytes();
        let key: Vec<u8> = key_from_address_and_subtype::<K>(
            K::Usize::from(0xFFu8).swap_bytes(),
            b'S',
        )
        .chain(
            label_ref.as_ref()[0..label_ref.as_ref().len() - 1]
                .iter()
                .copied(),
        )
        .collect();
        Ok(self.sub_values(key))
    }

    /// read the `$ segs` entries of the database
    pub fn segments(&self) -> Result<SegmentIter<K>> {
        let entry = self
            .get("N$ segs")
            .ok_or_else(|| anyhow!("Unable to find entry segs"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        Ok(SegmentIter {
            _kind: std::marker::PhantomData,
            segments: self.sub_values(key),
        })
    }

    /// find the `$ segstrings`
    pub fn segment_strings_idx(&self) -> Option<SegmentStringsIdx> {
        self.get("N$ segstrings")
            .map(|x| SegmentStringsIdx(&x.value))
    }

    /// read all the `$ segstrings` entries of the database
    pub fn segment_strings(&self, idx: SegmentStringsIdx) -> SegmentStringIter {
        let key: Vec<u8> = b"."
            .iter()
            .chain(idx.0.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        SegmentStringIter::new(self.sub_values(key))
    }

    /// find the `$ patches`
    pub fn segment_patches_idx(&self) -> Option<SegmentPatchIdx> {
        self.get("N$ patches").map(|x| SegmentPatchIdx(&x.value))
    }

    /// read all the original values from `$ patches` entries of the database
    pub fn segment_patches_original_value(
        &self,
        idx: SegmentPatchIdx,
    ) -> SegmentPatchOriginalValueIter<K> {
        let key: Vec<u8> = b"."
            .iter()
            .chain(idx.0.iter().rev())
            .chain(b"A")
            .copied()
            .collect();
        let key_len = key.len();
        let entries = self.sub_values(key);
        SegmentPatchOriginalValueIter::new(entries, key_len)
    }

    // TODO there is also a "P" entry in patches, it seems to only contains
    // the value 0x01 for each equivalent "A" entry

    pub fn segment_name(&self, idx: SegmentNameIdx) -> Result<&[u8]> {
        let seg_idx = self.segment_strings_idx();
        // TODO I think this is dependent on the version, and not on availability
        if let Some(seg_idx) = seg_idx {
            for seg in self.segment_strings(seg_idx) {
                let (seg_idx, seg_value) = seg?;
                if seg_idx == idx {
                    return Ok(seg_value);
                }
            }
            Err(anyhow!("Unable to find ID0 Segment Name"))
        } else {
            // if there is no names, AKA `$ segstrings`, search for the key directly
            self.name_by_index(idx)
        }
    }

    pub(crate) fn name_by_index(&self, idx: SegmentNameIdx) -> Result<&[u8]> {
        // if there is no names, AKA `$ segstrings`, search for the key directly
        let key: Vec<u8> = key_from_address_and_subtype::<K>(
            K::Usize::from(0xFFu8).swap_bytes(),
            b'N',
        )
        .collect();
        let name = self
            .get(key)
            .ok_or_else(|| anyhow!("Not found name for segment {}", idx.0))?;
        parse_maybe_cstr(&name.value)
            .ok_or_else(|| anyhow!("Invalid segment name {}", idx.0))
    }

    /// read the `$ loader name` entries of the database
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
            .iter()
            .map(|e| Ok(CStr::from_bytes_with_nul(&e.value)?.to_str()?)))
    }

    pub fn root_info_node(&self) -> Result<NodeIdx<K>> {
        let entry = self
            .get("NRoot Node")
            .ok_or_else(|| anyhow!("Unable to find entry Root Node"))?;
        let node_idx = K::Usize::from_bytes::<LE>(&entry.value[..])
            .ok_or_else(|| anyhow!("Invalid Root Node key value"))?;
        Ok(NodeIdx(node_idx))
    }

    /// read the `Root Node` entries of the database
    pub fn root_info(
        &self,
        idx: NodeIdx<K>,
    ) -> Result<impl Iterator<Item = Result<IDBRootInfo<K>>>> {
        let key: Vec<u8> = key_from_address::<K>(idx.0).collect();
        let key_len = key.len();
        Ok(self.sub_values(key).iter().map(move |entry| {
            let sub_key = &entry.key[key_len..];
            let Some(sub_type) = sub_key.first().copied() else {
                return Ok(IDBRootInfo::Unknown(entry));
            };
            match (sub_type, sub_key.len()) {
                (b'N', 1) => {
                    ensure!(
                        parse_maybe_cstr(&entry.value)
                            == Some(&b"Root Node"[..]),
                        "Invalid Root Node Name"
                    );
                    return Ok(IDBRootInfo::RootNodeName);
                }
                // TODO filenames can be non-utf-8, but are they always CStr?
                (b'V', 1) => return Ok(IDBRootInfo::InputFile(&entry.value)),
                _ => {}
            }
            let Some(value) = K::Usize::from_bytes::<BE>(&sub_key[1..]) else {
                return Ok(IDBRootInfo::Unknown(entry));
            };
            match (sub_type, value.as_i64()) {
                (b'A', -6) => K::Usize::from_bytes::<LE>(&entry.value[..])
                    .ok_or_else(|| anyhow!("Unable to parse imagebase value"))
                    .map(ImageBase)
                    .map(IDBRootInfo::ImageBase),
                (b'A', -5) => K::Usize::from_bytes::<LE>(&entry.value[..])
                    .ok_or_else(|| anyhow!("Unable to parse crc value"))
                    .map(IDBRootInfo::Crc),
                (b'A', -4) => K::Usize::from_bytes::<LE>(&entry.value[..])
                    .ok_or_else(|| anyhow!("Unable to parse open_count value"))
                    .map(IDBRootInfo::OpenCount),
                (b'A', -2) => K::Usize::from_bytes::<LE>(&entry.value[..])
                    .ok_or_else(|| anyhow!("Unable to parse CreatedDate value"))
                    .map(IDBRootInfo::CreatedDate),
                (b'A', -1) => K::Usize::from_bytes::<LE>(&entry.value[..])
                    .ok_or_else(|| anyhow!("Unable to parse Version value"))
                    .map(IDBRootInfo::Version),
                (b'S', 1302) => entry
                    .value
                    .as_slice()
                    .try_into()
                    .map(IDBRootInfo::Md5)
                    .map_err(|_| anyhow!("Value Md5 with invalid len")),
                (b'S', 1303) => parse_maybe_cstr(&entry.value)
                    .and_then(|version| core::str::from_utf8(version).ok())
                    .ok_or_else(|| {
                        anyhow!("Unable to parse VersionString string")
                    })
                    .map(IDBRootInfo::VersionString),
                (b'S', 1349) => entry
                    .value
                    .as_slice()
                    .try_into()
                    .map(IDBRootInfo::Sha256)
                    .map_err(|_| anyhow!("Value Sha256 with invalid len")),
                (b'S', 0x41b994) => IDBParam::<K>::read(&entry.value)
                    .map(Box::new)
                    .map(IDBRootInfo::IDAInfo),
                _ => Ok(IDBRootInfo::Unknown(entry)),
            }
        }))
    }

    /// read the `Root Node` ida_info entry of the database
    pub fn ida_info(&self) -> Result<IDBParam<K>> {
        // TODO Root Node is always the last one?
        let entry = self.root_info_node()?;
        let sub_key = K::Usize::from(0x41B994u32);
        let key: Vec<u8> = key_from_address_and_subtype::<K>(entry.0, b'S')
            .chain(sub_key.to_be_bytes().as_ref().iter().copied())
            .collect();
        let description =
            self.sub_values(key).iter().next().ok_or_else(|| {
                anyhow!("Unable to find id_params inside Root Node")
            })?;
        IDBParam::<K>::read(&description.value)
    }

    /// read the `$ fileregions` entries of the database
    pub fn file_regions_idx(&self) -> Result<FileRegionIdx<K>> {
        let entry = self
            .get("N$ fileregions")
            .ok_or_else(|| anyhow!("Unable to find entry fileregions"))?;
        let node_idx = K::Usize::from_bytes::<LE>(&entry.value[..])
            .ok_or_else(|| anyhow!("Invalid fileregions key value"))?;
        Ok(FileRegionIdx(NodeIdx(node_idx)))
    }

    /// read the `$ fileregions` entries of the database
    pub fn file_regions(
        &self,
        idx: FileRegionIdx<K>,
        version: u16,
    ) -> FileRegionIter<K> {
        let key: Vec<u8> =
            key_from_address_and_subtype::<K>(idx.0 .0, b'S').collect();
        let key_len = key.len();
        // TODO find the meaning of "$ fileregions" b'V' entries
        let segments = self.sub_values(key);
        FileRegionIter {
            _kind: std::marker::PhantomData,
            segments,
            key_len,
            version,
        }
    }

    /// read the `$ funcs` entries of the database
    pub fn functions_and_comments(
        &self,
    ) -> Result<impl Iterator<Item = Result<FunctionsAndComments<'_, K>>>> {
        let entry = self
            .get("N$ funcs")
            .ok_or_else(|| anyhow!("Unable to find functions"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .copied()
            .collect();
        let key_len = key.len();
        Ok(self.sub_values(key).iter().map(move |e| {
            let key = &e.key[key_len..];
            FunctionsAndComments::read(key, &e.value)
        }))
    }

    // TODO implement $ fixups
    // TODO implement $ imports
    // TODO implement $ scriptsnippets
    // TODO implement $ enums
    // TODO implement $ structs

    // TODO implement $ hidden_ranges
    // TODO the address_info for 0xff00_00XX (or 0xff00_0000__0000_00XX for 64bits) seesm to be reserved, what happens if there is data at that page?

    fn entry_points_raw(
        &self,
    ) -> Result<impl Iterator<Item = Result<EntryPointRaw<'_, K>>>> {
        let entry = self
            .get("N$ entry points")
            .ok_or_else(|| anyhow!("Unable to find functions"))?;
        let key: Vec<u8> = b"."
            .iter()
            .chain(entry.value.iter().rev())
            .copied()
            .collect();
        let key_len = key.len();
        Ok(self.sub_values(key).iter().map(move |e| {
            let key = &e.key[key_len..];
            EntryPointRaw::read(key, &e.value)
        }))
    }

    /// read the `$ entry points` entries of the database
    pub fn entry_points(&self) -> Result<Vec<EntryPoint<K>>> {
        type RawEntryPoint<'a, K> =
            HashMap<K, (Option<K>, Option<&'a str>, Option<&'a str>)>;
        let mut entry_points: RawEntryPoint<'_, K::Usize> = HashMap::new();
        for entry_point in self.entry_points_raw()? {
            match entry_point? {
                EntryPointRaw::Unknown { .. }
                | EntryPointRaw::Name
                | EntryPointRaw::Ordinal { .. } => {}
                EntryPointRaw::Address { key, address } => {
                    if let Some(_old) =
                        entry_points.entry(key).or_default().0.replace(address)
                    {
                        return Err(anyhow!(
                            "Duplicated function address for {key}"
                        ));
                    }
                }
                EntryPointRaw::ForwardedSymbol { key, symbol } => {
                    if let Some(_old) =
                        entry_points.entry(key).or_default().1.replace(symbol)
                    {
                        return Err(anyhow!(
                            "Duplicated function symbol for {key}"
                        ));
                    }
                }
                EntryPointRaw::FunctionName { key, name } => {
                    if let Some(_old) =
                        entry_points.entry(key).or_default().2.replace(name)
                    {
                        return Err(anyhow!(
                            "Duplicated function name for {key}"
                        ));
                    }
                }
            }
        }
        let mut result: Vec<_> = entry_points
            .into_iter()
            .filter_map(|(key, (address, symbol, name))| {
                match (address, symbol, name) {
                    // Function without name or address is possible, this is
                    // probably some label that got deleted
                    (Some(_), _, None)
                    | (None, _, Some(_))
                    | (None, _, None) => None,
                    (Some(address), forwarded, Some(name)) => {
                        let entry =
                            match self.find_entry_point_type(key, address) {
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
                }
            })
            .collect::<Result<_, _>>()?;
        result.sort_by_key(|entry| entry.address);
        Ok(result)
    }

    fn find_entry_point_type(
        &self,
        key: K::Usize,
        address: K::Usize,
    ) -> Result<Option<til::Type>> {
        if let Some(key_entry) =
            self.find_entry_point_type_value(key, K::Usize::from(0x3000u16))?
        {
            return Ok(Some(key_entry));
        }
        // TODO some times it uses the address as key, it's based on the version?
        if let Some(key_entry) = self
            .find_entry_point_type_value(address, K::Usize::from(0x3000u16))?
        {
            return Ok(Some(key_entry));
        }
        Ok(None)
    }

    fn find_entry_point_type_value(
        &self,
        value: K::Usize,
        key_find: K::Usize,
    ) -> Result<Option<til::Type>> {
        let key: Vec<u8> =
            key_from_address_and_subtype::<K>(value, b'S').collect();
        let key_len = key.len();
        for entry in self.sub_values(key) {
            let key = &entry.key[key_len..];
            let key = K::Usize::from_bytes::<BE>(key).unwrap();
            // TODO handle other values for the key
            if key == key_find {
                return til::Type::new_from_id0(&entry.value, vec![])
                    .map(Option::Some);
            }
        }
        Ok(None)
    }

    /// read the address information for all addresses from `$ fileregions`
    pub fn address_info(
        &self,
        version: u16,
    ) -> Result<SectionAddressInfoIter<K>> {
        SectionAddressInfoIter::new(self, version)
    }

    /// read the address information for all addresses from `$ fileregions`
    pub fn address_info_by_address(
        &self,
        version: u16,
    ) -> Result<SectionAddressInfoByAddressIter<K>> {
        SectionAddressInfoByAddressIter::new(self, version)
    }

    /// read the address information for the address
    pub fn address_info_at(
        &self,
        address: impl Id0AddressKey<K::Usize>,
    ) -> Result<AddressInfoIterAt<K>> {
        let address = address.as_u64();
        let key: Vec<u8> = key_from_address::<K>(address).collect();
        let start = self.binary_search(&key).unwrap_or_else(|start| start);
        let end = self.binary_search_end(&key).unwrap_or_else(|end| end);

        let entries = &self.entries[start..end];
        Ok(AddressInfoIterAt::new(AddressInfoIter::new(entries, self)))
    }

    /// read the label set at address, if any
    pub fn label_at(
        &self,
        id0_addr: impl Id0AddressKey<K::Usize>,
    ) -> Result<Option<Cow<[u8]>>> {
        let key: Vec<u8> = key_from_address::<K>(id0_addr.as_u64())
            .chain(Some(b'N'))
            .collect();
        let Ok(start) = self.binary_search(&key) else {
            return Ok(None);
        };

        let entry = &self.entries[start];
        let key_len = key.len();
        let key = &entry.key[key_len..];
        ensure!(key.is_empty(), "Label ID0 entry with key");
        let label = ID0CStr::<'_, K>::parse_cstr_or_subkey(&entry.value)
            .ok_or_else(|| anyhow!("Label is not valid CStr"))?;
        match label {
            ID0CStr::CStr(label) => Ok(Some(Cow::Borrowed(label))),
            ID0CStr::Ref(label_ref) => {
                let entries = self.address_info_value(label_ref)?;
                Ok(Some(Cow::Owned(
                    entries
                        .iter()
                        .flat_map(|x| &x.value[..])
                        .copied()
                        .collect(),
                )))
            }
        }
    }

    pub fn struct_at(&self, idx: SubtypeId<K>) -> Result<&[u8]> {
        let key: Vec<u8> =
            key_from_address_and_subtype::<K>(idx.0, b'N').collect();
        let start = self.binary_search(&key).map_err(|_| {
            anyhow!("Unable to locate struct type for id0 entry")
        })?;

        let entry = &self.entries[start];
        // older versions dont have this prefix
        let value =
            entry.value.strip_prefix(b"$$ ").unwrap_or(&entry.value[..]);
        Ok(value)
    }

    pub(crate) fn dirtree_from_name<T: FromDirTreeNumber<K::Usize>>(
        &self,
        name: impl AsRef<[u8]>,
    ) -> Result<DirTreeRoot<T>> {
        let Ok(index) = self.binary_search(name) else {
            // if the entry is missin, it's probably just don't have entries
            return Ok(DirTreeRoot { entries: vec![] });
        };
        let key: Vec<u8> = b"."
            .iter()
            .chain(self.entries[index].value.iter().rev())
            .chain(b"S")
            .copied()
            .collect();
        let key_len = key.len();
        let mut sub_values = self.sub_values(key).iter().map(|entry| {
            let raw_idx = K::Usize::from_bytes::<BE>(&entry.key[key_len..])
                .ok_or_else(|| anyhow!("invalid dirtree entry key"))?;
            let idx = raw_idx >> 16;
            let sub_idx: u16 = (raw_idx & K::Usize::from(0xFFFFu16)).as_();
            Ok((idx, sub_idx, &entry.value[..]))
        });
        let dirs = dirtree::parse_dirtree::<'_, _, _, K>(&mut sub_values)?;
        ensure!(sub_values.next().is_none(), "unparsed diretree entries");
        Ok(dirs)
    }

    // https://hex-rays.com/products/ida/support/idapython_docs/ida_dirtree.html

    /// read the `$ dirtree/tinfos` entries of the database
    pub fn dirtree_tinfos(&self) -> Result<DirTreeRoot<Id0TilOrd>> {
        self.dirtree_from_name("N$ dirtree/tinfos")
    }

    // TODO remove the u64 and make it a TILOrdIndex type
    /// read the `$ dirtree/structs` entries of the database
    pub fn dirtree_structs(&self) -> Result<DirTreeRoot<K::Usize>> {
        self.dirtree_from_name("N$ dirtree/structs")
    }

    // TODO remove the u64 and make it a TILOrdIndex type
    /// read the `$ dirtree/enums` entries of the database
    pub fn dirtree_enums(&self) -> Result<DirTreeRoot<K::Usize>> {
        self.dirtree_from_name("N$ dirtree/enums")
    }

    // TODO remove the u64 and make it a FuncAddress type
    /// read the `$ dirtree/funcs` entries of the database
    pub fn dirtree_function_address(
        &self,
    ) -> Result<DirTreeRoot<Id0Address<K>>> {
        self.dirtree_from_name("N$ dirtree/funcs")
    }

    /// read the `$ dirtree/names` entries of the database
    pub fn dirtree_names(&self) -> Result<DirTreeRoot<Id0Address<K>>> {
        self.dirtree_from_name("N$ dirtree/names")
    }

    // TODO remove the u64 and make it a ImportIDX type
    /// read the `$ dirtree/imports` entries of the database
    pub fn dirtree_imports(&self) -> Result<DirTreeRoot<K::Usize>> {
        self.dirtree_from_name("N$ dirtree/imports")
    }

    // TODO remove the u64 and make it a BptsIDX type
    /// read the `$ dirtree/bpts` entries of the database
    pub fn dirtree_bpts(&self) -> Result<DirTreeRoot<K::Usize>> {
        self.dirtree_from_name("N$ dirtree/bpts")
    }

    // TODO remove the u64 and make it a &str type
    /// read the `$ dirtree/bookmarks_idaplace_t` entries of the database
    pub fn dirtree_bookmarks_idaplace(&self) -> Result<DirTreeRoot<K::Usize>> {
        self.dirtree_from_name("N$ dirtree/bookmarks_idaplace_t")
    }

    // TODO remove the u64 and make it a &str type
    /// read the `$ dirtree/bookmarks_structplace_t` entries of the database
    pub fn dirtree_bookmarks_structplace(
        &self,
    ) -> Result<DirTreeRoot<K::Usize>> {
        self.dirtree_from_name("N$ dirtree/bookmarks_structplace_t")
    }

    // TODO remove the u64 and make it a &str type
    /// read the `$ dirtree/bookmarks_tiplace_t` entries of the database
    pub fn dirtree_bookmarks_tiplace(&self) -> Result<DirTreeRoot<K::Usize>> {
        self.dirtree_from_name("N$ dirtree/bookmarks_tiplace_t")
    }
}

fn key_from_address_and_subtype<K: IDAKind>(
    address: K::Usize,
    subtype: u8,
) -> impl Iterator<Item = u8> {
    key_from_address::<K>(address).chain([subtype].into_iter())
}

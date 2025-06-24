use std::borrow::Cow;
use std::ffi::CStr;
use std::ops::Range;

use anyhow::Result;
use num_traits::{AsPrimitive, PrimInt, ToBytes};

use crate::addr_info::SubtypeId;
use crate::ida_reader::{IdbBufRead, IdbReadKind};
use crate::til;
use crate::{IDAVariants, SectionReader, IDA32, IDA64};

use super::entry_iter::{
    EntryTagContinuousSubkeys, NetnodeRangeIter, NetnodeSupRangeIter,
};
use super::flag::netnode::nn_res::*;
use super::flag::nsup::{E_NEXT, E_PREV};
use super::flag::ridx::*;
use super::function::*;
use super::*;

pub type ID0SectionVariants = IDAVariants<ID0Section<IDA32>, ID0Section<IDA64>>;

#[derive(Debug, Clone)]
pub struct ID0Section<K: IDAKind> {
    // the data itself don't have a kind, but it's required to handle the data
    _kind: std::marker::PhantomData<K>,
    pub(crate) entries: Vec<ID0Entry>,
}

#[derive(Debug, Clone)]
pub struct ID0Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct NetnodeIdx<K: IDAKind>(pub(crate) K::Usize);

impl<K: IDAKind> SectionReader<K> for ID0Section<K> {
    type Result = ID0Section<K>;

    fn read_section<I: IdbReadKind<K> + IdbBufRead>(
        input: &mut I,
    ) -> Result<Self::Result> {
        let mut output = vec![];
        input.read_to_end(&mut output)?;
        ID0BTree::read_inner(&output[..])
            .map(ID0BTree::into_vec)
            .map(|entries| Self {
                _kind: std::marker::PhantomData,
                entries,
            })
    }
}

impl<K: IDAKind> ID0Section<K> {
    pub fn all_entries(&self) -> &[ID0Entry] {
        &self.entries
    }

    /// Search and return the index for the key in the database
    fn binary_search(&self, key: &[u8]) -> Result<usize, usize> {
        self.entries.binary_search_by_key(&key, |b| &b.key[..])
    }

    /// Get the index of the next entry that don't match the key
    /// NOTE this could be out-of-index for the entries, normally used for
    /// range end
    fn binary_search_end(&self, key: &[u8]) -> usize {
        let idx = self.entries.binary_search_by(|b| {
            if b.key.starts_with(key) {
                std::cmp::Ordering::Less
            } else {
                b.key.as_slice().cmp(key)
            }
        });
        match idx {
            // This can never find the exact entry, because if it does, then it
            // just search for the next one
            Ok(_) => unreachable!(),
            Err(idx) => idx,
        }
    }

    /// Get the range for the index of all entries that match (start_with) the
    /// provided key
    fn binary_search_range(&self, key: &[u8]) -> Range<usize> {
        let start = match self.binary_search(&key) {
            Ok(idx) => idx,
            Err(idx) => {
                let entry_key = &self.entries[idx].key;
                if !entry_key.starts_with(key) {
                    // No entry match this key, empty range
                    return 0..0;
                }
                idx
            }
        };
        let end = self.binary_search_end(&key);
        start..end
    }

    fn first_idx(&self, key: &[u8]) -> Option<usize> {
        match self.binary_search(key) {
            // if found the exact entry return the entry index
            Ok(idx) => Some(idx),
            // if not found exact, check it's part of the netnode entry, if so
            // return it
            Err(idx) => {
                self.entries.get(idx)?.key.starts_with(key).then_some(idx)
            }
        }
    }

    fn last_idx(&self, key: &[u8]) -> Option<usize> {
        // get the end of the range
        let idx = self.binary_search_end(key);
        // -1 so we get the last entry of this range
        let idx_last = idx.checked_sub(1)?;
        // check this entry is part of the key
        self.entries[idx_last].key.starts_with(key).then_some(idx)
    }

    fn next_idx(&self, key: &[u8]) -> Option<usize> {
        let idx = self.binary_search_end(key);
        // only return true if is in-bound
        (self.entries.len() > idx).then_some(idx)
    }

    fn prev_idx(&self, key: &[u8]) -> Option<usize> {
        // if Found this netnode, get the previous one, unless it's the first
        // if Not found the netnode, just return the previous where it should be
        match self.binary_search(key) {
            Ok(idx) => idx.checked_sub(1),
            Err(idx) => idx.checked_sub(1),
        }
    }

    /// Get the database index for the provided node index, only return exact
    /// matches
    pub(crate) fn netnode_idx(&self, idx: NetnodeIdx<K>) -> Option<usize> {
        let key: Vec<u8> = key_from_netnode::<K>(idx.0).collect();
        self.binary_search(&key).ok()
    }

    /// Get the database index for the provided node index and alt, only
    /// return exact matches
    pub(crate) fn netnode_tag_idx(
        &self,
        idx: NetnodeIdx<K>,
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> = key_from_netnode_tag::<K>(idx.0, tag).collect();
        self.binary_search(&key).ok()
    }

    /// Get the database index for the provided node index, alt and tag, only
    /// return exact matches
    pub(crate) fn netnode_tag_alt_idx(
        &self,
        idx: NetnodeIdx<K>,
        alt: K::Usize,
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> =
            key_from_netnode_tag_alt::<K>(idx.0, tag, alt).collect();
        self.binary_search(&key).ok()
    }

    /// Get the database index for the provided node index, alt and tag, only
    /// return exact matches
    pub(crate) fn netnode_tag_hash_idx(
        &self,
        idx: NetnodeIdx<K>,
        hash: &[u8],
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> =
            key_from_netnode_tag_hash::<K>(idx.0, tag, hash).collect();
        self.binary_search(&key).ok()
    }

    /// Get the entry index for the first entry
    pub(crate) fn netnode_tag_first_idx(
        &self,
        idx: NetnodeIdx<K>,
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> = key_from_netnode_tag::<K>(idx.0, tag).collect();
        self.first_idx(&key)
    }

    /// Get the entry index for the last entry
    pub(crate) fn netnode_tag_last_idx(
        &self,
        idx: NetnodeIdx<K>,
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> = key_from_netnode_tag::<K>(idx.0, tag).collect();
        self.last_idx(&key)
    }

    /// Get the next entry index for the provided netnode.
    pub(crate) fn netnode_next_idx(&self, idx: NetnodeIdx<K>) -> Option<usize> {
        let key: Vec<u8> = key_from_netnode::<K>(idx.0).collect();
        self.next_idx(&key).and_then(|idx| {
            is_key_netnode(&self.entries[idx].key).then_some(idx)
        })
    }

    /// Get the next entry index for the provided netnode, tag and alt.
    /// returning only if is the same idx and tag
    pub(crate) fn netnode_tag_alt_next_idx(
        &self,
        idx: NetnodeIdx<K>,
        alt: K::Usize,
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> =
            key_from_netnode_tag_alt::<K>(idx.0, tag, alt).collect();
        let sub_key = &key[..key_len_netnode_tag::<K>()];
        let other_idx = self.next_idx(&key)?;
        let other_key = &self.entries[other_idx].key;
        other_key.starts_with(sub_key).then_some(other_idx)
    }

    fn netnode_is_same_tag(
        &self,
        key: &[u8],
        other_idx: usize,
    ) -> Option<usize> {
        let sub_key = &key[..key_len_netnode_tag::<K>()];
        let other_key = &self.entries[other_idx].key;
        other_key.starts_with(sub_key).then_some(other_idx)
    }

    /// Get the next entry index for the provided netnode, tag and hash.
    pub(crate) fn netnode_tag_hash_next_idx(
        &self,
        idx: NetnodeIdx<K>,
        hash: &[u8],
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> =
            key_from_netnode_tag_hash::<K>(idx.0, tag, hash).collect();
        let other_idx = self.next_idx(&key)?;
        self.netnode_is_same_tag(&key, other_idx)
    }

    /// Get the previous entry index for the provided netnode index,
    /// None means there is no previous netnode entry
    pub(crate) fn netnode_prev_idx(&self, idx: NetnodeIdx<K>) -> Option<usize> {
        let key: Vec<u8> = key_from_netnode::<K>(idx.0).collect();
        let prev_idx = self.prev_idx(&key)?;
        is_key_netnode(&self.entries[prev_idx].key).then_some(prev_idx)
    }

    /// Get the previous entry index for the provided netnode index and tag and
    /// alt, None means there is not previous entry in the same netnode and tag
    pub(crate) fn netnode_tag_alt_prev_idx(
        &self,
        idx: NetnodeIdx<K>,
        alt: K::Usize,
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> =
            key_from_netnode_tag_alt::<K>(idx.0, tag, alt).collect();
        let other_idx = self.prev_idx(&key)?;
        self.netnode_is_same_tag(&key, other_idx)
    }

    /// Get the previous entry index for the provided netnode index and tag and
    /// hash, None means there is not previous entry in the same netnode and tag
    pub(crate) fn netnode_tag_hash_prev_idx(
        &self,
        idx: NetnodeIdx<K>,
        hash: &[u8],
        tag: u8,
    ) -> Option<usize> {
        let key: Vec<u8> =
            key_from_netnode_tag_hash::<K>(idx.0, tag, hash).collect();
        let other_idx = self.prev_idx(&key)?;
        self.netnode_is_same_tag(&key, other_idx)
    }

    /// Get the entries range that match the provided netnode idx
    pub(crate) fn netnode_range_idx(&self, idx: NetnodeIdx<K>) -> Range<usize> {
        let key: Vec<u8> = key_from_netnode::<K>(idx.0).collect();
        self.binary_search_range(&key)
    }

    /// Get the entries range that match the provided netnode idx and tag
    pub(crate) fn netnode_tag_range_idx(
        &self,
        idx: NetnodeIdx<K>,
        tag: u8,
    ) -> Range<usize> {
        let key: Vec<u8> = key_from_netnode_tag::<K>(idx.0, tag).collect();
        self.binary_search_range(&key)
    }

    /// Get the Node index for a intry with the provided name
    pub fn netnode_idx_by_name(
        &self,
        name: &str,
    ) -> Result<Option<NetnodeIdx<K>>> {
        let key = format!("N{name}");
        self.binary_search(key.as_bytes())
            .ok()
            .map(|idx| {
                K::usize_try_from_le_bytes(&self.entries[idx].value)
                    .map(NetnodeIdx)
                    .ok_or_else(|| anyhow!("Invalid netnode IDX value"))
            })
            .transpose()
    }

    pub fn netnode(&self, idx: NetnodeIdx<K>) -> Option<(u8, &[u8], &[u8])> {
        let idx = self.netnode_idx(idx)?;
        let entry = &self.entries[idx];
        let key_len = key_len_netnode::<K>();
        let (tag, key) = entry.key[key_len..].split_first()?;
        Some((*tag, key, &entry.value[..]))
    }

    pub fn netnode_range(&self, idx: NetnodeIdx<K>) -> NetnodeRangeIter<'_, K> {
        let range = self.netnode_range_idx(idx);
        NetnodeRangeIter::new(&self.entries[range])
    }

    pub fn netnode_name(&self, idx: NetnodeIdx<K>) -> Option<&[u8]> {
        self.netnode_tag_idx(idx, NAME_TAG)
            .map(|i| &self.entries[i].value[..])
    }

    pub fn netnode_value(&self, idx: NetnodeIdx<K>) -> Option<&[u8]> {
        self.netnode_tag_idx(idx, VALUE_TAG)
            .map(|i| &self.entries[i].value[..])
    }

    pub fn sup_value(
        &self,
        idx: NetnodeIdx<K>,
        alt: K::Usize,
        tag: u8,
    ) -> Option<&[u8]> {
        self.netnode_tag_alt_idx(idx, alt, tag)
            .map(|idx| &self.entries[idx].value[..])
    }

    pub fn sup_first(
        &self,
        idx: NetnodeIdx<K>,
        tag: u8,
    ) -> Option<Result<(K::Usize, &[u8])>> {
        self.netnode_tag_first_idx(idx, tag).map(|i| {
            let key_len = key_len_netnode_tag::<K>();
            let entry = &self.entries[i];
            let key_raw = &entry.key[key_len..];
            let key = K::usize_try_from_be_bytes(key_raw)
                .ok_or_else(|| anyhow!("Invalid sup index key"))?;
            let value = &entry.value[..];
            Ok((key, value))
        })
    }

    pub fn sup_range(
        &self,
        idx: NetnodeIdx<K>,
        tag: u8,
    ) -> NetnodeSupRangeIter<'_, K> {
        let range = self.netnode_tag_range_idx(idx, tag);
        NetnodeSupRangeIter::new(&self.entries[range])
    }

    pub fn char_value(
        &self,
        idx: NetnodeIdx<K>,
        alt: K::Usize,
        tag: u8,
    ) -> Option<u8> {
        self.sup_value(idx, alt, tag)
            .and_then(|value| (value.len() == 1).then_some(value[0]))
    }

    pub fn hash_value<'a>(
        &'a self,
        idx: NetnodeIdx<K>,
        alt: &[u8],
        tag: u8,
    ) -> Option<&'a [u8]> {
        self.netnode_tag_hash_idx(idx, alt, tag)
            .map(|idx| &self.entries[idx].value[..])
    }

    pub fn hash_range<'a>(
        &'a self,
        idx: NetnodeIdx<K>,
        alt: &[u8],
        tag: u8,
    ) -> &'a [ID0Entry] {
        let key: Vec<u8> =
            key_from_netnode_tag_hash::<K>(idx.0, tag, alt).collect();
        let range = self.binary_search_range(&key);
        &self.entries[range]
    }

    pub fn blob<'a>(
        &'a self,
        idx: NetnodeIdx<K>,
        start: K::Usize,
        tag: u8,
    ) -> impl Iterator<Item = u8> + use<'a, K> {
        EntryTagContinuousSubkeys::<'_, K>::new(self, idx, tag, start)
            .flat_map(|entry| &entry.value[..])
            .copied()
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
                "Invalid Address Info value Ref"
            );
        }
        let label_ref = (label_ref << 8).to_be_bytes();
        Ok(self.hash_range(
            // TODO this should probably recovered from somwere in the ID0
            NetnodeIdx(K::Usize::from(0xFFu8).swap_bytes()),
            &label_ref.as_ref()[0..label_ref.as_ref().len() - 1],
            ARRAY_SUP_TAG,
        ))
    }

    /// read the `$ segs` entries of the database
    pub fn segments_idx(&self) -> Result<Option<SegmentIdx<K>>> {
        self.netnode_idx_by_name("$ segs")
            .map(|x| x.map(|x| SegmentIdx(x.0)))
    }

    pub fn segments(&self, idx: SegmentIdx<K>) -> SegmentIter<K> {
        let segments = self.sup_range(idx.into(), ARRAY_SUP_TAG);
        SegmentIter {
            _kind: std::marker::PhantomData,
            segments: segments.entries,
        }
    }

    /// find the `$ segstrings`
    pub fn segment_strings_idx(&self) -> Result<Option<SegmentStringsIdx<K>>> {
        self.netnode_idx_by_name("$ segstrings")
            .map(|opt_idx| opt_idx.map(|idx| SegmentStringsIdx(idx.0)))
    }

    /// read all the `$ segstrings` entries of the database
    pub fn segment_strings(
        &self,
        idx: SegmentStringsIdx<K>,
    ) -> SegmentStringIter {
        let range = self.sup_range(idx.into(), ARRAY_SUP_TAG);
        SegmentStringIter::new(range.entries)
    }

    /// find the `$ patches`
    pub fn segment_patches_idx(&self) -> Result<Option<SegmentPatchIdx<K>>> {
        self.netnode_idx_by_name("$ patches")
            .map(|opt_idx| opt_idx.map(|idx| SegmentPatchIdx(idx.0)))
    }

    /// read all the original values from `$ patches` entries of the database
    pub fn segment_patches_original_value(
        &self,
        idx: SegmentPatchIdx<K>,
    ) -> SegmentPatchOriginalValueIter<K> {
        let range =
            self.sup_range(idx.into(), flag::netnode::nn_res::ARRAY_ALT_TAG);
        SegmentPatchOriginalValueIter::new(range.entries)
    }

    // TODO there is also a "P" entry in patches, it seems to only contains
    // the value 0x01 for each equivalent "A" entry

    pub fn segment_name(&self, idx: SegmentNameIdx) -> Result<&[u8]> {
        let seg_idx = self.segment_strings_idx()?;
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
        let name_idx = self
            .netnode_tag_idx(
                NetnodeIdx(K::Usize::from(0xFFu8).swap_bytes()),
                NAME_TAG,
            )
            .ok_or_else(|| anyhow!("Not found name for segment {}", idx.0))?;
        parse_maybe_cstr(&self.entries[name_idx].value)
            .ok_or_else(|| anyhow!("Invalid segment name {}", idx.0))
    }

    /// read the `$ loader name` entries of the database
    pub fn loader_name(
        &self,
    ) -> Result<Option<impl Iterator<Item = Result<&str>>>> {
        let Some(entry) = self.netnode_idx_by_name("$ loader name")? else {
            return Ok(None);
        };
        // TODO check that keys are 0 => plugin, or 1 => format
        let entries = self.sup_range(entry.into(), ARRAY_SUP_TAG).entries;
        Ok(Some(entries.iter().map(|e| {
            Ok(CStr::from_bytes_with_nul(&e.value)?.to_str()?)
        })))
    }

    pub fn root_node(&self) -> Result<RootNodeIdx<K>> {
        let node_idx = self
            .netnode_idx_by_name("Root Node")?
            .ok_or_else(|| anyhow!("Unable to find entry Root Node"))?;
        Ok(RootNodeIdx(node_idx.0))
    }

    fn root_node_value(
        &self,
        idx: RootNodeIdx<K>,
        value: i32,
        tag: u8,
    ) -> Option<&[u8]> {
        let alt: K::Usize = <K::Isize as From<i32>>::from(value).as_();
        self.sup_value(idx.into(), alt, tag)
    }

    fn root_info_range(
        &self,
        idx: RootNodeIdx<K>,
        tag: u8,
        alt: u32,
        max_len: usize,
    ) -> Result<impl Iterator<Item = (u8, &[u8])>> {
        let alt = <K::Usize as From<u32>>::from(alt);
        Ok(
            EntryTagContinuousSubkeys::<'_, K>::new(self, idx.into(), tag, alt)
                .take(max_len)
                .map(move |entry| {
                    let key =
                        K::usize_try_from_be_bytes(&entry.key).unwrap() - alt;
                    (key.try_into().unwrap(), &entry.value[..])
                }),
        )
    }

    pub fn input_file(&self, idx: RootNodeIdx<K>) -> Option<&[u8]> {
        self.netnode_value(idx.into())
    }

    // TODO identify the data
    /// output file encoding index
    #[allow(dead_code)]
    pub(crate) fn output_file_encoding_idx(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_ALT_OUTFILEENC, ARRAY_ALT_TAG)
    }

    /// input file size
    pub fn input_file_size(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<Option<K::Usize>> {
        let Some(value_raw) =
            self.root_node_value(idx, RIDX_ALT_FSIZE, ARRAY_ALT_TAG)
        else {
            return Ok(None);
        };
        let value = K::usize_try_from_le_bytes(value_raw)
            .ok_or_else(|| anyhow!("Unable to parse imagebase value"))?;
        Ok(Some(value))
    }

    // TODO identify the data
    /// ids modnode id (for import_module)
    #[allow(dead_code)]
    pub(crate) fn ids_modenode_id(&self, idx: RootNodeIdx<K>) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_ALT_IDSNODE, ARRAY_ALT_TAG)
    }

    /// image base, AKA the offset between address and netnode value
    pub fn image_base(&self, idx: RootNodeIdx<K>) -> Result<ImageBase<K>> {
        let Some(value_raw) =
            self.root_node_value(idx, RIDX_ALT_IMAGEBASE, ARRAY_ALT_TAG)
        else {
            // No Image base, so id0 netnodes and addrs are the same
            return Ok(ImageBase(0u8.into()));
        };
        let value = K::usize_try_from_le_bytes(value_raw)
            .ok_or_else(|| anyhow!("Unable to parse imagebase value"))?;
        Ok(ImageBase(value))
    }

    /// input file crc32
    pub fn input_file_crc32(&self, idx: RootNodeIdx<K>) -> Result<Option<u32>> {
        let Some(value_raw) =
            self.root_node_value(idx, RIDX_ALT_CRC32, ARRAY_ALT_TAG)
        else {
            return Ok(None);
        };
        let value = K::usize_try_from_le_bytes(value_raw)
            .and_then(|value| <K::Usize as TryInto<u32>>::try_into(value).ok())
            .ok_or_else(|| anyhow!("Unable to parse file_input crc32 value"))?;
        Ok(Some(value))
    }

    /// how many times the database is opened
    pub fn database_num_opens(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<Option<K::Usize>> {
        let Some(value_raw) =
            self.root_node_value(idx, RIDX_ALT_NOPENS, ARRAY_ALT_TAG)
        else {
            return Ok(None);
        };
        let value = K::usize_try_from_le_bytes(value_raw)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| anyhow!("Unable to parse number of id0 opens"))?;
        Ok(value)
    }

    /// seconds database stayed open
    pub fn database_secs_opens(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<Option<K::Usize>> {
        let Some(value_raw) =
            self.root_node_value(idx, RIDX_ALT_ELAPSED, ARRAY_ALT_TAG)
        else {
            return Ok(None);
        };
        let value = K::usize_try_from_le_bytes(value_raw)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| {
                anyhow!("Unable to parse number of id0 seconds opens")
            })?;
        Ok(value)
    }

    /// database creation timestamp
    pub fn database_creation_time(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<Option<K::Usize>> {
        let Some(value_raw) =
            self.root_node_value(idx, RIDX_ALT_CTIME, ARRAY_ALT_TAG)
        else {
            return Ok(None);
        };
        let value = K::usize_try_from_le_bytes(value_raw)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| {
                anyhow!("Unable to parse the database creation time")
            })?;
        Ok(value)
    }

    /// initial version of database
    pub fn database_initial_version(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<Option<K::Usize>> {
        let Some(value_raw) =
            self.root_node_value(idx, RIDX_ALT_VERSION, ARRAY_ALT_TAG)
        else {
            return Ok(None);
        };
        let value = K::usize_try_from_le_bytes(value_raw)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| {
                anyhow!(
                    "Unable to parse number of the database initial version"
                )
            })?;
        Ok(value)
    }

    // TODO identify the data
    /// user-closed source files
    #[allow(dead_code)]
    pub(crate) fn user_closed_source_files(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<impl Iterator<Item = (u8, &[u8])>> {
        // TODO check the TAG
        self.root_info_range(idx, ARRAY_SUP_TAG, RIDX_SRCDBG_UNDESIRED, 20)
    }

    // TODO identify the data
    /// problem lists
    #[allow(dead_code)]
    pub(crate) fn problem_lists(&self, idx: RootNodeIdx<K>) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_PROBLEMS as i32, ARRAY_SUP_TAG)
    }

    // TODO identify the data
    /// Archive file path
    #[allow(dead_code)]
    pub(crate) fn archive_file_path(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_ARCHIVE_PATH as i32, ARRAY_SUP_TAG)
    }

    // TODO identify the data
    /// ABI name (processor specific)
    #[allow(dead_code)]
    pub(crate) fn abi_name(&self, idx: RootNodeIdx<K>) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_ABINAME as i32, ARRAY_SUP_TAG)
    }

    // TODO identify the data
    /// SHA256 of the input file
    pub fn input_file_sha256(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<Option<&[u8; 32]>> {
        self.root_node_value(idx, RIDX_SHA256 as i32, ARRAY_SUP_TAG)
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| anyhow!("Invalid SHA256 value len"))
            })
            .transpose()
    }

    /// unused, is menationed on the SDK v9.1
    #[allow(dead_code)]
    pub(crate) fn debug_binary_paths(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<impl Iterator<Item = (u8, &[u8])>> {
        self.root_info_range(idx, ARRAY_SUP_TAG, RIDX_DBG_BINPATHS, 20)
    }

    // TODO identify the data
    /// source debug paths
    #[allow(dead_code)]
    pub(crate) fn source_debug_paths(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<impl Iterator<Item = (u8, &[u8])>> {
        self.root_info_range(idx, ARRAY_SUP_TAG, RIDX_SRCDBG_PATHS, 20)
    }

    // TODO identify the data
    /// A list of encodings for the program strings
    #[allow(dead_code)]
    pub(crate) fn strings_encodings(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_STR_ENCODINGS as i32, ARRAY_SUP_TAG)
    }

    /// version of ida which created the database
    pub fn database_creation_version(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<Cow<str>> {
        self.root_node_value(idx, RIDX_IDA_VERSION as i32, ARRAY_SUP_TAG)
            .map(|value| String::from_utf8_lossy(value))
    }

    /// MD5 of the input file
    pub fn input_file_md5(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<Option<&[u8; 16]>> {
        self.root_node_value(idx, RIDX_MD5 as i32, ARRAY_SUP_TAG)
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| anyhow!("Invalid MD5 value len"))
            })
            .transpose()
    }

    // TODO identify the data
    /// Text representation options
    #[allow(dead_code)]
    pub(crate) fn text_representation_options(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_DUALOP_TEXT as i32, ARRAY_SUP_TAG)
    }

    // TODO identify the data
    /// Graph text representation options
    #[allow(dead_code)]
    pub(crate) fn graph_representation_options(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_DUALOP_GRAPH as i32, ARRAY_SUP_TAG)
    }

    // TODO identify the data
    /// Instant IDC statements, blob
    #[allow(dead_code)]
    pub(crate) fn instant_idc_statements(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_SMALL_IDC as i32, ARRAY_SUP_TAG)
    }

    // TODO identify the data
    /// assembler include file name
    #[allow(dead_code)]
    pub(crate) fn assembler_include_filename(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_INCLUDE as i32, ARRAY_SUP_TAG)
    }

    // TODO identify the data
    /// notepad
    #[allow(dead_code)]
    pub(crate) fn notepad_data(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<impl Iterator<Item = (u8, &[u8])>> {
        self.root_info_range(idx, ARRAY_SUP_TAG, RIDX_NOTEPAD, 1000)
    }

    // TODO identify the data
    /// Instant IDC statements (obsolete)
    #[allow(dead_code)]
    pub(crate) fn instant_idc_statements_old(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_SMALL_IDC_OLD as i32, ARRAY_SUP_TAG)
    }

    /// C predefined macros
    pub fn c_predefined_macros(&self, idx: RootNodeIdx<K>) -> Option<Cow<str>> {
        self.root_node_value(idx, RIDX_C_MACROS as i32, ARRAY_SUP_TAG)
            .map(String::from_utf8_lossy)
    }

    /// C header path
    pub fn c_header_path(&self, idx: RootNodeIdx<K>) -> Option<Cow<str>> {
        self.root_node_value(idx, RIDX_H_PATH as i32, ARRAY_SUP_TAG)
            .map(String::from_utf8_lossy)
    }

    // TODO identify the data
    /// segment group information (see the SDK init_groups())
    #[allow(dead_code)]
    pub(crate) fn segment_group_info(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_GROUPS as i32, ARRAY_SUP_TAG)
    }

    // TODO identify the data
    /// 2..63 are for selector_t blob (see the SDK init_selectors())
    #[allow(dead_code)]
    pub(crate) fn selectors(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Result<impl Iterator<Item = (u8, &[u8])>> {
        self.root_info_range(idx, ARRAY_SUP_TAG, RIDX_SELECTORS, 61)
    }

    // TODO identify the data
    /// file format name for loader modules
    #[allow(dead_code)]
    pub(crate) fn file_format_name_loader(
        &self,
        idx: RootNodeIdx<K>,
    ) -> Option<&[u8]> {
        self.root_node_value(idx, RIDX_FILE_FORMAT_NAME as i32, ARRAY_SUP_TAG)
    }

    /// read the `Root Node` ida_info entry of the database
    pub fn ida_info(&self, idx: RootNodeIdx<K>) -> Result<IDBParam<K>> {
        // TODO Root Node is always the last one?
        // TODO Only one or range?
        let value = self
            .root_node_value(idx, 0x0041_B994, ARRAY_SUP_TAG)
            .ok_or_else(|| anyhow!("Unable to find Root Node entry"))?;
        IDBParam::<K>::read(value)
    }

    /// read the `$ fileregions` entries of the database
    pub fn file_regions_idx(&self) -> Result<FileRegionIdx<K>> {
        let idx = self
            .netnode_idx_by_name("$ fileregions")?
            .ok_or_else(|| anyhow!("Unable to find entry fileregions"))?;
        Ok(FileRegionIdx(idx.0))
    }

    /// read the `$ fileregions` entries of the database
    pub fn file_regions(
        &self,
        idx: FileRegionIdx<K>,
        version: u16,
    ) -> FileRegionIter<K> {
        let segments = self.sup_range(idx.into(), ARRAY_SUP_TAG);
        FileRegionIter {
            _kind: std::marker::PhantomData,
            segments,
            version,
        }
    }

    /// read the `$ funcs` idx entries of the database
    pub fn funcs_idx(&self) -> Result<Option<FuncIdx<K>>> {
        funcs_idx(self)
    }

    /// read the `$ funcs` entries of the database
    pub fn functions_and_comments(
        &self,
        idx: FuncIdx<K>,
    ) -> impl Iterator<Item = Result<FunctionsAndComments<'_, K>>> {
        functions_and_comments(self, idx)
    }

    pub fn fchunks(
        &self,
        idx: FuncIdx<K>,
    ) -> impl Iterator<Item = Result<IDBFunction<K>>> + use<'_, K> {
        fchunks(self, idx)
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
            .netnode_idx_by_name("$ entry points")?
            .ok_or_else(|| anyhow!("Unable to find functions"))?;
        let entries = self.netnode_range(entry);
        Ok(entries.map(move |(key, value)| EntryPointRaw::read(key, value)))
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
        for entry in self.sup_range(NetnodeIdx(value), ARRAY_SUP_TAG) {
            let (key, value) = entry?;
            // TODO handle other values for the key
            if key == key_find {
                return til::Type::new_from_id0(value, vec![])
                    .map(Option::Some);
            }
        }
        Ok(None)
    }

    pub(crate) fn comment_at(&self, netnode: NetnodeIdx<K>) -> Option<&[u8]> {
        let comment = self.sup_value(netnode, 0u8.into(), ARRAY_SUP_TAG)?;
        Some(parse_maybe_cstr(comment).unwrap_or(comment))
    }

    pub(crate) fn comment_repeatable_at(
        &self,
        netnode: NetnodeIdx<K>,
    ) -> Option<&[u8]> {
        let comment = self.sup_value(netnode, 1u8.into(), ARRAY_SUP_TAG)?;
        Some(parse_maybe_cstr(comment).unwrap_or(comment))
    }

    // TODO: comments have a strange hole in id0
    // regular comments are     'S' -> 0
    // repeatable  comments are 'S' -> 1
    // pre comments are         'S' -> 1000..2000
    // post comments are        'S' -> 2000..3000
    // What about 2..1000? Maybe is used by older version?

    pub(crate) fn comment_pre_at(
        &self,
        netnode: NetnodeIdx<K>,
    ) -> impl Iterator<Item = &[u8]> {
        crate::id0::entry_iter::EntryTagContinuousSubkeys::new(
            self,
            netnode,
            ARRAY_SUP_TAG,
            E_PREV.into(),
        )
        // 1000..2000
        // max number of lines, NOTE this check is not done by IDA
        .take(1000)
        .map(|entry| parse_maybe_cstr(&entry.value).unwrap_or(&entry.value[..]))
    }

    pub(crate) fn comment_post_at(
        &self,
        netnode: NetnodeIdx<K>,
    ) -> impl Iterator<Item = &[u8]> {
        crate::id0::entry_iter::EntryTagContinuousSubkeys::new(
            self,
            netnode,
            ARRAY_SUP_TAG,
            E_NEXT.into(),
        )
        // 2000..3000
        // max number of lines, NOTE this check is not done by IDA
        .take(1000)
        .map(|entry| parse_maybe_cstr(&entry.value).unwrap_or(&entry.value[..]))
    }

    pub fn struct_at(&self, idx: SubtypeId<K>) -> Result<&[u8]> {
        let key: Vec<u8> = key_from_netnode_tag::<K>(idx.0, b'N').collect();
        let start = self.binary_search(&key).map_err(|_| {
            anyhow!("Unable to locate struct type for id0 entry")
        })?;

        let entry = &self.entries[start];
        // older versions dont have this prefix
        let value =
            entry.value.strip_prefix(b"$$ ").unwrap_or(&entry.value[..]);
        Ok(value)
    }

    // TODO are those K::Usize Address or Netnodes?
    fn dirtree_from_name(
        &self,
        name: &str,
    ) -> Result<Option<DirTreeRoot<K::Usize>>> {
        let Some(netnode) = self.netnode_idx_by_name(name)? else {
            // if the entry is missing, it's probably just don't have entries
            return Ok(None);
        };
        let entries = self.sup_range(netnode, ARRAY_SUP_TAG);
        let mut sub_values = entries.map(|entry| {
            let (raw_idx, value) = entry?;
            let idx = raw_idx >> 16;
            let sub_idx: u16 =
                (raw_idx & K::Usize::from(0xFFFFu16)).try_into().unwrap();
            Ok((idx, sub_idx, value))
        });
        let dirs = dirtree::parse_dirtree::<'_, _, _, K>(&mut sub_values)?;
        ensure!(sub_values.next().is_none(), "unparsed diretree entries");
        Ok(Some(dirs))
    }

    // https://hex-rays.com/products/ida/support/idapython_docs/ida_dirtree.html

    /// read the `$ dirtree/tinfos` entries of the database
    pub fn dirtree_tinfos(&self) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/tinfos")
    }

    // TODO remove the u64 and make it a TILOrdIndex type
    /// read the `$ dirtree/structs` entries of the database
    pub fn dirtree_structs(&self) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/structs")
    }

    // TODO remove the u64 and make it a TILOrdIndex type
    /// read the `$ dirtree/enums` entries of the database
    pub fn dirtree_enums(&self) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/enums")
    }

    // TODO remove the u64 and make it a FuncAddress type
    /// read the `$ dirtree/funcs` entries of the database
    pub fn dirtree_function_address(
        &self,
    ) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/funcs")
    }

    /// read the `$ dirtree/names` entries of the database
    pub fn dirtree_names(&self) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/names")
    }

    // TODO remove the u64 and make it a ImportIDX type
    /// read the `$ dirtree/imports` entries of the database
    pub fn dirtree_imports(&self) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/imports")
    }

    // TODO remove the u64 and make it a BptsIDX type
    /// read the `$ dirtree/bpts` entries of the database
    pub fn dirtree_bpts(&self) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/bpts")
    }

    // TODO remove the u64 and make it a &str type
    /// read the `$ dirtree/bookmarks_idaplace_t` entries of the database
    pub fn dirtree_bookmarks_idaplace(
        &self,
    ) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/bookmarks_idaplace_t")
    }

    // TODO remove the u64 and make it a &str type
    /// read the `$ dirtree/bookmarks_structplace_t` entries of the database
    pub fn dirtree_bookmarks_structplace(
        &self,
    ) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/bookmarks_structplace_t")
    }

    // TODO remove the u64 and make it a &str type
    /// read the `$ dirtree/bookmarks_tiplace_t` entries of the database
    pub fn dirtree_bookmarks_tiplace(
        &self,
    ) -> Result<Option<DirTreeRoot<K::Usize>>> {
        self.dirtree_from_name("$ dirtree/bookmarks_tiplace_t")
    }
}

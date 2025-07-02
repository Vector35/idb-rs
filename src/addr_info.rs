use std::borrow::Cow;

use crate::bytes_info::BytesInfo;
use crate::id0::entry_iter::EntryTagContinuousSubkeys;
use crate::id0::flag::nalt::x::NALT_DREF_FROM;
use crate::id0::flag::netnode::nn_res::ARRAY_SUP_TAG;
use crate::id0::flag::nsup::NSUP_TYPEINFO;
use crate::id0::{
    get_sup_from_key, parse_maybe_cstr, ID0CStr, ID0Section, Netdelta,
    NetnodeIdx,
};
use crate::id1::{ByteDataType, ByteInfo, ByteType, ID1Section};
use crate::id2::ID2Section;
use crate::til::Type;
use crate::{Address, IDAKind};

use anyhow::{anyhow, Result};

pub struct AddressInfo<'a, K: IDAKind> {
    id0: &'a ID0Section<K>,
    address: Address<K>,
    netdelta: Netdelta<K>,
    byte_info: ByteInfo,
}

impl<'a, K: IDAKind> AddressInfo<'a, K> {
    pub fn new(
        id0: &'a ID0Section<K>,
        id1: &ID1Section,
        id2: Option<&ID2Section<K>>,
        netdelta: Netdelta<K>,
        address: Address<K>,
    ) -> Option<Self> {
        let byte_info =
            BytesInfo::new(Some(id1), id2).byte_by_address(address)?;
        Some(Self {
            id0,
            address,
            netdelta,
            byte_info,
        })
    }

    /// this ignores the byte mapping from id1/id2, some entries, specialy for
    /// labels, need this because they are outside the mapped address.
    pub fn new_forced(
        id0: &'a ID0Section<K>,
        netdelta: Netdelta<K>,
        address: Address<K>,
    ) -> Option<Self> {
        Some(Self {
            id0,
            netdelta,
            address,
            // TODO how to handle flags?
            byte_info: ByteInfo::from_raw(
                crate::id1::flag::flags::byte_info::FF_NAME,
            ),
        })
    }

    pub fn netnode(&self) -> NetnodeIdx<K> {
        self.netdelta.ea2node(self.address)
    }

    pub fn address(&self) -> Address<K> {
        self.address
    }

    pub fn byte_info(&self) -> ByteInfo {
        self.byte_info
    }

    // TODO what happens if a comment is created, then a multi-byte type is
    // created in such a way that the comment is in the middle of the type?
    // the function `get_cmt` search for the next non-tail entry in id1,
    // maybe that's for compatibility reasons, but maybe the `has_comment`
    // flag should be ignored in tail id1 entries
    pub fn comment(&self) -> Option<&'a [u8]> {
        self.id0.comment_at(self.netnode())
    }

    pub fn comment_repeatable(&self) -> Option<&'a [u8]> {
        if !self.byte_info.has_comment() {
            return None;
        }
        self.id0.comment_repeatable_at(self.netnode())
    }

    pub fn comment_pre(&self) -> Option<impl Iterator<Item = &[u8]>> {
        if !self.byte_info.has_comment_ext() {
            return None;
        }
        Some(self.id0.comment_pre_at(self.netnode()))
    }

    pub fn comment_post(&self) -> Option<impl Iterator<Item = &[u8]>> {
        if !self.byte_info.has_comment_ext() {
            return None;
        }
        Some(self.id0.comment_post_at(self.netnode()))
    }

    pub fn label(&self) -> Result<Option<Cow<'a, [u8]>>> {
        if !self.byte_info.has_name() {
            if !self.byte_info.has_dummy_name() {
                return Ok(None);
            }
            // TODO a dummy name is returned here depending on the context
            // eg sub_XXXXX
            // known formats: "sub" "loc" "unk" "off" "seg" "xmmword" "algn"
            // "ymmword" "zmmword" "custdata" "dbl" "packreal" "flt" "qword"
            // "asc" "stru" "tbyte" "word" "dword" "byte"
            Ok(None)
        } else {
            let Some(name_raw) = self.id0.netnode_name(self.netnode()) else {
                return Ok(None);
            };
            let value = ID0CStr::<'_, K>::parse_cstr_or_subkey(name_raw)
                .ok_or_else(|| {
                    anyhow!("Label is not a valid CStr or ID0 Ref")
                })?;
            match value {
                ID0CStr::CStr(label) => Ok(Some(Cow::Borrowed(label))),
                ID0CStr::Ref(label_ref) => {
                    let entries = self.id0.address_info_value(label_ref)?;
                    let label = entries
                        .iter()
                        .flat_map(|x| &x.value[..])
                        .copied()
                        .collect();
                    Ok(Some(Cow::Owned(label)))
                }
            }
        }
    }

    pub fn tinfo(&self) -> Result<Option<Type>> {
        let ByteType::Data(byte_data) = self.byte_info.byte_type() else {
            return Ok(None);
        };
        if byte_data.data_type() != ByteDataType::Struct {
            return Ok(None);
        }
        // take the field names and the continuation (optional!)
        let mut iter = EntryTagContinuousSubkeys::new(
            self.id0,
            self.netnode(),
            ARRAY_SUP_TAG,
            NSUP_TYPEINFO.into(),
        )
        .take(0x1000);
        let Some(first_entry) = iter.next() else {
            return Ok(None);
        };
        let mut til_raw: Vec<u8> = first_entry.value.to_vec();

        // convert the value into fields
        // usually this string ends with \x00, but maybe there is no garanty for that.
        // TODO what if there is more fields that can fit a id0 entry
        let field_names = if let Some(fields_entry) = iter.next() {
            let value = parse_maybe_cstr(&fields_entry.value)
                .ok_or_else(|| anyhow!("Incomplete Fields for TIL Type"))?;
            crate::ida_reader::split_strings_from_array(value)
                .ok_or_else(|| anyhow!("Invalid Fields for TIL Type"))?
        } else {
            // no fields
            // TODO what if the type requires a continuation but it have no
            // fields, does it just skip 0x3001? If so can't use
            // EntryTagContinuousSubkeys above
            vec![vec![]]
        };

        // condensate the data continuation into a single buffer
        til_raw.extend(iter.flat_map(|e| &e.value[..]));

        // create the raw type
        let til = Type::new_from_id0(&til_raw, field_names)?;
        Ok(Some(til))
    }

    // TODO make a index type
    // Used to defined what struct is apply at the address
    pub fn tinfo_ref(
        &self,
    ) -> impl Iterator<Item = Result<SubtypeId<K>>> + use<'_, K> {
        let range = self
            .id0
            .netnode_tag_range_idx(self.netnode(), NALT_DREF_FROM);
        self.id0.entries[range]
            .iter()
            .filter(|e| e.value[..] == [0x03])
            .map(|e| {
                get_sup_from_key::<K>(&e.key)
                    .map(SubtypeId)
                    .ok_or_else(|| anyhow!("Invalid tinfo_ref index value"))
            })
    }
}

pub fn all_address_info<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    id1: &ID1Section,
    id2: Option<&ID2Section<K>>,
    netdelta: Netdelta<K>,
) -> Vec<(AddressInfo<'a, K>, usize)> {
    BytesInfo::new(Some(id1), id2)
        .all_bytes_no_tails()
        .into_iter()
        .filter(|(_a, b, _len)| {
            // InnerRef v9.1 fa53bd30-ebf1-4641-80ef-4ddc73db66cd 0x4b3370
            b.has_name()
                || b.has_comment()
                || b.has_comment_ext()
                || !matches!(
                    b.byte_type(),
                    ByteType::Tail(_) | ByteType::Unknown
                )
        })
        .map(move |(address, byte_info, len)| {
            let addr_info = AddressInfo {
                id0,
                address,
                netdelta,
                byte_info,
            };
            (addr_info, len)
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
pub struct SubtypeId<K: IDAKind>(pub(crate) K::Usize);
